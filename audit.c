#define _GNU_SOURCE

#include "audit.h"

#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/file.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <time.h>
#include <unistd.h>

#include <pthread.h>
#include <signal.h>
#include <stdatomic.h>
#include <sys/uio.h>

#include <sodium.h>

#include "vendor/cjson/cJSON.h"

#define AUDIT_LOG_DIR      "/var/log/pigcloud-tee"
#define AUDIT_KEY_MIN       16
#define AUDIT_KEY_MAX      256

static unsigned char g_audit_key[AUDIT_KEY_MAX];
static size_t        g_audit_key_len = 0;
static int           g_audit_enabled = 0;

static atomic_ullong g_audit_write_failures = 0;

uint64_t audit_write_failures(void)
{
    return atomic_load(&g_audit_write_failures);
}

#define AUDIT_GENESIS_PREV \
    "0000000000000000000000000000000000000000000000000000000000000000"

#define AUDIT_TAIL_SCAN 65536

static pthread_mutex_t g_audit_mutex = PTHREAD_MUTEX_INITIALIZER;
static char            g_audit_date[11] = "";
static uint64_t        g_audit_seq = 0;
static char            g_audit_prev[SHA256_HEX_BUF] = AUDIT_GENESIS_PREV;
static ino_t           g_audit_inode = 0;

static volatile sig_atomic_t g_audit_reseed = 0;

void audit_request_reseed(void)
{
    g_audit_reseed = 1;
}

int audit_init(void)
{
    const char *key_env = getenv("TEE_AUDIT_HMAC_KEY");
    if (!key_env) {
        fprintf(stderr,
            "WARN: TEE_AUDIT_HMAC_KEY unset — audit log disabled\n");
        return -1;
    }
    size_t len = strlen(key_env);
    if (len < AUDIT_KEY_MIN || len > AUDIT_KEY_MAX) {
        fprintf(stderr,
            "WARN: TEE_AUDIT_HMAC_KEY length %zu outside [%d,%d] — audit log disabled\n",
            len, AUDIT_KEY_MIN, AUDIT_KEY_MAX);
        return -1;
    }
    memcpy(g_audit_key, key_env, len);
    g_audit_key_len = len;
    g_audit_enabled = 1;
    return 0;
}

void audit_shutdown(void)
{
    sodium_memzero(g_audit_key, sizeof(g_audit_key));
    g_audit_key_len = 0;
    g_audit_enabled = 0;
}

static int build_canonical_and_sign(const audit_entry_t *entry,
                                    const char *ts_rfc3339,
                                    const char *log_date,
                                    const char *prev_hex,
                                    uint64_t seq,
                                    char sig_hex[SHA256_HEX_BUF],
                                    char **canonical_out)
{
    cJSON *canonical = cJSON_CreateObject();
    if (!canonical) return -1;

    cJSON_AddNumberToObject(canonical, "duration_ms", (double)entry->duration_ms);
    cJSON_AddStringToObject(canonical, "log_date", log_date);
    cJSON_AddStringToObject(canonical, "plaintext_sha256", entry->plaintext_sha256 ? entry->plaintext_sha256 : "");
    cJSON_AddStringToObject(canonical, "prev", prev_hex);
    cJSON_AddStringToObject(canonical, "reason", entry->reason ? entry->reason : "");
    cJSON_AddNumberToObject(canonical, "seq", (double)seq);
    cJSON_AddStringToObject(canonical, "ts", ts_rfc3339);
    cJSON_AddNumberToObject(canonical, "user_id", (double)entry->user_id);
    cJSON_AddStringToObject(canonical, "verdict", entry->verdict ? entry->verdict : "");

    char *canonical_json = cJSON_PrintUnformatted(canonical);
    cJSON_Delete(canonical);
    if (!canonical_json) return -1;

    unsigned char mac[32];
    crypto_auth_hmacsha256_state st;
    crypto_auth_hmacsha256_init(&st, g_audit_key, g_audit_key_len);
    crypto_auth_hmacsha256_update(&st, (const unsigned char *)canonical_json,
                                  strlen(canonical_json));
    crypto_auth_hmacsha256_final(&st, mac);
    sodium_memzero(&st, sizeof(st));
    sodium_bin2hex(sig_hex, 65, mac, sizeof(mac));
    sodium_memzero(mac, sizeof(mac));

    *canonical_out = canonical_json;
    return 0;
}

static int format_rfc3339_utc_at(time_t now, char *out, size_t outlen)
{
    struct tm tm_utc;
    if (!gmtime_r(&now, &tm_utc)) return -1;
    return (int)strftime(out, outlen, "%Y-%m-%dT%H:%M:%S+00:00", &tm_utc);
}

static int format_log_date_at(time_t now, char *out, size_t outlen)
{
    struct tm tm_utc;
    if (!gmtime_r(&now, &tm_utc)) return -1;
    return (int)strftime(out, outlen, "%Y-%m-%d", &tm_utc);
}

static int audit_log_path_for_date(const char *log_date, char *out, size_t outlen)
{
    return snprintf(out, outlen, "%s/audit-%s.log", AUDIT_LOG_DIR, log_date);
}

static void audit_set_genesis(void)
{
    g_audit_seq = 0;
    memcpy(g_audit_prev, AUDIT_GENESIS_PREV, sizeof(g_audit_prev));
}

static void audit_reseed_from_tail(int fd)
{
    audit_set_genesis();

    struct stat stbuf;
    if (fstat(fd, &stbuf) != 0) return;
    off_t size = stbuf.st_size;
    if (size <= 0) return;

    off_t start = (size > (off_t)AUDIT_TAIL_SCAN) ? size - (off_t)AUDIT_TAIL_SCAN : 0;
    size_t buflen = (size_t)(size - start);
    char *buf = malloc(buflen + 1);
    if (!buf) return;
    ssize_t got = pread(fd, buf, buflen, start);
    if (got <= 0) { free(buf); return; }
    buf[got] = '\0';

    ssize_t last_nl = -1;
    for (ssize_t i = got - 1; i >= 0; i--) {
        if (buf[i] == '\n') { last_nl = i; break; }
    }

    if (last_nl < 0) {
        if (start == 0) {
            if (ftruncate(fd, 0) != 0) {   }
        } else {
            fprintf(stderr, "WARN: audit no record boundary in last %d bytes; genesis reset\n",
                    AUDIT_TAIL_SCAN);
        }
        free(buf);
        audit_set_genesis();
        return;
    }

    off_t nl_abs = start + last_nl;
    if (nl_abs + 1 < size) {
        if (ftruncate(fd, nl_abs + 1) != 0) {   }
    }

    ssize_t line_start = 0;
    for (ssize_t i = last_nl - 1; i >= 0; i--) {
        if (buf[i] == '\n') { line_start = i + 1; break; }
    }
    if ((size_t)(last_nl - line_start) == 0) { free(buf); audit_set_genesis(); return; }

    buf[last_nl] = '\0';
    cJSON *rec = cJSON_Parse(buf + line_start);
    free(buf);
    if (!rec) {
        fprintf(stderr, "WARN: audit last line unparseable; visible genesis reset\n");
        audit_set_genesis();
        return;
    }

    cJSON *seq_item = cJSON_GetObjectItemCaseSensitive(rec, "seq");
    cJSON *sig_item = cJSON_GetObjectItemCaseSensitive(rec, "sig");
    if (!cJSON_IsNumber(seq_item) || !cJSON_IsString(sig_item) ||
        !sig_item->valuestring ||
        strlen(sig_item->valuestring) != SHA256_HEX_LEN) {
        cJSON_Delete(rec);
        fprintf(stderr, "WARN: audit last line missing seq/sig; visible genesis reset\n");
        audit_set_genesis();
        return;
    }

    double seqd = seq_item->valuedouble;
    g_audit_seq = (seqd < 0.0) ? 0 : (uint64_t)seqd + 1;
    memcpy(g_audit_prev, sig_item->valuestring, SHA256_HEX_LEN);
    g_audit_prev[SHA256_HEX_LEN] = '\0';
    cJSON_Delete(rec);
}

void audit_record(const audit_entry_t *entry)
{
    if (!g_audit_enabled || !entry) return;

    time_t now = time(NULL);
    char ts[32];
    char log_date[11];
    if (format_rfc3339_utc_at(now, ts, sizeof(ts)) <= 0) {
        atomic_fetch_add(&g_audit_write_failures, 1);
        return;
    }
    if (format_log_date_at(now, log_date, sizeof(log_date)) <= 0) {
        atomic_fetch_add(&g_audit_write_failures, 1);
        return;
    }

    char log_path[256];
    if (audit_log_path_for_date(log_date, log_path, sizeof(log_path)) <= 0) {
        atomic_fetch_add(&g_audit_write_failures, 1);
        return;
    }

    if (mkdir(AUDIT_LOG_DIR, 0750) != 0 && errno != EEXIST) {
    }

    pthread_mutex_lock(&g_audit_mutex);

    if (g_audit_reseed) {
        g_audit_date[0] = '\0';
        g_audit_reseed = 0;
    }

    int fd = open(log_path, O_RDWR | O_CREAT | O_APPEND | O_CLOEXEC, 0640);
    if (fd < 0) {
        atomic_fetch_add(&g_audit_write_failures, 1);
        pthread_mutex_unlock(&g_audit_mutex);
        return;
    }
    if (flock(fd, LOCK_EX) != 0) {
        atomic_fetch_add(&g_audit_write_failures, 1);
        close(fd);
        pthread_mutex_unlock(&g_audit_mutex);
        return;
    }

    struct stat audit_st;
    if (fstat(fd, &audit_st) == 0) {
        if (g_audit_inode != 0 && audit_st.st_ino != g_audit_inode) {
            g_audit_date[0] = '\0';
        }
        g_audit_inode = audit_st.st_ino;
    }

    if (strcmp(g_audit_date, log_date) != 0) {
        audit_reseed_from_tail(fd);
        memcpy(g_audit_date, log_date, sizeof(g_audit_date));
    }

    char sig_hex[SHA256_HEX_BUF];
    char *canonical_json = NULL;
    if (build_canonical_and_sign(entry, ts, log_date, g_audit_prev,
                                 g_audit_seq, sig_hex, &canonical_json) != 0) {
        atomic_fetch_add(&g_audit_write_failures, 1);
        (void)flock(fd, LOCK_UN);
        close(fd);
        pthread_mutex_unlock(&g_audit_mutex);
        return;
    }

    cJSON *record = cJSON_Parse(canonical_json);
    if (!record) {
        atomic_fetch_add(&g_audit_write_failures, 1);
        sodium_memzero(canonical_json, strlen(canonical_json));
        free(canonical_json);
        (void)flock(fd, LOCK_UN);
        close(fd);
        pthread_mutex_unlock(&g_audit_mutex);
        return;
    }
    cJSON_AddStringToObject(record, "sig", sig_hex);
    char *line_json = cJSON_PrintUnformatted(record);
    cJSON_Delete(record);
    sodium_memzero(canonical_json, strlen(canonical_json));
    free(canonical_json);
    if (!line_json) {
        atomic_fetch_add(&g_audit_write_failures, 1);
        (void)flock(fd, LOCK_UN);
        close(fd);
        pthread_mutex_unlock(&g_audit_mutex);
        return;
    }

    size_t line_len = strlen(line_json);
    struct iovec iov[2];
    iov[0].iov_base = line_json;
    iov[0].iov_len  = line_len;
    iov[1].iov_base = (void *)"\n";
    iov[1].iov_len  = 1;
    ssize_t want  = (ssize_t)(line_len + 1);
    ssize_t wrote = writev(fd, iov, 2);
    if (wrote == want) {
        g_audit_seq += 1;
        memcpy(g_audit_prev, sig_hex, sizeof(g_audit_prev));
    } else {
        atomic_fetch_add(&g_audit_write_failures, 1);
        g_audit_date[0] = '\0';
        fprintf(stderr, "WARN: audit short write (%zd/%zd), chain not advanced\n",
                wrote, want);
    }

    sodium_memzero(line_json, line_len);
    free(line_json);
    (void)flock(fd, LOCK_UN);
    close(fd);
    pthread_mutex_unlock(&g_audit_mutex);
}
