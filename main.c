#define _GNU_SOURCE

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <signal.h>
#include <errno.h>
#include <fcntl.h>
#include <time.h>
#include <limits.h>
#include <math.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <sys/types.h>
#include <poll.h>
#include <dirent.h>
#include <pwd.h>
#include <pthread.h>
#include <stdatomic.h>
#include <sys/prctl.h>

#ifdef HAVE_SYSTEMD
#include <systemd/sd-daemon.h>
#endif

#include <sodium.h>

#include "vendor/cjson/cJSON.h"
#include "protocol.h"
#include "admission.h"
#include "crypto.h"
#include "attestation.h"
#include "audit.h"
#include "scanner.h"
#include "clamav.h"
#include "seccomp.h"

static volatile sig_atomic_t g_running = 1;
static time_t g_start_time;

static atomic_ulong g_scans_completed = 0;
static atomic_ulong g_scans_clean = 0;
static atomic_ulong g_scans_sanitized = 0;
static atomic_ulong g_scans_rejected = 0;
static atomic_ulong g_scans_errored = 0;
static atomic_ulong g_clamav_hits = 0;
static atomic_ulong g_av_unavailable = 0;
static atomic_ulong g_yara_unavailable = 0;
static atomic_ulong g_scan_duration_total_ms = 0;
static atomic_int g_inflight = 0;
static atomic_llong g_inflight_bytes = 0;
static atomic_ulong g_scans_busy = 0;

static uid_t g_expected_peer_uid = (uid_t)-1;

#ifdef HAVE_SYSTEMD
static void watchdog_progress_hook(void)
{
    sd_notify(0, "WATCHDOG=1");
}
#endif

static int av_stream_feed_trampoline(const unsigned char *chunk, size_t len,
                                     void *userdata)
{
    clamav_stream_t *s = (clamav_stream_t *)userdata;
    (void)clamav_stream_feed(s, chunk, len);
    return 0;
}

static void signal_handler(int sig)
{
    (void)sig;
    g_running = 0;
}

static void audit_sighup_handler(int sig)
{
    (void)sig;
    audit_request_reseed();
}

static work_queue_t g_queue;
static pthread_t g_workers[WORKER_POOL_SIZE];

static int recv_exact(int fd, void *buf, size_t n)
{
    size_t total = 0;
    while (total < n) {
        ssize_t rd = recv(fd, (char *)buf + total, n - total, 0);
        if (rd <= 0) {
            return -1;
        }
        total += (size_t)rd;
    }
    return 0;
}

static int send_exact(int fd, const void *buf, size_t n)
{
    size_t total = 0;
    while (total < n) {
        ssize_t wr = send(fd, (const char *)buf + total, n - total, MSG_NOSIGNAL);
        if (wr <= 0) {
            return -1;
        }
        total += (size_t)wr;
    }
    return 0;
}

static cJSON *recv_message(int fd)
{
    unsigned char len_buf[4];
    if (recv_exact(fd, len_buf, 4) != 0) {
        return NULL;
    }

    uint32_t msg_len = ((uint32_t)len_buf[0] << 24)
                     | ((uint32_t)len_buf[1] << 16)
                     | ((uint32_t)len_buf[2] <<  8)
                     | ((uint32_t)len_buf[3]);

    if (msg_len == 0 || msg_len > PROTOCOL_MAX_MSG_SIZE) {
        return NULL;
    }

    char *json_str = malloc(msg_len + 1);
    if (!json_str) {
        return NULL;
    }

    if (recv_exact(fd, json_str, msg_len) != 0) {
        free(json_str);
        return NULL;
    }
    json_str[msg_len] = '\0';

    cJSON *json = cJSON_Parse(json_str);
    free(json_str);
    return json;
}

static int send_message(int fd, cJSON *json)
{
    char *str = cJSON_PrintUnformatted(json);
    if (!str) {
        return -1;
    }

    uint32_t len = (uint32_t)strlen(str);
    unsigned char len_buf[4];
    len_buf[0] = (unsigned char)(len >> 24);
    len_buf[1] = (unsigned char)(len >> 16);
    len_buf[2] = (unsigned char)(len >>  8);
    len_buf[3] = (unsigned char)(len);

    int rc = 0;
    if (send_exact(fd, len_buf, 4) != 0 || send_exact(fd, str, len) != 0) {
        rc = -1;
    }

    cJSON_free(str);
    return rc;
}

static int send_error(int fd, const char *reason)
{
    cJSON *resp = cJSON_CreateObject();
    cJSON_AddStringToObject(resp, "verdict", VERDICT_ERROR);
    cJSON_AddStringToObject(resp, "reason", reason);
    int rc = send_message(fd, resp);
    cJSON_Delete(resp);
    return rc;
}

static int send_error_detail(int fd, const char *reason, const char *detail)
{
    cJSON *resp = cJSON_CreateObject();
    cJSON_AddStringToObject(resp, "verdict", VERDICT_ERROR);
    cJSON_AddStringToObject(resp, "reason", reason);
    if (detail) {
        cJSON_AddStringToObject(resp, "detail", detail);
    }
    int rc = send_message(fd, resp);
    cJSON_Delete(resp);
    return rc;
}

static void sanitize_reason(const char *in, char *out, size_t out_size)
{
    size_t n = 0;
    if (in && out_size > 1) {
        for (; in[n] != '\0' && n + 1 < out_size; n++) {
            unsigned char c = (unsigned char)in[n];
            int ok = (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z')
                  || (c >= '0' && c <= '9') || c == '_' || c == '.' || c == '-';
            out[n] = ok ? (char)c : '?';
        }
    }
    if (n == 0) {
        snprintf(out, out_size, "none");
        return;
    }
    out[n] = '\0';
}

static int send_busy(int fd)
{
    cJSON *resp = tee_admission_busy_response();
    if (!resp) {
        return -1;
    }
    int rc = send_message(fd, resp);
    cJSON_Delete(resp);
    return rc;
}

static int handle_health(int fd)
{
    cJSON *resp = cJSON_CreateObject();
    cJSON_AddStringToObject(resp, "status", "ok");
    cJSON_AddNumberToObject(resp, "uptime_seconds", (double)(time(NULL) - g_start_time));
    cJSON_AddNumberToObject(resp, "scans_completed", (double)atomic_load(&g_scans_completed));
    cJSON_AddNumberToObject(resp, "inflight", (double)atomic_load(&g_inflight));
    cJSON_AddNumberToObject(resp, "audit_write_failures", (double)audit_write_failures());
    cJSON_AddStringToObject(resp, "attestation_mode",
        attestation_get_mode() == ATTEST_MODE_EPID ? "epid" : "none");
    int rc = send_message(fd, resp);
    cJSON_Delete(resp);
    return rc;
}

static int handle_metrics(int fd)
{
    cJSON *resp = cJSON_CreateObject();
    cJSON_AddNumberToObject(resp, "uptime_seconds", (double)(time(NULL) - g_start_time));
    cJSON_AddNumberToObject(resp, "scans_total", (double)atomic_load(&g_scans_completed));
    cJSON_AddNumberToObject(resp, "scans_clean", (double)atomic_load(&g_scans_clean));
    cJSON_AddNumberToObject(resp, "scans_sanitized", (double)atomic_load(&g_scans_sanitized));
    cJSON_AddNumberToObject(resp, "scans_rejected", (double)atomic_load(&g_scans_rejected));
    cJSON_AddNumberToObject(resp, "scans_errored", (double)atomic_load(&g_scans_errored));
    cJSON_AddNumberToObject(resp, "clamav_hits", (double)atomic_load(&g_clamav_hits));
    cJSON_AddNumberToObject(resp, "av_unavailable", (double)atomic_load(&g_av_unavailable));
    cJSON_AddNumberToObject(resp, "yara_unavailable", (double)atomic_load(&g_yara_unavailable));
    cJSON_AddNumberToObject(resp, "scan_duration_total_ms", (double)atomic_load(&g_scan_duration_total_ms));
    cJSON_AddNumberToObject(resp, "inflight", (double)atomic_load(&g_inflight));
    cJSON_AddNumberToObject(resp, "scans_busy", (double)atomic_load(&g_scans_busy));
    cJSON_AddNumberToObject(resp, "inflight_bytes", (double)atomic_load(&g_inflight_bytes));
    cJSON_AddNumberToObject(resp, "mem_budget_bytes", (double)TEE_SCAN_MEM_BUDGET_BYTES);
    cJSON_AddNumberToObject(resp, "audit_write_failures", (double)audit_write_failures());
    int rc = send_message(fd, resp);
    cJSON_Delete(resp);
    return rc;
}

static int handle_attestation(int fd, cJSON *msg)
{
    attestation_maybe_refresh();

    const unsigned char *noncep = NULL;
    unsigned char nonce[TEE_ATTEST_NONCE_SIZE];
    cJSON *nj = cJSON_GetObjectItemCaseSensitive(msg, "nonce");
    if (cJSON_IsString(nj)) {
        size_t nlen = 0;
        if (sodium_base642bin(nonce, sizeof(nonce),
                              nj->valuestring, strlen(nj->valuestring),
                              NULL, &nlen, NULL,
                              sodium_base64_VARIANT_ORIGINAL) != 0
            || nlen != sizeof(nonce)) {
            return send_error(fd, "invalid_nonce");
        }
        noncep = nonce;
    }

    attestation_data_t data;
    if (attestation_get_data(&data, noncep) != 0) {
        return send_error(fd, "attestation_failed");
    }

    cJSON *resp = cJSON_CreateObject();
    cJSON_AddStringToObject(resp, "attestation_mode",
        attestation_get_mode() == ATTEST_MODE_EPID ? "epid" : "none");
    cJSON_AddStringToObject(resp, "enclave_public_key", data.enclave_pk_b64);
    cJSON_AddStringToObject(resp, "enclave_public_key_kyber",
        data.enclave_pk_kyber_b64 ? data.enclave_pk_kyber_b64 : "");
    cJSON_AddStringToObject(resp, "enclave_signing_pk_ed25519", data.enclave_pk_ed25519_b64);
    cJSON_AddStringToObject(resp, "enclave_signing_pk_mldsa",
        data.enclave_pk_mldsa_b64 ? data.enclave_pk_mldsa_b64 : "");
    cJSON_AddStringToObject(resp, "sgx_quote", data.sgx_quote_b64 ? data.sgx_quote_b64 : "");
    cJSON_AddStringToObject(resp, "ias_report", data.ias_report_b64 ? data.ias_report_b64 : "");
    cJSON_AddStringToObject(resp, "ias_signature", data.ias_signature_b64 ? data.ias_signature_b64 : "");
    cJSON_AddStringToObject(resp, "ias_cert_chain", data.ias_cert_chain ? data.ias_cert_chain : "");
    cJSON_AddStringToObject(resp, "mrenclave", data.mrenclave_hex);
    cJSON_AddNumberToObject(resp, "enclave_epoch", (double)attestation_get_epoch());

    int rc = send_message(fd, resp);
    cJSON_Delete(resp);
    attestation_data_free(&data);
    return rc;
}

static const char *g_signer_socket = SIGNER_SOCKET_PATH;

static int signer_connect(void)
{
    int fd = socket(AF_UNIX, SOCK_STREAM, 0);
    if (fd < 0) {
        return -1;
    }
    fcntl(fd, F_SETFD, FD_CLOEXEC);
    struct timeval tv = { .tv_sec = 120, .tv_usec = 0 };
    setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
    setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));
    struct sockaddr_un addr;
    memset(&addr, 0, sizeof(addr));
    addr.sun_family = AF_UNIX;
    snprintf(addr.sun_path, sizeof(addr.sun_path), "%s", g_signer_socket);
    if (connect(fd, (struct sockaddr *)&addr, sizeof(addr)) != 0) {
        close(fd);
        return -1;
    }
    return fd;
}

static cJSON *signer_call(cJSON *req)
{
    int fd = signer_connect();
    if (fd < 0) {
        usleep(500 * 1000);
        fd = signer_connect();
    }
    if (fd < 0) {
        return NULL;
    }
    cJSON *resp = NULL;
    if (send_message(fd, req) == 0) {
        resp = recv_message(fd);
    }
    close(fd);
    return resp;
}

static int scanner_unseal_via_signer(const unsigned char *sealed, size_t sealed_len,
                                     unsigned char data_key_out[E2EE_KEY_SIZE],
                                     char *reason_out, size_t reason_size)
{
    if (reason_size > 0) {
        reason_out[0] = '\0';
    }
    char b64[sodium_base64_ENCODED_LEN(HYBRID_SEALED_DATA_KEY_SIZE,
                                       sodium_base64_VARIANT_ORIGINAL)];
    sodium_bin2base64(b64, sizeof(b64), sealed, sealed_len,
                      sodium_base64_VARIANT_ORIGINAL);
    cJSON *req = cJSON_CreateObject();
    cJSON_AddStringToObject(req, "op", OP_UNSEAL);
    cJSON_AddStringToObject(req, "sealed", b64);
    cJSON *resp = signer_call(req);
    cJSON_Delete(req);
    sodium_memzero(b64, sizeof(b64));
    if (!resp) {
        snprintf(reason_out, reason_size, "signer_unreachable");
        return -1;
    }
    int rc = -1;
    cJSON *dk = cJSON_GetObjectItemCaseSensitive(resp, "data_key");
    if (cJSON_IsString(dk)) {
        size_t dlen = 0;
        if (sodium_base642bin(data_key_out, E2EE_KEY_SIZE,
                              dk->valuestring, strlen(dk->valuestring),
                              NULL, &dlen, NULL,
                              sodium_base64_VARIANT_ORIGINAL) == 0 &&
            dlen == E2EE_KEY_SIZE) {
            rc = 0;
        } else {
            snprintf(reason_out, reason_size, "signer_bad_data_key");
        }
    } else {
        const cJSON *detail = cJSON_GetObjectItemCaseSensitive(resp, "detail");
        const cJSON *why = cJSON_GetObjectItemCaseSensitive(resp, "reason");
        const cJSON *pick = cJSON_IsString(detail) ? detail : why;
        char safe[64];
        sanitize_reason(cJSON_IsString(pick) ? pick->valuestring : NULL,
                        safe, sizeof(safe));
        snprintf(reason_out, reason_size, "signer_rejected:%s", safe);
    }
    cJSON_Delete(resp);
    return rc;
}

static int scanner_sign_output_via_signer(tee_output_digest_t digest,
                                          unsigned char sig_ed_out[E2EE_ED25519_SIG_SIZE],
                                          unsigned char sig_ml_out[MLDSA44_SIGNATURE_SIZE])
{
    if (!digest.produced) {
        return -1;
    }
    char hb64[sodium_base64_ENCODED_LEN(32, sodium_base64_VARIANT_ORIGINAL)];
    sodium_bin2base64(hb64, sizeof(hb64), digest.bytes, sizeof(digest.bytes),
                      sodium_base64_VARIANT_ORIGINAL);
    cJSON *req = cJSON_CreateObject();
    cJSON_AddStringToObject(req, "op", OP_SIGN);
    cJSON_AddStringToObject(req, "hash", hb64);
    cJSON *resp = signer_call(req);
    cJSON_Delete(req);
    if (!resp) {
        return -1;
    }
    int rc = -1;
    cJSON *ed = cJSON_GetObjectItemCaseSensitive(resp, "ed25519");
    cJSON *ml = cJSON_GetObjectItemCaseSensitive(resp, "mldsa");
    if (cJSON_IsString(ed) && cJSON_IsString(ml)) {
        size_t el = 0, mln = 0;
        if (sodium_base642bin(sig_ed_out, E2EE_ED25519_SIG_SIZE,
                              ed->valuestring, strlen(ed->valuestring),
                              NULL, &el, NULL, sodium_base64_VARIANT_ORIGINAL) == 0 &&
            el == E2EE_ED25519_SIG_SIZE &&
            sodium_base642bin(sig_ml_out, MLDSA44_SIGNATURE_SIZE,
                              ml->valuestring, strlen(ml->valuestring),
                              NULL, &mln, NULL, sodium_base64_VARIANT_ORIGINAL) == 0 &&
            mln == MLDSA44_SIGNATURE_SIZE) {
            rc = 0;
        }
    }
    cJSON_Delete(resp);
    return rc;
}

static int handle_attestation_proxy(int fd, cJSON *msg)
{
    cJSON *req = cJSON_CreateObject();
    cJSON_AddStringToObject(req, "op", OP_ATTESTATION);
    cJSON *nj = cJSON_GetObjectItemCaseSensitive(msg, "nonce");
    if (cJSON_IsString(nj)) {
        cJSON_AddStringToObject(req, "nonce", nj->valuestring);
    }
    cJSON *resp = signer_call(req);
    cJSON_Delete(req);
    if (!resp) {
        return send_error(fd, "attestation_unavailable");
    }
    int rc = send_message(fd, resp);
    cJSON_Delete(resp);
    return rc;
}

static int is_safe_quarantine_path(const char *path)
{
    if (!path || path[0] != '/') {
        return 0;
    }
    size_t prefix_len = strlen(QUARANTINE_PATH_PREFIX);
    if (strncmp(path, QUARANTINE_PATH_PREFIX, prefix_len) != 0) {
        return 0;
    }
    if (strstr(path, "/../") != NULL || strstr(path, "/..") == path + strlen(path) - 3) {
        return 0;
    }
    size_t plen = strlen(path);
    if (plen <= prefix_len || path[plen - 1] == '/') {
        return 0;
    }

    char resolved[PATH_MAX];
    char resolved_prefix[PATH_MAX];
    if (!realpath(path, resolved) || !realpath(QUARANTINE_PATH_PREFIX, resolved_prefix)) {
        return 0;
    }
    size_t rprefix_len = strlen(resolved_prefix);
    if (strncmp(resolved, resolved_prefix, rprefix_len) != 0 ||
        resolved[rprefix_len] != '/') {
        return 0;
    }
    return 1;
}

static int is_hex_str(const char *s, size_t len)
{
    if (!s) return 0;
    for (size_t i = 0; i < len; i++) {
        char c = s[i];
        if (!((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f'))) {
            return 0;
        }
    }
    return s[len] == '\0';
}

static int parse_scan_request(cJSON *json, scan_request_t *req)
{
    memset(req, 0, sizeof(*req));

    cJSON *file_path = cJSON_GetObjectItemCaseSensitive(json, "file_path");
    cJSON *user_id   = cJSON_GetObjectItemCaseSensitive(json, "user_id");
    cJSON *tee_key   = cJSON_GetObjectItemCaseSensitive(json, "tee_sealed_key");
    cJSON *enc_meta  = cJSON_GetObjectItemCaseSensitive(json, "encryption_meta");
    cJSON *filename  = cJSON_GetObjectItemCaseSensitive(json, "original_filename");

    if (!cJSON_IsString(file_path) || !cJSON_IsString(tee_key) || !cJSON_IsObject(enc_meta) ||
        !cJSON_IsNumber(user_id)) {
        return -1;
    }

    double uid_raw = user_id->valuedouble;
    if (uid_raw < 1 || uid_raw > (double)UINT64_MAX || uid_raw != (double)(uint64_t)uid_raw) {
        return -1;
    }
    req->user_id = (uint64_t)uid_raw;

    size_t fp_len = strlen(file_path->valuestring);
    if (fp_len == 0 || fp_len >= sizeof(req->file_path) ||
        !is_safe_quarantine_path(file_path->valuestring)) {
        return -1;
    }
    memcpy(req->file_path, file_path->valuestring, fp_len);
    req->file_path[fp_len] = '\0';

    size_t key_max = sizeof(req->tee_sealed_key);
    if (sodium_base642bin(req->tee_sealed_key, key_max,
                          tee_key->valuestring, strlen(tee_key->valuestring),
                          NULL, &req->tee_sealed_key_len, NULL,
                          sodium_base64_VARIANT_ORIGINAL) != 0 ||
        req->tee_sealed_key_len != HYBRID_SEALED_DATA_KEY_SIZE) {
        return -1;
    }

    cJSON *ver   = cJSON_GetObjectItemCaseSensitive(enc_meta, "version");
    cJSON *nonce = cJSON_GetObjectItemCaseSensitive(enc_meta, "nonce");
    cJSON *cs    = cJSON_GetObjectItemCaseSensitive(enc_meta, "chunk_size");
    cJSON *ch    = cJSON_GetObjectItemCaseSensitive(enc_meta, "chunks");
    cJSON *sha   = cJSON_GetObjectItemCaseSensitive(enc_meta, "plaintext_sha256");
    cJSON *psz   = cJSON_GetObjectItemCaseSensitive(enc_meta, "plaintext_size");
    cJSON *mac   = cJSON_GetObjectItemCaseSensitive(enc_meta, "metadata_mac");

    if (!cJSON_IsNumber(ver) || !cJSON_IsString(nonce) ||
        !cJSON_IsNumber(cs)  || !cJSON_IsNumber(ch) ||
        !cJSON_IsString(sha) || !cJSON_IsNumber(psz) ||
        !cJSON_IsString(mac)) {
        return -1;
    }

    double ver_raw = ver->valuedouble;
    double cs_raw  = cs->valuedouble;
    double ch_raw  = ch->valuedouble;
    double psz_raw = psz->valuedouble;
    if (!isfinite(ver_raw) || ver_raw < 0 || ver_raw > (double)INT_MAX ||
        !isfinite(cs_raw)  || cs_raw  < 0 || cs_raw  > (double)INT_MAX ||
        !isfinite(ch_raw)  || ch_raw  < 0 || ch_raw  > (double)INT_MAX ||
        !isfinite(psz_raw) || psz_raw < 0 || psz_raw > (double)TEE_MAX_PLAINTEXT_SIZE) {
        return -1;
    }
    req->meta_version = (int)ver_raw;
    req->meta_chunk_size = (int)cs_raw;
    req->meta_chunks = (int)ch_raw;
    req->meta_plaintext_size = (int64_t)psz_raw;

    if (req->meta_version < E2EE_METADATA_VERSION) {
        return -1;
    }
    if (req->meta_chunk_size != E2EE_CHUNK_SIZE) {
        return -1;
    }
    if (req->meta_chunks <= 0) {
        return -1;
    }
    if (req->meta_plaintext_size < 0 ||
        (uint64_t)req->meta_plaintext_size > TEE_MAX_PLAINTEXT_SIZE) {
        return -1;
    }
    int64_t expected_chunks = (req->meta_plaintext_size + E2EE_CHUNK_SIZE - 1) / E2EE_CHUNK_SIZE;
    if (req->meta_chunks < expected_chunks - 1 || req->meta_chunks > expected_chunks + 1) {
        return -1;
    }
    if (!is_hex_str(sha->valuestring, 64) || !is_hex_str(mac->valuestring, 64)) {
        return -1;
    }

    size_t nonce_len = 0;
    if (sodium_base642bin(req->meta_nonce, E2EE_NONCE_SIZE,
                          nonce->valuestring, strlen(nonce->valuestring),
                          NULL, &nonce_len, NULL,
                          sodium_base64_VARIANT_ORIGINAL) != 0 ||
        nonce_len != E2EE_NONCE_SIZE) {
        return -1;
    }

    memcpy(req->meta_plaintext_sha256, sha->valuestring, 64);
    req->meta_plaintext_sha256[64] = '\0';
    memcpy(req->meta_metadata_mac, mac->valuestring, 64);
    req->meta_metadata_mac[64] = '\0';

    if (cJSON_IsString(filename)) {
        size_t fn_len = strlen(filename->valuestring);
        if (fn_len >= sizeof(req->original_filename)) {
            return -1;
        }
        memcpy(req->original_filename, filename->valuestring, fn_len);
        req->original_filename[fn_len] = '\0';
    }

    return 0;
}

static uint64_t scan_elapsed_ms(const struct timespec *start)
{
    struct timespec now;
    clock_gettime(CLOCK_MONOTONIC, &now);
    return (uint64_t)((now.tv_sec - start->tv_sec) * 1000 +
                      (now.tv_nsec - start->tv_nsec) / 1000000);
}

static void audit_scan_failure(uint64_t user_id, const char *sha,
                               const char *reason, uint64_t duration_ms)
{
    audit_entry_t e = {
        .user_id = user_id,
        .plaintext_sha256 = sha,
        .verdict = VERDICT_ERROR,
        .reason = reason,
        .duration_ms = duration_ms,
    };
    audit_record(&e);
}

static int handle_scan(int fd, cJSON *json)
{
    struct timespec ts_start, ts_end;
    clock_gettime(CLOCK_MONOTONIC, &ts_start);

    atomic_fetch_add(&g_inflight, 1);

    scan_request_t req;
    if (parse_scan_request(json, &req) != 0) {
        audit_scan_failure(req.user_id, req.meta_plaintext_sha256,
                           "invalid_request", scan_elapsed_ms(&ts_start));
        atomic_fetch_sub(&g_inflight, 1);
        return send_error(fd, "invalid_request");
    }

    unsigned char data_key[E2EE_KEY_SIZE];
    char unseal_reason[96];
    if (scanner_unseal_via_signer(
            req.tee_sealed_key, req.tee_sealed_key_len, data_key,
            unseal_reason, sizeof(unseal_reason)) != 0) {
        fprintf(stderr, "WARN: scan unseal failed: %s (sealed_len=%zu)\n",
                unseal_reason, req.tee_sealed_key_len);
        audit_scan_failure(req.user_id, req.meta_plaintext_sha256,
                           "unseal_failed", scan_elapsed_ms(&ts_start));
        atomic_fetch_sub(&g_inflight, 1);
        return send_error(fd, "unseal_failed");
    }

    {
        char nonce_b64[48];
        sodium_bin2base64(nonce_b64, sizeof(nonce_b64),
                          req.meta_nonce, E2EE_NONCE_SIZE,
                          sodium_base64_VARIANT_ORIGINAL);

        if (tee_verify_metadata_mac(data_key,
                req.meta_version, nonce_b64, req.meta_chunk_size,
                req.meta_chunks, req.meta_plaintext_sha256,
                req.meta_plaintext_size, req.meta_metadata_mac) != 0) {
            sodium_memzero(data_key, sizeof(data_key));
            audit_scan_failure(req.user_id, req.meta_plaintext_sha256,
                               "metadata_mac_invalid", scan_elapsed_ms(&ts_start));
            atomic_fetch_sub(&g_inflight, 1);
            return send_error(fd, "metadata_mac_invalid");
        }
    }

    long long reserve_bytes =
        (long long)req.meta_plaintext_size * TEE_SCAN_MEM_RESERVE_MULT;
    if (tee_admission_reserve(&g_inflight_bytes, reserve_bytes) != 0) {
        atomic_fetch_add(&g_scans_busy, 1);
        sodium_memzero(data_key, sizeof(data_key));
        atomic_fetch_sub(&g_inflight, 1);
        return send_busy(fd);
    }

    clamav_stream_t *av_stream = clamav_stream_begin();
    unsigned char *plaintext = NULL;
    size_t plaintext_len = 0;
    int decrypt_rc = tee_decrypt_file_cb(
            req.file_path, data_key, req.meta_nonce,
            req.meta_chunks, req.meta_plaintext_sha256,
            req.meta_version,
            av_stream ? av_stream_feed_trampoline : NULL,
            av_stream,
            &plaintext, &plaintext_len);
    if (decrypt_rc != 0) {
        if (av_stream) {
            char av_sig[1] = {0};
            clamav_stream_finish(av_stream, av_sig, sizeof av_sig);
        }
        sodium_memzero(data_key, sizeof(data_key));
        tee_admission_release(&g_inflight_bytes, reserve_bytes);
        audit_scan_failure(req.user_id, req.meta_plaintext_sha256,
                           "decryption_failed", scan_elapsed_ms(&ts_start));
        atomic_fetch_sub(&g_inflight, 1);
        return send_error(fd, "decryption_failed");
    }

    char av_sig[128] = {0};
    clamav_verdict_t av_verdict = av_stream
        ? clamav_stream_finish(av_stream, av_sig, sizeof av_sig)
        : CLAMAV_VERDICT_UNAVAILABLE;
    int skip_av_in_scanner = (av_stream != NULL) &&
                             (av_verdict == CLAMAV_VERDICT_CLEAN ||
                              av_verdict == CLAMAV_VERDICT_INFECTED);

    if (av_verdict != CLAMAV_VERDICT_INFECTED &&
        tee_scan_past_deadline(NULL, scan_elapsed_ms(&ts_start))) {
        sodium_memzero(plaintext, plaintext_len);
        free(plaintext);
        sodium_memzero(data_key, sizeof(data_key));
        tee_admission_release(&g_inflight_bytes, reserve_bytes);
        audit_scan_failure(req.user_id, req.meta_plaintext_sha256,
                           "scan_deadline_exceeded", scan_elapsed_ms(&ts_start));
        atomic_fetch_sub(&g_inflight, 1);
        return send_error(fd, "scan_deadline_exceeded");
    }

    scan_result_t result;
    unsigned char *sanitized = NULL;
    size_t sanitized_len = 0;

    if (av_verdict == CLAMAV_VERDICT_INFECTED) {
        memset(&result, 0, sizeof(result));
        result.verdict = VERDICT_REJECTED;
        snprintf(result.reason, sizeof(result.reason), "virus_detected");
        fprintf(stderr, "WARN: ClamAV stream match: %s\n",
                av_sig[0] ? av_sig : "(unnamed)");
    } else if (scanner_inspect(plaintext, plaintext_len, req.original_filename,
                               skip_av_in_scanner,
                               &result, &sanitized, &sanitized_len) != 0) {
        sodium_memzero(plaintext, plaintext_len);
        free(plaintext);
        sodium_memzero(data_key, sizeof(data_key));
        tee_admission_release(&g_inflight_bytes, reserve_bytes);
        audit_scan_failure(req.user_id, req.meta_plaintext_sha256,
                           "scanner_internal_error", scan_elapsed_ms(&ts_start));
        atomic_fetch_sub(&g_inflight, 1);
        return send_error(fd, "scanner_internal_error");
    }

    if (tee_scan_past_deadline(result.verdict, scan_elapsed_ms(&ts_start))) {
        if (sanitized) {
            sodium_memzero(sanitized, sanitized_len);
            free(sanitized);
        }
        sodium_memzero(plaintext, plaintext_len);
        free(plaintext);
        sodium_memzero(data_key, sizeof(data_key));
        tee_admission_release(&g_inflight_bytes, reserve_bytes);
        audit_scan_failure(req.user_id, req.meta_plaintext_sha256,
                           "scan_deadline_exceeded", scan_elapsed_ms(&ts_start));
        atomic_fetch_sub(&g_inflight, 1);
        return send_error(fd, "scan_deadline_exceeded");
    }

    if (sanitized && sanitized_len > 0) {
        const char *basename = strrchr(req.file_path, '/');
        basename = basename ? basename + 1 : req.file_path;
        char sanitized_path[sizeof(req.file_path) + 32];
        int n = snprintf(sanitized_path, sizeof(sanitized_path),
                         "%s%s%s.sanitized",
                         QUARANTINE_PATH_PREFIX,
                         QUARANTINE_SANITIZED_SUBDIR,
                         basename);
        if (n < 0 || (size_t)n >= sizeof(sanitized_path)) {
            sodium_memzero(sanitized, sanitized_len);
            free(sanitized);
            sodium_memzero(plaintext, plaintext_len);
            free(plaintext);
            sodium_memzero(data_key, sizeof(data_key));
            tee_admission_release(&g_inflight_bytes, reserve_bytes);
            audit_scan_failure(req.user_id, req.meta_plaintext_sha256,
                               "sanitized_path_too_long", scan_elapsed_ms(&ts_start));
            atomic_fetch_sub(&g_inflight, 1);
            return send_error(fd, "sanitized_path_too_long");
        }

        unsigned char new_nonce[E2EE_NONCE_SIZE];
        int new_chunks = 0;
        char new_sha256[65];
        tee_output_digest_t ct_digest = {0};

        if (tee_encrypt_file(sanitized, sanitized_len, data_key,
                             sanitized_path, new_nonce, &new_chunks, new_sha256,
                             &ct_digest) != 0) {
            sodium_memzero(sanitized, sanitized_len);
            free(sanitized);
            sodium_memzero(plaintext, plaintext_len);
            free(plaintext);
            sodium_memzero(data_key, sizeof(data_key));
            tee_admission_release(&g_inflight_bytes, reserve_bytes);
            audit_scan_failure(req.user_id, req.meta_plaintext_sha256,
                               "reencryption_failed", scan_elapsed_ms(&ts_start));
            atomic_fetch_sub(&g_inflight, 1);
            return send_error(fd, "reencryption_failed");
        }

        char nonce_b64[48];
        sodium_bin2base64(nonce_b64, sizeof(nonce_b64),
                          new_nonce, E2EE_NONCE_SIZE,
                          sodium_base64_VARIANT_ORIGINAL);

        result.has_new_meta = 1;
        memcpy(result.new_nonce, new_nonce, E2EE_NONCE_SIZE);
        result.new_chunks = new_chunks;
        snprintf(result.new_plaintext_sha256, sizeof(result.new_plaintext_sha256), "%s", new_sha256);
        result.new_plaintext_size = (int64_t)sanitized_len;
        snprintf(result.sanitized_path, sizeof(result.sanitized_path), "%s", sanitized_path);

        tee_compute_metadata_mac(data_key,
            E2EE_METADATA_VERSION, nonce_b64, E2EE_CHUNK_SIZE,
            new_chunks, new_sha256, (int64_t)sanitized_len,
            result.new_metadata_mac);

        if (scanner_sign_output_via_signer(ct_digest,
                                           result.tee_signature_ed25519,
                                           result.tee_signature_mldsa) != 0) {
            sodium_memzero(sanitized, sanitized_len);
            free(sanitized);
            sodium_memzero(plaintext, plaintext_len);
            free(plaintext);
            sodium_memzero(data_key, sizeof(data_key));
            tee_admission_release(&g_inflight_bytes, reserve_bytes);
            audit_scan_failure(req.user_id, req.meta_plaintext_sha256,
                               "tee_sign_failed", scan_elapsed_ms(&ts_start));
            atomic_fetch_sub(&g_inflight, 1);
            return send_error(fd, "tee_sign_failed");
        }
        result.has_tee_signature = 1;

        sodium_memzero(sanitized, sanitized_len);
        free(sanitized);
    }

    sodium_memzero(plaintext, plaintext_len);
    free(plaintext);
    sodium_memzero(data_key, sizeof(data_key));

    clock_gettime(CLOCK_MONOTONIC, &ts_end);
    result.duration_ms = (uint64_t)(
        (ts_end.tv_sec - ts_start.tv_sec) * 1000 +
        (ts_end.tv_nsec - ts_start.tv_nsec) / 1000000
    );

    cJSON *resp = cJSON_CreateObject();
    cJSON_AddStringToObject(resp, "verdict", result.verdict);
    if (result.reason[0] != '\0') {
        cJSON_AddStringToObject(resp, "reason", result.reason);
    }
    if (result.detected_mime[0] != '\0') {
        cJSON_AddStringToObject(resp, "detected_mime", result.detected_mime);
    }
    cJSON_AddNumberToObject(resp, "duration_ms", (double)result.duration_ms);

    if (result.has_new_meta) {
        cJSON_AddStringToObject(resp, "sanitized_path", result.sanitized_path);

        char nonce_b64[48];
        sodium_bin2base64(nonce_b64, sizeof(nonce_b64),
                          result.new_nonce, E2EE_NONCE_SIZE,
                          sodium_base64_VARIANT_ORIGINAL);

        cJSON *meta = cJSON_CreateObject();
        cJSON_AddNumberToObject(meta, "version", E2EE_METADATA_VERSION);
        cJSON_AddStringToObject(meta, "nonce", nonce_b64);
        cJSON_AddNumberToObject(meta, "chunk_size", E2EE_CHUNK_SIZE);
        cJSON_AddNumberToObject(meta, "chunks", result.new_chunks);
        cJSON_AddStringToObject(meta, "plaintext_sha256", result.new_plaintext_sha256);
        cJSON_AddNumberToObject(meta, "plaintext_size", (double)result.new_plaintext_size);
        cJSON_AddStringToObject(meta, "metadata_mac", result.new_metadata_mac);
        cJSON_AddBoolToObject(meta, "e2ee", 1);
        cJSON_AddItemToObject(resp, "new_encryption_meta", meta);
    }

    if (result.has_tee_signature) {
        char ed_b64[128];
        sodium_bin2base64(ed_b64, sizeof(ed_b64),
                          result.tee_signature_ed25519, E2EE_ED25519_SIG_SIZE,
                          sodium_base64_VARIANT_ORIGINAL);
        cJSON_AddStringToObject(resp, "tee_signature_ed25519", ed_b64);

        char ml_b64[sodium_base64_ENCODED_LEN(MLDSA44_SIGNATURE_SIZE,
                                              sodium_base64_VARIANT_ORIGINAL)];
        sodium_bin2base64(ml_b64, sizeof(ml_b64),
                          result.tee_signature_mldsa, MLDSA44_SIGNATURE_SIZE,
                          sodium_base64_VARIANT_ORIGINAL);
        cJSON_AddStringToObject(resp, "tee_signature_mldsa", ml_b64);
    }

    if (strcmp(result.verdict, VERDICT_CLEAN) == 0) {
        atomic_fetch_add(&g_scans_clean, 1);
    } else if (strcmp(result.verdict, VERDICT_SANITIZED) == 0) {
        atomic_fetch_add(&g_scans_sanitized, 1);
    } else if (strcmp(result.verdict, VERDICT_REJECTED) == 0) {
        atomic_fetch_add(&g_scans_rejected, 1);
        if (strncmp(result.reason, "virus_detected", 14) == 0) {
            atomic_fetch_add(&g_clamav_hits, 1);
        }
    } else {
        atomic_fetch_add(&g_scans_errored, 1);
    }
    atomic_fetch_add(&g_scan_duration_total_ms, result.duration_ms);
    if (result.av_unavailable) {
        atomic_fetch_add(&g_av_unavailable, 1);
    }
    if (result.yara_unavailable) {
        atomic_fetch_add(&g_yara_unavailable, 1);
    }

    audit_entry_t audit_entry = {
        .user_id = req.user_id,
        .plaintext_sha256 = req.meta_plaintext_sha256,
        .verdict = result.verdict,
        .reason = result.reason,
        .duration_ms = result.duration_ms,
    };
    audit_record(&audit_entry);

    int rc = send_message(fd, resp);
    cJSON_Delete(resp);

    atomic_fetch_add(&g_scans_completed, 1);
    tee_admission_release(&g_inflight_bytes, reserve_bytes);
    atomic_fetch_sub(&g_inflight, 1);
    return rc;
}

static void handle_connection(int client_fd)
{
    cJSON *msg = recv_message(client_fd);
    if (!msg) {
        send_error(client_fd, "invalid_message");
        return;
    }

    cJSON *op = cJSON_GetObjectItemCaseSensitive(msg, "op");
    if (!cJSON_IsString(op)) {
        send_error(client_fd, "missing_op");
        cJSON_Delete(msg);
        return;
    }

    const char *op_str = op->valuestring;

    if (strcmp(op_str, OP_SCAN) == 0) {
        handle_scan(client_fd, msg);
    } else if (strcmp(op_str, OP_ATTESTATION) == 0) {
        handle_attestation_proxy(client_fd, msg);
    } else if (strcmp(op_str, OP_HEALTH) == 0) {
        handle_health(client_fd);
    } else if (strcmp(op_str, OP_METRICS) == 0) {
        handle_metrics(client_fd);
    } else {
        send_error(client_fd, "unknown_op");
    }

    cJSON_Delete(msg);
}

#define FASTPATH_MAX_MSG        64
#define FASTPATH_WAIT_MS        1000
#define FASTPATH_POLL_SLICE_MS  20

static int fastpath_control_op(int fd)
{
    unsigned char buf[4 + FASTPATH_MAX_MSG + 1];
    int budget_ms = FASTPATH_WAIT_MS;
    uint32_t msg_len = 0;

    for (;;) {
        ssize_t got = recv(fd, buf, 4 + FASTPATH_MAX_MSG, MSG_PEEK | MSG_DONTWAIT);
        if (got < 0 && (errno == EAGAIN || errno == EWOULDBLOCK)) {
            got = 0;
        } else if (got <= 0) {
            return 0;
        }
        if (got >= 4) {
            msg_len = ((uint32_t)buf[0] << 24)
                    | ((uint32_t)buf[1] << 16)
                    | ((uint32_t)buf[2] <<  8)
                    | ((uint32_t)buf[3]);
            if (msg_len == 0 || msg_len > FASTPATH_MAX_MSG) {
                return 0;
            }
            if ((size_t)got >= 4 + (size_t)msg_len) {
                break;
            }
        }
        if (budget_ms <= 0) {
            return 0;
        }
        if (got == 0) {
            struct pollfd p = { .fd = fd, .events = POLLIN };
            poll(&p, 1, FASTPATH_POLL_SLICE_MS);
        } else {
            struct timespec ts = { 0, FASTPATH_POLL_SLICE_MS * 1000000L };
            nanosleep(&ts, NULL);
        }
        budget_ms -= FASTPATH_POLL_SLICE_MS;
    }

    buf[4 + msg_len] = '\0';
    cJSON *msg = cJSON_Parse((const char *)buf + 4);
    if (!msg) {
        return 0;
    }
    cJSON *op = cJSON_GetObjectItemCaseSensitive(msg, "op");
    int is_health  = cJSON_IsString(op) && strcmp(op->valuestring, OP_HEALTH) == 0;
    int is_metrics = cJSON_IsString(op) && strcmp(op->valuestring, OP_METRICS) == 0;
    cJSON_Delete(msg);
    if (!is_health && !is_metrics) {
        return 0;
    }

    (void)recv(fd, buf, 4 + (size_t)msg_len, MSG_DONTWAIT);

    struct timeval tv = { .tv_sec = 2, .tv_usec = 0 };
    setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));
    if (is_health) {
        handle_health(fd);
    } else {
        handle_metrics(fd);
    }
    return 1;
}

static void *worker_loop(void *arg)
{
    (void)arg;
    while (1) {
        int fd = tee_queue_pop(&g_queue);
        if (fd < 0) {
            return NULL;
        }
        handle_connection(fd);
        close(fd);
    }
}

static int handle_signer_unseal(int fd, cJSON *json)
{
    cJSON *sealed = cJSON_GetObjectItemCaseSensitive(json, "sealed");
    if (!cJSON_IsString(sealed)) {
        return send_error(fd, "invalid_request");
    }
    unsigned char blob[HYBRID_SEALED_DATA_KEY_SIZE];
    size_t blob_len = 0;
    if (sodium_base642bin(blob, sizeof(blob),
                          sealed->valuestring, strlen(sealed->valuestring),
                          NULL, &blob_len, NULL,
                          sodium_base64_VARIANT_ORIGINAL) != 0 ||
        blob_len != HYBRID_SEALED_DATA_KEY_SIZE) {
        fprintf(stderr, "WARN: signer unseal rejected blob: b64_len=%zu decoded_len=%zu want=%d\n",
                strlen(sealed->valuestring), blob_len, HYBRID_SEALED_DATA_KEY_SIZE);
        return send_error(fd, "invalid_sealed");
    }
    unsigned char data_key[E2EE_KEY_SIZE];
    const char *unseal_reason = NULL;
    if (tee_unseal_hybrid_data_key(blob, blob_len,
                                   attestation_get_secret_key(),
                                   attestation_get_kyber_seed(),
                                   data_key, &unseal_reason) != 0) {
        if (!unseal_reason) {
            unseal_reason = "unseal_unknown";
        }
        fprintf(stderr, "WARN: signer unseal failed: %s (blob_len=%zu)\n",
                unseal_reason, blob_len);
        return send_error_detail(fd, "unseal_failed", unseal_reason);
    }
    char key_b64[sodium_base64_ENCODED_LEN(E2EE_KEY_SIZE,
                                           sodium_base64_VARIANT_ORIGINAL)];
    sodium_bin2base64(key_b64, sizeof(key_b64),
                      data_key, E2EE_KEY_SIZE,
                      sodium_base64_VARIANT_ORIGINAL);
    sodium_memzero(data_key, sizeof(data_key));

    cJSON *resp = cJSON_CreateObject();
    cJSON_AddStringToObject(resp, "data_key", key_b64);
    int rc = send_message(fd, resp);
    cJSON_Delete(resp);
    sodium_memzero(key_b64, sizeof(key_b64));
    return rc;
}

static int handle_signer_sign(int fd, cJSON *json)
{
    cJSON *hash = cJSON_GetObjectItemCaseSensitive(json, "hash");
    if (!cJSON_IsString(hash)) {
        return send_error(fd, "invalid_request");
    }
    unsigned char digest[crypto_hash_sha256_BYTES];
    size_t digest_len = 0;
    if (sodium_base642bin(digest, sizeof(digest),
                          hash->valuestring, strlen(hash->valuestring),
                          NULL, &digest_len, NULL,
                          sodium_base64_VARIANT_ORIGINAL) != 0 ||
        digest_len != sizeof(digest)) {
        return send_error(fd, "invalid_hash");
    }
    unsigned char sig_ed[E2EE_ED25519_SIG_SIZE];
    unsigned char sig_ml[MLDSA44_SIGNATURE_SIZE];
    if (tee_sign_hash(digest,
                      attestation_get_ed25519_secret_key(),
                      attestation_get_mldsa_secret_key(),
                      sig_ed, sig_ml) != 0) {
        return send_error(fd, "sign_failed");
    }
    char ed_b64[sodium_base64_ENCODED_LEN(E2EE_ED25519_SIG_SIZE,
                                          sodium_base64_VARIANT_ORIGINAL)];
    sodium_bin2base64(ed_b64, sizeof(ed_b64),
                      sig_ed, E2EE_ED25519_SIG_SIZE,
                      sodium_base64_VARIANT_ORIGINAL);
    char ml_b64[sodium_base64_ENCODED_LEN(MLDSA44_SIGNATURE_SIZE,
                                          sodium_base64_VARIANT_ORIGINAL)];
    sodium_bin2base64(ml_b64, sizeof(ml_b64),
                      sig_ml, MLDSA44_SIGNATURE_SIZE,
                      sodium_base64_VARIANT_ORIGINAL);

    cJSON *resp = cJSON_CreateObject();
    cJSON_AddStringToObject(resp, "ed25519", ed_b64);
    cJSON_AddStringToObject(resp, "mldsa", ml_b64);
    int rc = send_message(fd, resp);
    cJSON_Delete(resp);
    return rc;
}

static void handle_signer_connection(int client_fd)
{
    cJSON *msg = recv_message(client_fd);
    if (!msg) {
        send_error(client_fd, "invalid_message");
        return;
    }
    cJSON *op = cJSON_GetObjectItemCaseSensitive(msg, "op");
    if (!cJSON_IsString(op)) {
        send_error(client_fd, "missing_op");
        cJSON_Delete(msg);
        return;
    }
    const char *op_str = op->valuestring;
    if (strcmp(op_str, OP_UNSEAL) == 0) {
        handle_signer_unseal(client_fd, msg);
    } else if (strcmp(op_str, OP_SIGN) == 0) {
        handle_signer_sign(client_fd, msg);
    } else if (strcmp(op_str, OP_ATTESTATION) == 0) {
        handle_attestation(client_fd, msg);
    } else if (strcmp(op_str, OP_HEALTH) == 0) {
        handle_health(client_fd);
    } else {
        send_error(client_fd, "unknown_op");
    }
    cJSON_Delete(msg);
}

static void *signer_worker_loop(void *arg)
{
    (void)arg;
    while (1) {
        int fd = tee_queue_pop(&g_queue);
        if (fd < 0) {
            return NULL;
        }
        handle_signer_connection(fd);
        close(fd);
    }
}

static int run_signer(const char *socket_path)
{
    struct passwd *pw = getpwnam("pigcloud-tee");
    if (!pw) {
        fprintf(stderr, "FATAL: getpwnam(pigcloud-tee) failed — cannot "
                        "authenticate the scanner peer\n");
        return 1;
    }
    g_expected_peer_uid = pw->pw_uid;

    if (attestation_init() != 0) {
        fprintf(stderr, "FATAL: attestation_init() failed\n");
        return 1;
    }
    fprintf(stderr, "INFO: signer attestation mode: %s\n",
        attestation_get_mode() == ATTEST_MODE_EPID ? "epid" : "none");

    struct sigaction sa;
    memset(&sa, 0, sizeof(sa));
    sa.sa_handler = signal_handler;
    sigaction(SIGTERM, &sa, NULL);
    sigaction(SIGINT, &sa, NULL);
    signal(SIGPIPE, SIG_IGN);

    int server_fd = -1;
    int socket_activated = 0;
#ifdef HAVE_SYSTEMD
    int listen_fds = sd_listen_fds(0);
    if (listen_fds > 1) {
        fprintf(stderr, "FATAL: systemd passed %d listen fds, expected 1\n", listen_fds);
        attestation_destroy();
        return 1;
    }
    if (listen_fds == 1) {
        server_fd = SD_LISTEN_FDS_START;
        socket_activated = 1;
    }
#endif
    if (server_fd < 0) {
        server_fd = socket(AF_UNIX, SOCK_STREAM, 0);
        if (server_fd < 0) {
            perror("socket");
            attestation_destroy();
            return 1;
        }
        struct sockaddr_un addr;
        memset(&addr, 0, sizeof(addr));
        addr.sun_family = AF_UNIX;
        snprintf(addr.sun_path, sizeof(addr.sun_path), "%s", socket_path);
        unlink(socket_path);
        if (bind(server_fd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
            perror("bind");
            close(server_fd);
            attestation_destroy();
            return 1;
        }
        chmod(socket_path, 0660);
        if (listen(server_fd, 64) < 0) {
            perror("listen");
            close(server_fd);
            unlink(socket_path);
            attestation_destroy();
            return 1;
        }
    }
    fcntl(server_fd, F_SETFD, FD_CLOEXEC);

    g_start_time = time(NULL);
    fprintf(stderr, "INFO: signer listening on %s%s (workers=%d)\n", socket_path,
            socket_activated ? " (socket-activated)" : "", WORKER_POOL_SIZE);

    if (pigcloud_seccomp_install(1) != 0) {
        return 1;
    }

    tee_queue_init(&g_queue);
    pthread_t workers[WORKER_POOL_SIZE];
    for (int i = 0; i < WORKER_POOL_SIZE; i++) {
        if (pthread_create(&workers[i], NULL, signer_worker_loop, NULL) != 0) {
            fprintf(stderr, "FATAL: pthread_create signer worker %d failed\n", i);
            return 1;
        }
    }

#ifdef HAVE_SYSTEMD
    sd_notify(0, "READY=1\nSTATUS=Signer listening on socket");
#endif

    struct pollfd pfd;
    pfd.fd = server_fd;
    pfd.events = POLLIN;
    while (g_running) {
#ifdef HAVE_SYSTEMD
        sd_notify(0, "WATCHDOG=1");
#endif
        int pret = poll(&pfd, 1, 10000);
        if (pret < 0) {
            if (errno == EINTR) {
                continue;
            }
            perror("poll");
            continue;
        }
        if (pret == 0) {
            continue;
        }

        int client_fd = accept4(server_fd, NULL, NULL, SOCK_CLOEXEC);
        if (client_fd < 0) {
            if (errno == EINTR) {
                continue;
            }
            perror("accept");
            continue;
        }

        struct ucred peer_cred = {0};
        socklen_t cred_len = sizeof(peer_cred);
        int cred_ok = (getsockopt(client_fd, SOL_SOCKET, SO_PEERCRED,
                                  &peer_cred, &cred_len) == 0 &&
                       cred_len == sizeof(peer_cred));
        int peer_allowed = cred_ok && g_expected_peer_uid != (uid_t)-1 &&
                           (peer_cred.uid == g_expected_peer_uid ||
                            peer_cred.uid == 0);
        if (!peer_allowed) {
            fprintf(stderr, "WARN: signer refused connection from uid=%d pid=%d\n",
                    (int)peer_cred.uid, (int)peer_cred.pid);
            close(client_fd);
            continue;
        }

        struct timeval tv = { .tv_sec = 120, .tv_usec = 0 };
        setsockopt(client_fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
        setsockopt(client_fd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));
        tee_queue_push(&g_queue, client_fd);
    }

    tee_queue_shutdown(&g_queue);
    for (int i = 0; i < WORKER_POOL_SIZE; i++) {
        pthread_join(workers[i], NULL);
    }

#ifdef HAVE_SYSTEMD
    sd_notify(0, "STOPPING=1\nSTATUS=Shutting down");
#endif
    close(server_fd);
    if (!socket_activated) {
        unlink(socket_path);
    }
    attestation_destroy();
    return 0;
}

static void check_memory_limit_consistency(void)
{
    FILE *cg = fopen("/proc/self/cgroup", "r");
    if (!cg) {
        return;
    }
    char line[512];
    char rel[sizeof(line)];
    rel[0] = '\0';
    while (fgets(line, sizeof(line), cg)) {
        if (strncmp(line, "0::", 3) != 0) {
            continue;
        }
        char *p = line + 3;
        char *nl = strchr(p, '\n');
        if (nl) {
            *nl = '\0';
        }
        snprintf(rel, sizeof(rel), "%s", p);
        break;
    }
    fclose(cg);
    if (rel[0] != '/') {
        return;
    }

    char path[sizeof(rel) + 64];
    int n = snprintf(path, sizeof(path), "/sys/fs/cgroup%s/memory.max", rel);
    if (n < 0 || (size_t)n >= sizeof(path)) {
        return;
    }
    FILE *f = fopen(path, "r");
    if (!f) {
        return;
    }
    char buf[64];
    char *got = fgets(buf, sizeof(buf), f);
    fclose(f);
    if (!got || strncmp(buf, "max", 3) == 0) {
        return;
    }
    errno = 0;
    char *end = NULL;
    unsigned long long limit = strtoull(buf, &end, 10);
    if (errno != 0 || end == buf) {
        return;
    }
    if (limit != TEE_MEMORYMAX_BYTES) {
        fprintf(stderr, "WARN: cgroup memory.max=%llu at %s disagrees with "
                "TEE_MEMORYMAX_BYTES=%llu; admission budget may be mis-sized "
                "(SCALE-36)\n", limit, path,
                (unsigned long long)TEE_MEMORYMAX_BYTES);
    }
}

int main(int argc, char *argv[])
{
    const char *socket_path = NULL;
    const char *role = "scanner";

    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "--socket") == 0 && i + 1 < argc) {
            socket_path = argv[++i];
        } else if (strcmp(argv[i], "--role") == 0 && i + 1 < argc) {
            role = argv[++i];
        } else if (strcmp(argv[i], "--signer-socket") == 0 && i + 1 < argc) {
            g_signer_socket = argv[++i];
        } else if (strcmp(argv[i], "--help") == 0) {
            fprintf(stderr, "Usage: %s [--role scanner|signer] [--socket PATH] [--signer-socket PATH]\n", argv[0]);
            return 0;
        }
    }

    int is_signer = (strcmp(role, "signer") == 0);
    if (!socket_path) {
        socket_path = is_signer ? SIGNER_SOCKET_PATH : SCANNER_SOCKET_PATH;
    }

    if (sodium_init() < 0) {
        fprintf(stderr, "FATAL: sodium_init() failed\n");
        return 1;
    }

    prctl(PR_SET_DUMPABLE, 0, 0, 0, 0);

    if (is_signer) {
        return run_signer(socket_path);
    }

#ifdef HAVE_SYSTEMD
    tee_crypto_set_progress_cb(watchdog_progress_hook);
    scanner_set_progress_cb(watchdog_progress_hook);
#endif

    {
        struct passwd *pw = getpwnam("www-data");
        if (!pw) {
            fprintf(stderr, "FATAL: getpwnam(www-data) failed — cannot "
                            "authenticate peers\n");
            return 1;
        }
        g_expected_peer_uid = pw->pw_uid;
        fprintf(stderr, "INFO: expecting peer uid=%d (www-data)\n",
                (int)g_expected_peer_uid);
    }

    check_memory_limit_consistency();

    if (scanner_init() != 0) {
        fprintf(stderr, "FATAL: scanner_init() failed\n");
        attestation_destroy();
        return 1;
    }

    (void)audit_init();

    struct sigaction sa;
    memset(&sa, 0, sizeof(sa));
    sa.sa_handler = signal_handler;
    sigaction(SIGTERM, &sa, NULL);
    sigaction(SIGINT, &sa, NULL);
    signal(SIGPIPE, SIG_IGN);

    struct sigaction sa_hup;
    memset(&sa_hup, 0, sizeof(sa_hup));
    sa_hup.sa_handler = audit_sighup_handler;
    sa_hup.sa_flags = SA_RESTART;
    sigaction(SIGHUP, &sa_hup, NULL);

    int server_fd = -1;
    int socket_activated = 0;

#ifdef HAVE_SYSTEMD
    int listen_fds = sd_listen_fds(0);
    if (listen_fds > 1) {
        fprintf(stderr, "FATAL: systemd passed %d listen fds, expected 1\n",
                listen_fds);
        scanner_destroy();
        attestation_destroy();
        return 1;
    }
    if (listen_fds == 1) {
        server_fd = SD_LISTEN_FDS_START;
        socket_activated = 1;
        fprintf(stderr, "INFO: using socket-activated fd %d\n", server_fd);
    }
#endif

    if (server_fd < 0) {
        server_fd = socket(AF_UNIX, SOCK_STREAM, 0);
        if (server_fd < 0) {
            perror("socket");
            scanner_destroy();
            attestation_destroy();
            return 1;
        }

        struct sockaddr_un addr;
        memset(&addr, 0, sizeof(addr));
        addr.sun_family = AF_UNIX;
        snprintf(addr.sun_path, sizeof(addr.sun_path), "%s", socket_path);

        unlink(socket_path);

        if (bind(server_fd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
            perror("bind");
            close(server_fd);
            scanner_destroy();
            attestation_destroy();
            return 1;
        }

        chmod(socket_path, 0660);

        if (listen(server_fd, 64) < 0) {
            perror("listen");
            close(server_fd);
            unlink(socket_path);
            scanner_destroy();
            attestation_destroy();
            return 1;
        }
    }

    fcntl(server_fd, F_SETFD, FD_CLOEXEC);

    g_start_time = time(NULL);
    fprintf(stderr, "INFO: listening on %s%s (workers=%d)\n", socket_path,
            socket_activated ? " (socket-activated)" : "",
            WORKER_POOL_SIZE);

    if (pigcloud_seccomp_install(0) != 0) {
        return 1;
    }

    tee_queue_init(&g_queue);
    for (int i = 0; i < WORKER_POOL_SIZE; i++) {
        if (pthread_create(&g_workers[i], NULL, worker_loop, NULL) != 0) {
            fprintf(stderr, "FATAL: pthread_create worker %d failed\n", i);
            return 1;
        }
    }

#ifdef HAVE_SYSTEMD
    sd_notify(0, "READY=1\nSTATUS=Listening on socket");
#endif

    struct pollfd pfd;
    pfd.fd = server_fd;
    pfd.events = POLLIN;

    while (g_running) {
#ifdef HAVE_SYSTEMD
        sd_notify(0, "WATCHDOG=1");
#endif

        int pret = poll(&pfd, 1, 10000);
        if (pret < 0) {
            if (errno == EINTR) {
                continue;
            }
            perror("poll");
            continue;
        }
        if (pret == 0) {
            continue;
        }

        int client_fd = accept4(server_fd, NULL, NULL, SOCK_CLOEXEC);
        if (client_fd < 0) {
            if (errno == EINTR) {
                continue;
            }
            perror("accept");
            continue;
        }

        struct ucred peer_cred = {0};
        socklen_t cred_len = sizeof(peer_cred);
        int cred_ok = (getsockopt(client_fd, SOL_SOCKET, SO_PEERCRED,
                                  &peer_cred, &cred_len) == 0 &&
                       cred_len == sizeof(peer_cred));
        int peer_allowed = cred_ok && g_expected_peer_uid != (uid_t)-1 &&
                           (peer_cred.uid == g_expected_peer_uid ||
                            peer_cred.uid == 0);
        if (!peer_allowed) {
            fprintf(stderr, "WARN: refused connection from uid=%d pid=%d\n",
                    (int)peer_cred.uid, (int)peer_cred.pid);
            close(client_fd);
            continue;
        }

        if (fastpath_control_op(client_fd)) {
            close(client_fd);
            continue;
        }

        struct timeval tv = { .tv_sec = 120, .tv_usec = 0 };
        setsockopt(client_fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
        setsockopt(client_fd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));

        if (tee_queue_try_push(&g_queue, client_fd) != 0) {
            struct timeval bt = { .tv_sec = 2, .tv_usec = 0 };
            setsockopt(client_fd, SOL_SOCKET, SO_SNDTIMEO, &bt, sizeof(bt));
            send_busy(client_fd);
            atomic_fetch_add(&g_scans_busy, 1);
            close(client_fd);
        }
    }

    tee_queue_shutdown(&g_queue);
    for (int i = 0; i < WORKER_POOL_SIZE; i++) {
        pthread_join(g_workers[i], NULL);
    }

    fprintf(stderr,
            "INFO: shutting down — scans=%lu (clean=%lu sanitized=%lu rejected=%lu errored=%lu clamav=%lu) inflight=%d\n",
            atomic_load(&g_scans_completed),
            atomic_load(&g_scans_clean),
            atomic_load(&g_scans_sanitized),
            atomic_load(&g_scans_rejected),
            atomic_load(&g_scans_errored),
            atomic_load(&g_clamav_hits),
            atomic_load(&g_inflight));

#ifdef HAVE_SYSTEMD
    sd_notify(0, "STOPPING=1\nSTATUS=Shutting down");
#endif

    close(server_fd);
    if (!socket_activated) {
        unlink(socket_path);
    }
    scanner_destroy();
    attestation_destroy();
    audit_shutdown();

    return 0;
}
