#define _GNU_SOURCE

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <ctype.h>
#include <unistd.h>
#include <magic.h>
#include <pthread.h>
#include "scanner.h"
#include "clamav.h"
#include "yara.h"
#include "sanitizers/sanitizers.h"

static magic_t g_magic = NULL;

static scanner_progress_cb g_scanner_progress_cb = NULL;

void scanner_set_progress_cb(scanner_progress_cb cb)
{
    g_scanner_progress_cb = cb;
}

static inline void scanner_progress_tick(void)
{
    if (g_scanner_progress_cb) g_scanner_progress_cb();
}

void tee_subproc_progress_tick(void)
{
    scanner_progress_tick();
}
static pthread_mutex_t g_magic_lock = PTHREAD_MUTEX_INITIALIZER;

#include "scanner_whitelist.h"

static void get_extension(const char *filename, char *ext, size_t ext_size)
{
    if (ext_size == 0) return;
    ext[0] = '\0';
    if (!filename) return;

    const char *dot = strrchr(filename, '.');
    if (!dot || dot == filename) return;
    dot++;

    size_t len = strlen(dot);
    if (len == 0) return;
    if (len >= ext_size) len = ext_size - 1;

    for (size_t i = 0; i < len; i++) {
        ext[i] = (char)tolower((unsigned char)dot[i]);
    }
    ext[len] = '\0';
}

static int ext_in_list(const char *ext, const char *const *list)
{
    for (int i = 0; list[i]; i++) {
        if (strcasecmp(ext, list[i]) == 0) return 1;
    }
    return 0;
}

static int check_whitelist(const char *mime, const char *ext, int *matches_ext)
{
    *matches_ext = 0;

    int exact_hit = 0;
    for (int i = 0; EXACT_MIMES[i].mime; i++) {
        if (strcasecmp(mime, EXACT_MIMES[i].mime) == 0) {
            exact_hit = 1;
            if (ext[0] != '\0' && ext_in_list(ext, EXACT_MIMES[i].extensions)) {
                *matches_ext = 1;
                return 1;
            }
            break;
        }
    }

    for (int i = 0; PREFIX_MIMES[i].prefix; i++) {
        size_t plen = strlen(PREFIX_MIMES[i].prefix);
        if (strncasecmp(mime, PREFIX_MIMES[i].prefix, plen) == 0) {
            if (ext[0] != '\0' && ext_in_list(ext, PREFIX_MIMES[i].extensions)) {
                *matches_ext = 1;
            }
            return 1;
        }
    }

    if (exact_hit) {
        return 1;
    }

    if (ext[0] != '\0' &&
        (strcasecmp(mime, "application/octet-stream") == 0 ||
         strcasecmp(mime, "application/unknown") == 0 ||
         strcasecmp(mime, "application/x-empty") == 0)) {
        if (ext_in_list(ext, OPAQUE_BINARY_EXTS)) {
            *matches_ext = 1;
            return 1;
        }
        if (ext_in_list(ext, INSPECTABLE_ARCHIVE_EXTS)) {
            *matches_ext = 1;
            return 1;
        }
    }

    return 0;
}

typedef enum {
    CAT_IMAGE_RASTER,
    CAT_IMAGE_SVG,
    CAT_PDF,
    CAT_VIDEO,
    CAT_AUDIO,
    CAT_TEXT,
    CAT_ARCHIVE,
    CAT_GENERIC
} content_category_t;

static content_category_t categorize(const char *mime, const char *ext)
{
    if (strcasecmp(mime, "image/svg+xml") == 0 || strcasecmp(ext, "svg") == 0) {
        return CAT_IMAGE_SVG;
    }
    if (strncasecmp(mime, "image/", 6) == 0) {
        return CAT_IMAGE_RASTER;
    }
    if (strcasecmp(mime, "application/pdf") == 0) {
        return CAT_PDF;
    }
    if (strncasecmp(mime, "video/", 6) == 0) {
        return CAT_VIDEO;
    }
    if (strncasecmp(mime, "audio/", 6) == 0) {
        return CAT_AUDIO;
    }

    for (int i = 0; INSPECTABLE_ARCHIVE_MIMES[i]; i++) {
        if (strcasecmp(mime, INSPECTABLE_ARCHIVE_MIMES[i]) == 0) {
            return CAT_ARCHIVE;
        }
    }
    if (ext[0] != '\0') {
        for (int i = 0; INSPECTABLE_ARCHIVE_EXTS[i]; i++) {
            if (strcasecmp(ext, INSPECTABLE_ARCHIVE_EXTS[i]) == 0) {
                return CAT_ARCHIVE;
            }
        }
    }

    if (strncasecmp(mime, "text/", 5) == 0) {
        return CAT_TEXT;
    }

    return CAT_GENERIC;
}

#define SVG_SNIFF_BYTES (64 * 1024)

static int mem_has_ci(const unsigned char *hay, size_t hlen,
                      const char *needle, size_t nlen)
{
    if (nlen == 0 || hlen < nlen) return 0;
    for (size_t i = 0; i + nlen <= hlen; i++) {
        size_t j = 0;
        while (j < nlen &&
               tolower((unsigned char)hay[i + j]) == (unsigned char)needle[j]) {
            j++;
        }
        if (j == nlen) return 1;
    }
    return 0;
}

static int buffer_looks_like_svg(const unsigned char *data, size_t len)
{
    if (!data) return 0;
    size_t end = len < (size_t)SVG_SNIFF_BYTES ? len : (size_t)SVG_SNIFF_BYTES;
    if (end < 4) return 0;

    static const char SVG_NS[] = "http://www.w3.org/2000/svg";
    if (mem_has_ci(data, end, SVG_NS, sizeof(SVG_NS) - 1)) return 1;

    for (size_t i = 0; i + 4 <= end; i++) {
        if (data[i] != '<') continue;
        size_t j = i + 1;
        size_t p = j;
        while (p < end && (isalnum((unsigned char)data[p]) ||
                           data[p] == '_' || data[p] == '-')) {
            p++;
        }
        if (p > j && p < end && data[p] == ':') j = p + 1;
        if (j + 3 > end) continue;
        if (tolower((unsigned char)data[j])     != 's' ||
            tolower((unsigned char)data[j + 1]) != 'v' ||
            tolower((unsigned char)data[j + 2]) != 'g') {
            continue;
        }
        size_t k = j + 3;
        if (k >= end) return 1;
        unsigned char c = data[k];
        if (c == ' ' || c == '\t' || c == '\r' || c == '\n' ||
            c == '>' || c == '/') {
            return 1;
        }
    }
    return 0;
}

static void reclassify_mime(char *mime, size_t mime_size,
                            const unsigned char *data, size_t data_len,
                            const char *ext)
{
    if (strcasecmp(mime, "application/x-empty") == 0) {
        static const char *TEXT_EXTS[] = {
            "txt", "csv", "tsv", "log", "json", "xml", "yaml", "yml",
            "md", "html", "htm", "css", "js", "php", "py", "rb", "sh",
            "c", "cpp", "h", "go", "rs", "java", "ts", "tsx", NULL
        };
        if (ext_in_list(ext, TEXT_EXTS)) {
            snprintf(mime, mime_size, "text/plain");
        }
    }

    if (strcasecmp(mime, "video/mp2t") == 0 &&
        (strcasecmp(ext, "ts") == 0 || strcasecmp(ext, "tsx") == 0)) {
        if (data_len > 0 && data[0] != 0x47) {
            snprintf(mime, mime_size, "text/plain");
        }
    }

    if (strcasecmp(mime, "video/mp4") == 0 &&
        (strcasecmp(ext, "m4a") == 0 || strcasecmp(ext, "m4r") == 0 ||
         strcasecmp(ext, "m4b") == 0)) {
        snprintf(mime, mime_size, "audio/mp4");
    }

    if (strcasecmp(mime, "video/x-ms-asf") == 0 &&
        strcasecmp(ext, "wma") == 0) {
        snprintf(mime, mime_size, "audio/x-ms-wma");
    }

    if (strcasecmp(mime, "video/x-matroska") == 0 &&
        strcasecmp(ext, "mka") == 0) {
        snprintf(mime, mime_size, "audio/x-matroska");
    }

    int mime_has_ogg = strcasestr(mime, "ogg") != NULL ||
                       strcasestr(mime, "vorbis") != NULL ||
                       strcasestr(mime, "opus") != NULL;
    if (mime_has_ogg && (strcasecmp(ext, "ogg") == 0 ||
                         strcasecmp(ext, "oga") == 0 ||
                         strcasecmp(ext, "opus") == 0)) {
        snprintf(mime, mime_size, "audio/ogg");
    } else if (strcasecmp(ext, "ogv") == 0 && mime_has_ogg) {
        snprintf(mime, mime_size, "video/ogg");
    }

    if (strcasecmp(ext, "tar") == 0 && data_len >= 262 &&
        memcmp(data + 257, "ustar", 5) == 0) {
        snprintf(mime, mime_size, "application/x-tar");
    }

    if ((strcasecmp(mime, "text/xml") == 0 ||
         strcasecmp(mime, "application/xml") == 0) &&
        buffer_looks_like_svg(data, data_len)) {
        snprintf(mime, mime_size, "image/svg+xml");
    }
}

static const char *PINNED_MAGIC_DB = "/usr/local/lib/pigcloud-tee/magic.mgc";

int scanner_init(void)
{
    g_magic = magic_open(MAGIC_MIME_TYPE | MAGIC_NO_CHECK_COMPRESS | MAGIC_ERROR);
    if (!g_magic) {
        fprintf(stderr, "ERROR: magic_open() failed\n");
        return -1;
    }

    const char *db = (access(PINNED_MAGIC_DB, R_OK) == 0) ? PINNED_MAGIC_DB : NULL;
    if (magic_load(g_magic, db) != 0) {
        fprintf(stderr, "ERROR: magic_load(%s) failed: %s\n",
                db ? db : "default", magic_error(g_magic));
        magic_close(g_magic);
        g_magic = NULL;
        return -1;
    }

    pigcloud_yara_init();

    return 0;
}

int scanner_inspect(
    const unsigned char *plaintext,
    size_t plaintext_len,
    const char *filename,
    int skip_av,
    scan_result_t *result,
    unsigned char **sanitized_out,
    size_t *sanitized_len)
{
    memset(result, 0, sizeof(*result));
    *sanitized_out = NULL;
    *sanitized_len = 0;

    if (plaintext_len == 0) {
        result->verdict = VERDICT_CLEAN;
        snprintf(result->reason, sizeof(result->reason), "empty_file");
        snprintf(result->detected_mime, sizeof(result->detected_mime), "application/x-empty");
        return 0;
    }

    char ext[32];
    get_extension(filename, ext, sizeof(ext));

    if (!g_magic) {
        result->verdict = VERDICT_ERROR;
        snprintf(result->reason, sizeof(result->reason), "libmagic_not_initialized");
        return -1;
    }

    char mime[256];
    {
        pthread_mutex_lock(&g_magic_lock);
        const char *raw_mime = magic_buffer(g_magic, plaintext, plaintext_len);
        if (!raw_mime || raw_mime[0] == '\0') {
            pthread_mutex_unlock(&g_magic_lock);
            result->verdict = VERDICT_ERROR;
            snprintf(result->reason, sizeof(result->reason), "mime_detection_failed");
            return 0;
        }
        snprintf(mime, sizeof(mime), "%s", raw_mime);
        pthread_mutex_unlock(&g_magic_lock);
    }
    for (char *p = mime; *p; p++) *p = (char)tolower((unsigned char)*p);

    reclassify_mime(mime, sizeof(mime), plaintext, plaintext_len, ext);

    snprintf(result->detected_mime, sizeof(result->detected_mime), "%s", mime);

    int matches_ext = 0;
    if (!check_whitelist(mime, ext, &matches_ext)) {
        result->verdict = VERDICT_REJECTED;
        snprintf(result->reason, sizeof(result->reason), "disallowed_mime_type");
#ifdef DEBUG
        fprintf(stderr, "DEBUG: rejected %s — disallowed MIME: %s\n", filename, mime);
#endif
        return 0;
    }

    if (ext[0] != '\0' && !matches_ext) {
        result->verdict = VERDICT_REJECTED;
        snprintf(result->reason, sizeof(result->reason), "mime_extension_mismatch");
#ifdef DEBUG
        fprintf(stderr, "DEBUG: rejected %s — MIME/ext mismatch: %s vs .%s\n",
                filename, mime, ext);
#endif
        return 0;
    }

    if (!skip_av) {
        char av_sig[128] = {0};
        clamav_verdict_t av = clamav_scan_buffer(plaintext, plaintext_len,
                                                 av_sig, sizeof(av_sig));
        if (av == CLAMAV_VERDICT_INFECTED) {
            result->verdict = VERDICT_REJECTED;
            snprintf(result->reason, sizeof(result->reason), "virus_detected");
            fprintf(stderr, "WARN: ClamAV match: %s\n",
                    av_sig[0] ? av_sig : "(unnamed)");
            return 0;
        }
        if (av == CLAMAV_VERDICT_TOO_LARGE) {
            result->av_unavailable = 1;
            result->verdict = VERDICT_REJECTED;
            snprintf(result->reason, sizeof(result->reason), "av_too_large");
            fprintf(stderr, "WARN: ClamAV cannot scan past size cap; rejecting\n");
            return 0;
        }
        if (av == CLAMAV_VERDICT_UNAVAILABLE || av == CLAMAV_VERDICT_ERROR) {
            result->av_unavailable = 1;
            result->verdict = VERDICT_REJECTED;
            snprintf(result->reason, sizeof(result->reason), "av_unavailable");
            fprintf(stderr, "WARN: ClamAV unavailable or protocol error; rejecting\n");
            return 0;
        }
    }

    {
        char rule_name[128] = {0};
        pigcloud_yara_verdict_t yv = pigcloud_yara_scan(plaintext, plaintext_len,
                                                       rule_name, sizeof(rule_name));
        if (yv == PIGCLOUD_YARA_MATCH) {
            result->verdict = VERDICT_REJECTED;
            snprintf(result->reason, sizeof(result->reason), "yara_match");
            fprintf(stderr, "WARN: YARA match: %s\n",
                    rule_name[0] ? rule_name : "(unnamed)");
            return 0;
        }
        if (yv == PIGCLOUD_YARA_TIMEOUT) {
            result->yara_unavailable = 1;
            result->verdict = VERDICT_REJECTED;
            snprintf(result->reason, sizeof(result->reason), "yara_timeout");
            fprintf(stderr, "WARN: YARA scan timed out; rejecting\n");
            return 0;
        }
        if (yv == PIGCLOUD_YARA_UNAVAILABLE) {
            result->yara_unavailable = 1;
            fprintf(stderr, "WARN: YARA engine unavailable or no rules loaded; "
                            "proceeding (ClamAV is the fail-closed backstop)\n");
        }
    }

    content_category_t cat = categorize(mime, ext);

    if (cat == CAT_ARCHIVE) {
        char archive_reason[REASON_BUF_SIZE] = {0};
        int arc_rc = inspect_archive(plaintext, plaintext_len, mime, ext,
                                     archive_reason, sizeof(archive_reason));
        if (arc_rc == SANITIZE_REJECTED) {
            result->verdict = VERDICT_REJECTED;
            snprintf(result->reason, sizeof(result->reason),
                     "archive_policy:%s", archive_reason);
            return 0;
        }
        result->verdict = VERDICT_CLEAN;
        return 0;
    }

    scanner_progress_tick();

    char san_reason[REASON_BUF_SIZE] = {0};
    int san_rc;

    switch (cat) {
    case CAT_IMAGE_RASTER:
        san_rc = sanitize_raster_image(plaintext, plaintext_len, mime, ext,
                                       sanitized_out, sanitized_len,
                                       san_reason, sizeof(san_reason));
        break;

    case CAT_IMAGE_SVG:
        san_rc = sanitize_svg(plaintext, plaintext_len,
                              sanitized_out, sanitized_len,
                              san_reason, sizeof(san_reason));
        break;

    case CAT_PDF:
        san_rc = sanitize_pdf(plaintext, plaintext_len,
                              sanitized_out, sanitized_len,
                              san_reason, sizeof(san_reason));
        break;

    case CAT_VIDEO:
        san_rc = sanitize_video(plaintext, plaintext_len, ext,
                                sanitized_out, sanitized_len,
                                san_reason, sizeof(san_reason));
        break;

    case CAT_AUDIO:
        san_rc = sanitize_audio(plaintext, plaintext_len, ext,
                                sanitized_out, sanitized_len,
                                san_reason, sizeof(san_reason));
        break;

    case CAT_TEXT:
        san_rc = sanitize_text(plaintext, plaintext_len,
                               sanitized_out, sanitized_len,
                               san_reason, sizeof(san_reason));
        break;

    default:
        san_rc = SANITIZE_CLEAN;
        break;
    }

    scanner_progress_tick();

    switch (san_rc) {
    case SANITIZE_CLEAN:
        result->verdict = VERDICT_CLEAN;
        break;

    case SANITIZE_MODIFIED:
        result->verdict = VERDICT_SANITIZED;
        if (san_reason[0]) {
            snprintf(result->reason, sizeof(result->reason), "%s", san_reason);
        }
        break;

    case SANITIZE_REJECTED:
        result->verdict = VERDICT_REJECTED;
        snprintf(result->reason, sizeof(result->reason), "%s",
                 san_reason[0] ? san_reason : "sanitizer_rejected");
        free(*sanitized_out);
        *sanitized_out = NULL;
        *sanitized_len = 0;
        break;

    case SANITIZE_ERROR:
    default:
        result->verdict = VERDICT_ERROR;
        snprintf(result->reason, sizeof(result->reason), "%s",
                 san_reason[0] ? san_reason : "sanitizer_error");
        free(*sanitized_out);
        *sanitized_out = NULL;
        *sanitized_len = 0;
        break;
    }

    return 0;
}

void scanner_destroy(void)
{
    if (g_magic) {
        magic_close(g_magic);
        g_magic = NULL;
    }
    pigcloud_yara_destroy();
}
