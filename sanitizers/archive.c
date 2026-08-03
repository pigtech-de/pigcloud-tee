#define _POSIX_C_SOURCE 200809L

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <stdint.h>
#ifdef HAVE_ZLIB
#include <zlib.h>
#endif
#include "sanitizers.h"
#include "../scanner_whitelist.h"

#define ZIP_LOCAL_SIG     0x04034b50
#define ZIP_CENTRAL_SIG   0x02014b50
#define ZIP_END_SIG       0x06054b50
#define ZIP_END64_SIG     0x06064b50
#define ZIP_LOC64_SIG     0x07064b50

static uint16_t read_u16(const unsigned char *p)
{
    return (uint16_t)p[0] | ((uint16_t)p[1] << 8);
}

static uint32_t read_u32(const unsigned char *p)
{
    return (uint32_t)p[0] | ((uint32_t)p[1] << 8) |
           ((uint32_t)p[2] << 16) | ((uint32_t)p[3] << 24);
}

static int is_archive_extension(const char *name, size_t name_len)
{
    static const char *nested_exts[] = {
        ".zip", ".tar", ".gz", ".tgz", ".tar.gz", ".tar.bz2", ".tar.xz",
        ".bz2", ".xz", ".7z", ".rar", ".zst", ".lz4", NULL
    };
    for (int i = 0; nested_exts[i]; i++) {
        size_t elen = strlen(nested_exts[i]);
        if (name_len >= elen) {
            const char *suffix = name + name_len - elen;
            if (strcasecmp(suffix, nested_exts[i]) == 0) {
                return 1;
            }
        }
    }
    return 0;
}

static int bytes_are_archive(const unsigned char *p, size_t n)
{
    if (n < 4) return 0;
    if (p[0] == 'P' && p[1] == 'K' &&
        (p[2] == 0x03 || p[2] == 0x05) && (p[3] == 0x04 || p[3] == 0x06)) return 1;
    if (p[0] == 0x1F && p[1] == 0x8B) return 1;
    if (p[0] == 0x28 && p[1] == 0xB5 && p[2] == 0x2F && p[3] == 0xFD) return 1;
    if (p[0] == 0x04 && p[1] == 0x22 && p[2] == 0x4D && p[3] == 0x18) return 1;
    if (n >= 3 && p[0] == 'B' && p[1] == 'Z' && p[2] == 'h') return 1;
    if (n >= 6 && p[0] == 0x37 && p[1] == 0x7A && p[2] == 0xBC &&
        p[3] == 0xAF && p[4] == 0x27 && p[5] == 0x1C) return 1;
    if (n >= 6 && p[0] == 0x52 && p[1] == 0x61 && p[2] == 0x72 &&
        p[3] == 0x21 && p[4] == 0x1A && p[5] == 0x07) return 1;
    if (n >= 6 && p[0] == 0xFD && p[1] == 0x37 && p[2] == 0x7A &&
        p[3] == 0x58 && p[4] == 0x5A && p[5] == 0x00) return 1;
    if (n >= 262 && memcmp(p + 257, "ustar", 5) == 0) return 1;
    return 0;
}

static int validate_entry_path(const char *path, size_t path_len,
                               const unsigned char *entry_data, size_t entry_data_len,
                               char *reason, size_t reason_size)
{
    if (path_len == 0) return 0;

    for (size_t i = 0; i < path_len; i++) {
        if (path[i] == '\0') {
            snprintf(reason, reason_size, "archive_entry_null_byte");
            return -1;
        }
    }

    if (path[0] == '/' || strstr(path, "../") != NULL || strstr(path, "..\\") != NULL) {
        snprintf(reason, reason_size, "archive_path_traversal");
        return -1;
    }

    if (is_archive_extension(path, path_len) ||
        (entry_data && entry_data_len >= 4 &&
         bytes_are_archive(entry_data, entry_data_len))) {
        snprintf(reason, reason_size, "archive_nested_archive");
        return -1;
    }

    int depth = 0;
    for (size_t i = 0; i < path_len; i++) {
        if (path[i] == '/' || path[i] == '\\') depth++;
    }
    if (depth > ARCHIVE_MAX_DEPTH) {
        snprintf(reason, reason_size, "archive_depth_exceeded");
        return -1;
    }

    return 0;
}

static void compute_limits(size_t archive_size, int64_t *max_expanded)
{
    int64_t orig = (int64_t)archive_size;
    if (orig < 1) orig = 1;

    int64_t expanded = orig * ARCHIVE_EXPANSION_MULT;
    if (expanded < ARCHIVE_EXPANSION_MIN) expanded = ARCHIVE_EXPANSION_MIN;
    if (expanded > ARCHIVE_EXPANSION_MAX) expanded = ARCHIVE_EXPANSION_MAX;

    *max_expanded = expanded;
}

#ifdef HAVE_ZLIB
static int trial_inflate_entry(const unsigned char *src, size_t src_len,
                               uint64_t declared, unsigned char *scratch,
                               size_t scratch_size)
{
    z_stream zs;
    memset(&zs, 0, sizeof(zs));
    if (inflateInit2(&zs, -MAX_WBITS) != Z_OK) {
        return -2;
    }
    uint64_t total = 0;
    size_t fed = 0;
    unsigned iters = 0;
    int rc = 0;
    for (;;) {
        if (zs.avail_in == 0 && fed < src_len) {
            size_t chunk = src_len - fed;
            if (chunk > (1u << 20)) chunk = 1u << 20;
            zs.next_in = (Bytef *)(src + fed);
            zs.avail_in = (uInt)chunk;
            fed += chunk;
        }
        uInt in_before = zs.avail_in;
        zs.next_out = scratch;
        zs.avail_out = (uInt)scratch_size;
        int zret = inflate(&zs, Z_NO_FLUSH);
        size_t produced = scratch_size - zs.avail_out;
        total += produced;
        if (total > declared) {
            rc = -1;
            break;
        }
        if (zret == Z_STREAM_END) {
            if (total != declared) {
                rc = -1;
            }
            break;
        }
        if (zret != Z_OK && zret != Z_BUF_ERROR) {
            rc = -2;
            break;
        }
        if (produced == 0 && zs.avail_in == in_before) {
            rc = -2;
            break;
        }
        if ((++iters & 0xFF) == 0) {
            tee_subproc_progress_tick();
        }
    }
    inflateEnd(&zs);
    return rc;
}
#endif

static int inspect_zip(const unsigned char *data, size_t len, char *reason, size_t reason_size)
{
    if (len < 22) {
        snprintf(reason, reason_size, "zip_too_small");
        return SANITIZE_REJECTED;
    }

    int64_t max_expanded;
    compute_limits(len, &max_expanded);

    const unsigned char *eocd = NULL;
    size_t search_start = len > 65557 ? len - 65557 : 0;
    for (size_t i = len - 22; i >= search_start; i--) {
        if (read_u32(data + i) == ZIP_END_SIG) {
            eocd = data + i;
            break;
        }
        if (i == 0) break;
    }

    if (!eocd) {
        snprintf(reason, reason_size, "zip_no_eocd");
        return SANITIZE_REJECTED;
    }

    uint16_t total_entries = read_u16(eocd + 10);
    uint32_t cd_size = read_u32(eocd + 12);
    uint32_t cd_offset = read_u32(eocd + 16);

    if (total_entries > ARCHIVE_MAX_ENTRIES) {
        snprintf(reason, reason_size, "archive_entries_exceeded");
        return SANITIZE_REJECTED;
    }

    if ((size_t)cd_offset + cd_size > len) {
        snprintf(reason, reason_size, "zip_cd_truncated");
        return SANITIZE_REJECTED;
    }

    const unsigned char *p = data + cd_offset;
    const unsigned char *cd_end = p + cd_size;
    int64_t total_uncompressed = 0;
    int entries_seen = 0;
#ifdef HAVE_ZLIB
    unsigned char scratch[ARCHIVE_INFLATE_SCRATCH];
#endif

    while (p + 46 <= cd_end && entries_seen < total_entries) {
        if (read_u32(p) != ZIP_CENTRAL_SIG) break;

        uint16_t name_len  = read_u16(p + 28);
        uint16_t extra_len = read_u16(p + 30);
        uint16_t comment_len = read_u16(p + 32);
        uint32_t uncomp_size = read_u32(p + 24);

        if (p + 46 + name_len > cd_end) break;
        char name_buf[512];
        size_t copy_len = name_len < sizeof(name_buf) - 1 ? name_len : sizeof(name_buf) - 1;
        memcpy(name_buf, p + 46, copy_len);
        name_buf[copy_len] = '\0';

        if (validate_entry_path(name_buf, copy_len, NULL, 0, reason, reason_size) != 0) {
            return SANITIZE_REJECTED;
        }

        total_uncompressed += uncomp_size;

        if (total_uncompressed > max_expanded) {
            snprintf(reason, reason_size, "archive_expansion_exceeded");
            (void)max_expanded;
            return SANITIZE_REJECTED;
        }

#ifdef HAVE_ZLIB
        uint16_t entry_flags  = read_u16(p + 8);
        uint16_t entry_method = read_u16(p + 10);
        uint32_t comp_size    = read_u32(p + 20);
        uint32_t local_off    = read_u32(p + 42);
        if (!(entry_flags & 0x0001) &&
            comp_size != 0xFFFFFFFFu && uncomp_size != 0xFFFFFFFFu &&
            (entry_method == 0 || entry_method == 8)) {
            if ((size_t)local_off + 30 > len ||
                read_u32(data + local_off) != ZIP_LOCAL_SIG) {
                snprintf(reason, reason_size, "zip_local_header_invalid");
                return SANITIZE_REJECTED;
            }
            size_t entry_data_off = (size_t)local_off + 30
                                  + read_u16(data + local_off + 26)
                                  + read_u16(data + local_off + 28);
            if (entry_data_off + comp_size > len) {
                snprintf(reason, reason_size, "zip_entry_truncated");
                return SANITIZE_REJECTED;
            }
            if (entry_method == 0) {
                if (comp_size != uncomp_size) {
                    snprintf(reason, reason_size, "archive_size_mismatch");
                    return SANITIZE_REJECTED;
                }
            } else if (comp_size > 0 || uncomp_size > 0) {
                int irc = trial_inflate_entry(data + entry_data_off, comp_size,
                                              uncomp_size, scratch, sizeof(scratch));
                if (irc == -1) {
                    snprintf(reason, reason_size, "archive_size_mismatch");
                    return SANITIZE_REJECTED;
                }
                if (irc != 0) {
                    snprintf(reason, reason_size, "zip_entry_corrupt");
                    return SANITIZE_REJECTED;
                }
            }
        }
#endif

        p += 46 + name_len + extra_len + comment_len;
        entries_seen++;
    }

    if (entries_seen != (int)total_entries) {
        snprintf(reason, reason_size, "zip_cd_malformed");
        return SANITIZE_REJECTED;
    }

    return SANITIZE_CLEAN;
}

static int64_t parse_tar_size(const unsigned char *header)
{
    if (header[124] & 0x80) {
        uint64_t uval = 0;
        for (int i = 125; i < 136; i++) {
            uval = (uval << 8) | header[i];
        }
        return uval > (uint64_t)INT64_MAX ? INT64_MAX : (int64_t)uval;
    }

    int64_t val = 0;
    int i = 124;
    while (i < 135 && header[i] == ' ') {
        i++;
    }
    for (; i < 135 && header[i] >= '0' && header[i] <= '7'; i++) {
        val = val * 8 + (header[i] - '0');
    }
    return val;
}

static int tar_checksum_valid(const unsigned char *header)
{
    int64_t stored = 0;
    int i = 148, seen = 0;
    while (i < 156 && header[i] == ' ') {
        i++;
    }
    for (; i < 156 && header[i] >= '0' && header[i] <= '7'; i++) {
        stored = stored * 8 + (header[i] - '0');
        seen = 1;
    }
    if (!seen) {
        return 0;
    }
    int64_t usum = 0, ssum = 0;
    for (int j = 0; j < 512; j++) {
        int c = (j >= 148 && j < 156) ? ' ' : header[j];
        usum += (unsigned char)c;
        ssum += (signed char)c;
    }
    return stored == usum || stored == ssum;
}

static int inspect_tar_data(const unsigned char *data, size_t len, char *reason, size_t reason_size)
{
    int64_t max_expanded;
    compute_limits(len, &max_expanded);

    size_t offset = 0;
    int entries = 0;
    int64_t total_size = 0;

    while (offset + 512 <= len) {
        const unsigned char *header = data + offset;

        int all_zero = 1;
        for (int i = 0; i < 512 && all_zero; i++) {
            if (header[i] != 0) all_zero = 0;
        }
        if (all_zero) break;

        if (!tar_checksum_valid(header)) {
            snprintf(reason, reason_size, "archive_malformed");
            return SANITIZE_REJECTED;
        }

        if (offset == 0 && memcmp(header + 257, "ustar", 5) != 0) {
        }

        char name[256];
        if (header[345] != '\0') {
            size_t prefix_len = strnlen((const char *)header + 345, 155);
            size_t base_len = strnlen((const char *)header, 100);
            if (prefix_len + 1 + base_len < sizeof(name)) {
                memcpy(name, header + 345, prefix_len);
                name[prefix_len] = '/';
                memcpy(name + prefix_len + 1, header, base_len);
                name[prefix_len + 1 + base_len] = '\0';
            } else {
                size_t copy = sizeof(name) - 1 < 100 ? sizeof(name) - 1 : 100;
                memcpy(name, header, copy);
                name[copy] = '\0';
            }
        } else {
            size_t copy = sizeof(name) - 1 < 100 ? sizeof(name) - 1 : 100;
            memcpy(name, header, copy);
            name[copy] = '\0';
        }

        char typeflag = (char)header[156];

        int64_t file_size = parse_tar_size(header);
        if (file_size < 0) file_size = 0;

        if (typeflag != 'x' && typeflag != 'g' && typeflag != 'L' && typeflag != 'K') {
            const unsigned char *entry_data = NULL;
            size_t entry_data_len = 0;
            if (offset + 512 < len) {
                entry_data = data + offset + 512;
                size_t avail = len - offset - 512;
                entry_data_len = (uint64_t)file_size < (uint64_t)avail
                                 ? (size_t)file_size : avail;
            }
            if (validate_entry_path(name, strlen(name), entry_data, entry_data_len,
                                    reason, reason_size) != 0) {
                return SANITIZE_REJECTED;
            }
            entries++;
        }

        if (entries > ARCHIVE_MAX_ENTRIES) {
            snprintf(reason, reason_size, "archive_entries_exceeded");
            return SANITIZE_REJECTED;
        }

        total_size += file_size;
        if (total_size > max_expanded) {
            snprintf(reason, reason_size, "archive_expansion_exceeded");
            return SANITIZE_REJECTED;
        }

        size_t data_blocks = ((size_t)file_size + 511) / 512;
        offset += 512 + data_blocks * 512;
    }

    return SANITIZE_CLEAN;
}

static int is_zip(const unsigned char *data, size_t len)
{
    return len >= 4 && data[0] == 'P' && data[1] == 'K' &&
           (data[2] == 0x03 || data[2] == 0x05) &&
           (data[3] == 0x04 || data[3] == 0x06);
}

static int is_gzip(const unsigned char *data, size_t len)
{
    return len >= 2 && data[0] == 0x1F && data[1] == 0x8B;
}

static int is_tar(const unsigned char *data, size_t len)
{
    return len >= 262 && memcmp(data + 257, "ustar", 5) == 0;
}

static int is_archive_mime(const char *mime, const char *ext)
{
    if (mime) {
        for (int i = 0; INSPECTABLE_ARCHIVE_MIMES[i]; i++) {
            if (strcasecmp(mime, INSPECTABLE_ARCHIVE_MIMES[i]) == 0) return 1;
        }
    }
    if (ext && ext[0] != '\0') {
        for (int i = 0; INSPECTABLE_ARCHIVE_EXTS[i]; i++) {
            if (strcasecmp(ext, INSPECTABLE_ARCHIVE_EXTS[i]) == 0) return 1;
        }
    }
    return 0;
}

int inspect_archive(
    const unsigned char *data, size_t len,
    const char *mime, const char *ext,
    char *reason, size_t reason_size)
{
    reason[0] = '\0';

    if (!is_archive_mime(mime, ext)) {
        return SANITIZE_CLEAN;
    }

    if (is_zip(data, len)) {
        return inspect_zip(data, len, reason, reason_size);
    }

    if (is_tar(data, len)) {
        return inspect_tar_data(data, len, reason, reason_size);
    }

    if (is_gzip(data, len)) {
        return SANITIZE_CLEAN;
    }

    return SANITIZE_CLEAN;
}
