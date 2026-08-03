#define _GNU_SOURCE

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <signal.h>
#include <unistd.h>
#include <sys/wait.h>
#include "sanitizers.h"
#include "memfd_helpers.h"
#include "../scanner_whitelist.h"

static const char *ffmpeg_audio_format(const char *ext)
{
    if (!ext || ext[0] == '\0') return "mp3";
    if (strcasecmp(ext, "mp3") == 0) return "mp3";
    if (strcasecmp(ext, "flac") == 0) return "flac";
    if (strcasecmp(ext, "ogg") == 0) return "ogg";
    if (strcasecmp(ext, "oga") == 0) return "ogg";
    if (strcasecmp(ext, "opus") == 0) return "ogg";
    if (strcasecmp(ext, "m4a") == 0) return "ipod";
    if (strcasecmp(ext, "m4r") == 0) return "ipod";
    if (strcasecmp(ext, "m4b") == 0) return "ipod";
    if (strcasecmp(ext, "aac") == 0) return "ipod";
    if (strcasecmp(ext, "wav") == 0) return "wav";
    if (strcasecmp(ext, "weba") == 0) return "webm";
    if (strcasecmp(ext, "aiff") == 0 || strcasecmp(ext, "aif") == 0) return "aiff";
    if (strcasecmp(ext, "mka") == 0) return "matroska";
    if (strcasecmp(ext, "wma") == 0) return "asf";
    if (strcasecmp(ext, "caf") == 0) return "caf";
    if (strcasecmp(ext, "amr") == 0) return "amr";
    if (strcasecmp(ext, "au") == 0 || strcasecmp(ext, "snd") == 0) return "au";
    if (strcasecmp(ext, "mid") == 0 || strcasecmp(ext, "midi") == 0) return "mp3";
    return "mp3";
}

static const char *ffmpeg_audio_codec(const char *ext)
{
    if (!ext || ext[0] == '\0') return NULL;
    if (strcasecmp(ext, "mp3") == 0) return "libmp3lame";
    if (strcasecmp(ext, "flac") == 0) return "flac";
    if (strcasecmp(ext, "ogg") == 0 || strcasecmp(ext, "oga") == 0) return "libvorbis";
    if (strcasecmp(ext, "opus") == 0) return "libopus";
    if (strcasecmp(ext, "m4a") == 0 || strcasecmp(ext, "m4r") == 0 ||
        strcasecmp(ext, "m4b") == 0 || strcasecmp(ext, "aac") == 0) return "aac";
    if (strcasecmp(ext, "wav") == 0 || strcasecmp(ext, "caf") == 0) return "pcm_s16le";
    if (strcasecmp(ext, "aiff") == 0 || strcasecmp(ext, "aif") == 0 ||
        strcasecmp(ext, "au") == 0 || strcasecmp(ext, "snd") == 0) return "pcm_s16be";
    if (strcasecmp(ext, "weba") == 0 || strcasecmp(ext, "mka") == 0) return "libopus";
    if (strcasecmp(ext, "wma") == 0) return "wmav2";
    if (strcasecmp(ext, "amr") == 0) return "libopencore_amrnb";
    return NULL;
}

static int ext_is_opaque(const char *ext)
{
    if (!ext || ext[0] == '\0') return 0;
    for (int i = 0; OPAQUE_BINARY_EXTS[i]; i++) {
        if (strcasecmp(ext, OPAQUE_BINARY_EXTS[i]) == 0) return 1;
    }
    return 0;
}

int sanitize_audio(
    const unsigned char *data, size_t len,
    const char *ext,
    unsigned char **out, size_t *out_len,
    char *reason, size_t reason_size)
{
    *out = NULL;
    *out_len = 0;

    if (ext_is_opaque(ext)) {
        snprintf(reason, reason_size, "opaque_audio_passthrough");
        return SANITIZE_CLEAN;
    }

    if (len > TEE_AUDIO_MAX_INPUT_BYTES) {
        snprintf(reason, reason_size, "audio_too_large");
        return SANITIZE_REJECTED;
    }

    const char *ffmpeg = tee_find_binary(TEE_FFMPEG_CANDIDATES);
    if (!ffmpeg) {
        snprintf(reason, reason_size, "ffmpeg_not_installed");
        return SANITIZE_ERROR;
    }

    const char *fmt = ffmpeg_audio_format(ext);

    tee_memfd_pair_t io;
    const char *memfd_reason = NULL;
    if (tee_memfd_pair_open(&io, "tee_aud_in", "tee_aud_out",
                            data, len, &memfd_reason) != 0) {
        snprintf(reason, reason_size, "%s", memfd_reason);
        return SANITIZE_ERROR;
    }
    int in_fd = io.in_fd;
    int out_fd = io.out_fd;
    char *in_path = io.in_path;
    char *out_path = io.out_path;

    struct timespec scan_deadline;
    clock_gettime(CLOCK_MONOTONIC, &scan_deadline);
    scan_deadline.tv_sec += TEE_SCAN_CONVERTER_BUDGET_SECS;
    int timed_out = 0;

    char *const remux_args[] = {
        (char *)ffmpeg, "-y", "-nostdin", "-loglevel", "warning",
        "-i", in_path,
        "-map_metadata", "-1",
        "-c", "copy",
        "-f", (char *)fmt,
        out_path, NULL
    };

    int remux_to = tee_secs_until(&scan_deadline);
    if (remux_to > TEE_SUBPROC_WALL_CAP_SECS) remux_to = TEE_SUBPROC_WALL_CAP_SECS;
    int rc = tee_spawn_converter(ffmpeg, remux_args, remux_to, (const int[]){in_fd, out_fd}, 2);
    if (rc == TEE_SUBPROC_TIMEOUT) timed_out = 1;

    if (rc != 0) {
        close(out_fd);
        out_fd = -1;

        const char *codec = ffmpeg_audio_codec(ext);
        int renc_fd = -1;
        if (codec) {
            char renc_path[TEE_MEMFD_PATH_MAX];
            renc_fd = tee_memfd_create("tee_aud_renc", renc_path, sizeof(renc_path));
            if (renc_fd >= 0) {
                char *const reencode_args[] = {
                    (char *)ffmpeg, "-y", "-nostdin", "-loglevel", "warning",
                    "-i", in_path,
                    "-map_metadata", "-1",
                    "-c:a", (char *)codec,
                    "-vn",
                    "-f", (char *)fmt,
                    renc_path, NULL
                };

                int reencode_to = tee_secs_until(&scan_deadline);
                if (reencode_to > TEE_SUBPROC_WALL_CAP_SECS) reencode_to = TEE_SUBPROC_WALL_CAP_SECS;

                rc = tee_spawn_converter(ffmpeg, reencode_args, reencode_to, (const int[]){in_fd, renc_fd}, 2);
                if (rc == TEE_SUBPROC_TIMEOUT) timed_out = 1;
                if (rc != 0) {
                    close(renc_fd);
                    renc_fd = -1;
                }
            }
        }

        if (rc != 0) {
            if (codec) {
                char lenient_path[TEE_MEMFD_PATH_MAX];
                int lenient_fd = tee_memfd_create("tee_aud_lenient", lenient_path, sizeof(lenient_path));
                if (lenient_fd >= 0) {
                    char *const lenient_args[] = {
                        (char *)ffmpeg, "-y", "-nostdin", "-loglevel", "warning",
                        "-err_detect", "ignore_err",
                        "-fflags", "+genpts+discardcorrupt",
                        "-i", in_path,
                        "-map_metadata", "-1",
                        "-c:a", (char *)codec,
                        "-vn",
                        "-f", (char *)fmt,
                        lenient_path, NULL
                    };

                    int lenient_to = tee_secs_until(&scan_deadline);
                    if (lenient_to > TEE_SUBPROC_WALL_CAP_SECS) lenient_to = TEE_SUBPROC_WALL_CAP_SECS;

                    rc = tee_spawn_converter(ffmpeg, lenient_args, lenient_to, (const int[]){in_fd, lenient_fd}, 2);
                    if (rc == TEE_SUBPROC_TIMEOUT) timed_out = 1;
                    if (rc == 0) {
                        renc_fd = lenient_fd;
                    } else {
                        close(lenient_fd);
                    }
                }
            }
        }

        if (rc != 0 || renc_fd < 0) {
            if (timed_out) {
                close(in_fd);
                snprintf(reason, reason_size, "ffmpeg_timeout");
                return SANITIZE_ERROR;
            }
            close(in_fd);
            snprintf(reason, reason_size, "ffmpeg_sanitize_failed");
            return SANITIZE_ERROR;
        }

        out_fd = renc_fd;
    }

    close(in_fd);

    *out = tee_read_memfd(out_fd, out_len, TEE_SUBPROC_MAX_OUTPUT_BYTES);
    close(out_fd);

    if (!*out || *out_len == 0) {
        free(*out);
        *out = NULL;
        *out_len = 0;
        snprintf(reason, reason_size, "ffmpeg_empty_output");
        return SANITIZE_ERROR;
    }

    return SANITIZE_MODIFIED;
}
