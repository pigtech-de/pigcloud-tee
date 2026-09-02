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

static const char *ffmpeg_format(const char *ext)
{
    if (!ext || ext[0] == '\0') return "mp4";
    if (strcasecmp(ext, "mp4") == 0) return "mp4";
    if (strcasecmp(ext, "m4v") == 0) return "mp4";
    if (strcasecmp(ext, "mkv") == 0) return "matroska";
    if (strcasecmp(ext, "webm") == 0) return "webm";
    if (strcasecmp(ext, "mov") == 0) return "mov";
    if (strcasecmp(ext, "avi") == 0) return "avi";
    if (strcasecmp(ext, "flv") == 0) return "flv";
    if (strcasecmp(ext, "f4v") == 0) return "flv";
    if (strcasecmp(ext, "wmv") == 0 || strcasecmp(ext, "asf") == 0) return "asf";
    if (strcasecmp(ext, "3gp") == 0) return "3gp";
    if (strcasecmp(ext, "3g2") == 0) return "3g2";
    if (strcasecmp(ext, "ogv") == 0) return "ogg";
    if (strcasecmp(ext, "mpeg") == 0 || strcasecmp(ext, "mpg") == 0) return "mpeg";
    if (strcasecmp(ext, "vob") == 0) return "vob";
    if (strcasecmp(ext, "mts") == 0 || strcasecmp(ext, "m2ts") == 0) return "mpegts";
    return "mp4";
}

int sanitize_video(
    const unsigned char *data, size_t len,
    const char *ext,
    unsigned char **out, size_t *out_len,
    char *reason, size_t reason_size)
{
    *out = NULL;
    *out_len = 0;

    if (len > TEE_VIDEO_MAX_INPUT_BYTES) {
        snprintf(reason, reason_size, "video_too_large");
        return SANITIZE_REJECTED;
    }

    const char *ffmpeg = tee_find_binary(TEE_FFMPEG_CANDIDATES);
    if (!ffmpeg) {
        snprintf(reason, reason_size, "ffmpeg_not_installed");
        return SANITIZE_ERROR;
    }

    const char *fmt = ffmpeg_format(ext);

    tee_memfd_pair_t io;
    const char *memfd_reason = NULL;
    if (tee_memfd_pair_open(&io, "tee_vid_in", "tee_vid_out",
                            data, len, &memfd_reason) != 0) {
        snprintf(reason, reason_size, "%s", memfd_reason);
        return SANITIZE_ERROR;
    }
    int in_fd = io.in_fd;
    int out_fd = io.out_fd;
    char *in_path = io.in_path;
    char *out_path = io.out_path;

    struct timespec scan_deadline;
    tee_deadline_start(&scan_deadline, TEE_SCAN_CONVERTER_BUDGET_SECS);
    int timed_out = 0;

    char *const remux_args[] = {
        (char *)ffmpeg, "-y", "-nostdin", "-loglevel", "warning",
        "-i", in_path,
        "-map_metadata", "-1", "-map_chapters", "-1",
        "-c", "copy",
        "-f", (char *)fmt,
        out_path, NULL
    };

    int rc = tee_spawn_converter(ffmpeg, remux_args, tee_secs_within(&scan_deadline, TEE_SUBPROC_WALL_CAP_SECS),
                                 (const int[]){in_fd, out_fd}, 2);
    if (rc == TEE_SUBPROC_TIMEOUT) timed_out = 1;

    if (rc != 0) {
        close(out_fd);

        char renc_path[TEE_MEMFD_PATH_MAX];
        int renc_fd = tee_memfd_create("tee_vid_renc", renc_path, sizeof(renc_path));
        if (renc_fd < 0) {
            close(in_fd);
            snprintf(reason, reason_size, "memfd_create_failed");
            return SANITIZE_ERROR;
        }

        char *const reencode_args[] = {
            (char *)ffmpeg, "-y", "-nostdin", "-loglevel", "warning",
            "-i", in_path,
            "-map_metadata", "-1", "-map_chapters", "-1",
            "-c:v", "libx264", "-preset", "fast", "-crf", "23",
            "-c:a", "aac", "-b:a", "128k",
            "-movflags", "+faststart",
            "-f", "mp4",
            renc_path, NULL
        };

        rc = tee_spawn_converter(ffmpeg, reencode_args, tee_secs_within(&scan_deadline, TEE_SUBPROC_WALL_CAP_SECS),
                                 (const int[]){in_fd, renc_fd}, 2);
        if (rc == TEE_SUBPROC_TIMEOUT) timed_out = 1;

        if (rc != 0) {
            close(in_fd);
            close(renc_fd);
            snprintf(reason, reason_size, "%s", timed_out ? "ffmpeg_timeout" : "ffmpeg_remux_and_reencode_failed");
            return SANITIZE_ERROR;
        }

        out_fd = renc_fd;
    }

    close(in_fd);
    if (tee_memfd_finish_output(out_fd, out, out_len, TEE_SUBPROC_MAX_OUTPUT_BYTES,
                                "ffmpeg_empty_output", reason, reason_size) != 0) {
        return SANITIZE_ERROR;
    }
    return SANITIZE_MODIFIED;
}
