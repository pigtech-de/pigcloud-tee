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

static const char *FFMPEG_CANDIDATES[] = {
    "/usr/local/lib/pigcloud-tee/ffmpeg",
    "/usr/bin/ffmpeg",
    "/usr/local/bin/ffmpeg",
    "ffmpeg",
    NULL
};

static const char *find_ffmpeg(void)
{
    for (int i = 0; FFMPEG_CANDIDATES[i]; i++) {
        if (access(FFMPEG_CANDIDATES[i], X_OK) == 0) {
            return FFMPEG_CANDIDATES[i];
        }
    }
    return NULL;
}

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

static int run_ffmpeg(const char *ffmpeg, char *const argv[], int timeout_secs,
                      const int *keep_fds, size_t n_keep)
{
    if (timeout_secs <= 0) return TEE_SUBPROC_TIMEOUT;
    pid_t pid = fork();
    if (pid < 0) return TEE_SUBPROC_FAIL;

    if (pid == 0) {
        int devnull = open("/dev/null", O_WRONLY | O_CLOEXEC);
        if (devnull >= 0) {
            dup2(devnull, STDOUT_FILENO);
            dup2(devnull, STDERR_FILENO);
            if (devnull > STDERR_FILENO) close(devnull);
        }
        for (size_t i = 0; i < n_keep; i++) {
            tee_keep_after_exec(keep_fds[i]);
        }
        tee_harden_child((rlim_t)timeout_secs * 4 + 30);
        execv(ffmpeg, argv);
        _exit(127);
    }

    int status = 0;
    return tee_wait_child(pid, timeout_secs, &status);
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

    const char *ffmpeg = find_ffmpeg();
    if (!ffmpeg) {
        snprintf(reason, reason_size, "ffmpeg_not_installed");
        return SANITIZE_ERROR;
    }

    const char *fmt = ffmpeg_format(ext);

    char in_path[64], out_path[64];

    int in_fd = tee_memfd_create("tee_vid_in", in_path, sizeof(in_path));
    if (in_fd < 0) {
        snprintf(reason, reason_size, "memfd_create_failed");
        return SANITIZE_ERROR;
    }

    int out_fd = tee_memfd_create("tee_vid_out", out_path, sizeof(out_path));
    if (out_fd < 0) {
        close(in_fd);
        snprintf(reason, reason_size, "memfd_create_failed");
        return SANITIZE_ERROR;
    }

    if (tee_memfd_write(in_fd, data, len) != 0) {
        close(in_fd);
        close(out_fd);
        snprintf(reason, reason_size, "memfd_write_failed");
        return SANITIZE_ERROR;
    }

    struct timespec scan_deadline;
    clock_gettime(CLOCK_MONOTONIC, &scan_deadline);
    scan_deadline.tv_sec += TEE_SCAN_CONVERTER_BUDGET_SECS;

    char *const remux_args[] = {
        (char *)ffmpeg, "-y", "-nostdin", "-loglevel", "warning",
        "-i", in_path,
        "-map_metadata", "-1", "-map_chapters", "-1",
        "-c", "copy",
        "-f", (char *)fmt,
        out_path, NULL
    };

    int remux_to = tee_secs_until(&scan_deadline);
    if (remux_to > TEE_SUBPROC_WALL_CAP_SECS) remux_to = TEE_SUBPROC_WALL_CAP_SECS;
    int rc = run_ffmpeg(ffmpeg, remux_args, remux_to, (const int[]){in_fd, out_fd}, 2);

    if (rc != 0) {
        close(out_fd);

        char renc_path[64];
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

        int reencode_to = tee_secs_until(&scan_deadline);
        if (reencode_to > TEE_SUBPROC_WALL_CAP_SECS) reencode_to = TEE_SUBPROC_WALL_CAP_SECS;

        rc = run_ffmpeg(ffmpeg, reencode_args, reencode_to, (const int[]){in_fd, renc_fd}, 2);

        if (rc != 0) {
            close(in_fd);
            close(renc_fd);
            snprintf(reason, reason_size, "ffmpeg_remux_and_reencode_failed");
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
