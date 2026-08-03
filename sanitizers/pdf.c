#define _GNU_SOURCE

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <unistd.h>
#include <sys/wait.h>
#include "sanitizers.h"
#include "memfd_helpers.h"

static const char *GS_CANDIDATES[] = {
    "/usr/bin/gs",
    "/usr/local/bin/gs",
    "gs",
    NULL
};

static const char *find_gs(void)
{
    for (int i = 0; GS_CANDIDATES[i]; i++) {
        if (access(GS_CANDIDATES[i], X_OK) == 0) {
            return GS_CANDIDATES[i];
        }
    }
    return NULL;
}

int sanitize_pdf(
    const unsigned char *data, size_t len,
    unsigned char **out, size_t *out_len,
    char *reason, size_t reason_size)
{
    *out = NULL;
    *out_len = 0;

    if (len > TEE_PDF_MAX_INPUT_BYTES) {
        snprintf(reason, reason_size, "pdf_too_large");
        return SANITIZE_REJECTED;
    }

    const char *gs = find_gs();
    if (!gs) {
        snprintf(reason, reason_size, "ghostscript_not_installed");
        return SANITIZE_ERROR;
    }

    char in_path[64], out_path[64], meta_path[64];

    int in_fd = tee_memfd_create("tee_pdf_in", in_path, sizeof(in_path));
    if (in_fd < 0) {
        snprintf(reason, reason_size, "memfd_create_failed");
        return SANITIZE_ERROR;
    }

    int out_fd = tee_memfd_create("tee_pdf_out", out_path, sizeof(out_path));
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

    static const char meta_script[] =
        "[/Title () /Author () /Subject () /Keywords () "
        "/Creator () /Producer () /CreationDate () /ModDate () "
        "/Metadata null /DOCINFO pdfmark\n";

    int meta_fd = tee_memfd_create("tee_pdf_meta", meta_path, sizeof(meta_path));
    if (meta_fd < 0) {
        close(in_fd);
        close(out_fd);
        snprintf(reason, reason_size, "memfd_create_failed");
        return SANITIZE_ERROR;
    }
    if (tee_memfd_write(meta_fd, (const unsigned char *)meta_script,
                        sizeof(meta_script) - 1) != 0) {
        close(in_fd);
        close(out_fd);
        close(meta_fd);
        snprintf(reason, reason_size, "memfd_write_failed");
        return SANITIZE_ERROR;
    }

    int timeout_secs = TEE_SUBPROC_WALL_CAP_SECS;

    pid_t pid = fork();
    if (pid < 0) {
        close(in_fd);
        close(out_fd);
        close(meta_fd);
        snprintf(reason, reason_size, "fork_failed");
        return SANITIZE_ERROR;
    }

    if (pid == 0) {
        int devnull = open("/dev/null", O_WRONLY | O_CLOEXEC);
        if (devnull >= 0) {
            dup2(devnull, STDOUT_FILENO);
            dup2(devnull, STDERR_FILENO);
            if (devnull > STDERR_FILENO) close(devnull);
        }

        tee_keep_after_exec(in_fd);
        tee_keep_after_exec(out_fd);
        tee_keep_after_exec(meta_fd);
        tee_harden_child((rlim_t)timeout_secs * 4 + 30);

        execl(gs, gs,
              "-dSAFER", "-dNOPAUSE", "-dBATCH", "-dQUIET",
              "-sDEVICE=pdfwrite",
              "-dCompatibilityLevel=1.7",
              "-dPDFSETTINGS=/default",
              "-dDetectDuplicateImages=true",
              "-dColorImageDownsample=false",
              "-dGrayImageDownsample=false",
              "-dMonoImageDownsample=false",
              "-o", out_path,
              in_path,
              meta_path,
              (char *)NULL);
        _exit(127);
    }

    int status = 0;
    int wait_rc = tee_wait_child(pid, timeout_secs, &status);

    close(in_fd);
    close(meta_fd);

    if (wait_rc != TEE_SUBPROC_OK) {
        close(out_fd);
        snprintf(reason, reason_size, "%s",
                 wait_rc == TEE_SUBPROC_TIMEOUT ? "ghostscript_timeout"
                                                : "ghostscript_failed");
        return SANITIZE_ERROR;
    }

    *out = tee_read_memfd(out_fd, out_len, TEE_SUBPROC_MAX_OUTPUT_BYTES);
    close(out_fd);

    if (!*out || *out_len == 0) {
        free(*out);
        *out = NULL;
        *out_len = 0;
        snprintf(reason, reason_size, "ghostscript_empty_output");
        return SANITIZE_ERROR;
    }

    return SANITIZE_MODIFIED;
}
