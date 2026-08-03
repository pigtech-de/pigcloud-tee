#define _GNU_SOURCE

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <unistd.h>
#include <sys/wait.h>
#include "sanitizers.h"
#include "memfd_helpers.h"

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

    const char *gs = tee_find_binary(TEE_GS_CANDIDATES);
    if (!gs) {
        snprintf(reason, reason_size, "ghostscript_not_installed");
        return SANITIZE_ERROR;
    }

    tee_memfd_pair_t io;
    const char *memfd_reason = NULL;
    if (tee_memfd_pair_open(&io, "tee_pdf_in", "tee_pdf_out",
                            data, len, &memfd_reason) != 0) {
        snprintf(reason, reason_size, "%s", memfd_reason);
        return SANITIZE_ERROR;
    }
    int in_fd = io.in_fd;
    int out_fd = io.out_fd;

    static const char meta_script[] =
        "[/Title () /Author () /Subject () /Keywords () "
        "/Creator () /Producer () /CreationDate () /ModDate () "
        "/Metadata null /DOCINFO pdfmark\n";

    char meta_path[TEE_MEMFD_PATH_MAX];
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

    struct timespec scan_deadline;
    clock_gettime(CLOCK_MONOTONIC, &scan_deadline);
    scan_deadline.tv_sec += TEE_SCAN_CONVERTER_BUDGET_SECS;

    int timeout_secs = tee_secs_until(&scan_deadline);
    if (timeout_secs > TEE_SUBPROC_WALL_CAP_SECS) timeout_secs = TEE_SUBPROC_WALL_CAP_SECS;

    char *const gs_args[] = {
        (char *)gs,
        "-dSAFER", "-dNOPAUSE", "-dBATCH", "-dQUIET",
        "-sDEVICE=pdfwrite",
        "-dCompatibilityLevel=1.7",
        "-dPDFSETTINGS=/default",
        "-dDetectDuplicateImages=true",
        "-dColorImageDownsample=false",
        "-dGrayImageDownsample=false",
        "-dMonoImageDownsample=false",
        "-o", io.out_path,
        io.in_path,
        meta_path,
        NULL
    };

    int wait_rc = tee_spawn_converter(gs, gs_args, timeout_secs,
                                      (const int[]){in_fd, out_fd, meta_fd}, 3);

    close(in_fd);
    close(meta_fd);

    if (wait_rc != TEE_SUBPROC_OK) {
        close(out_fd);
        const char *why = "ghostscript_failed";
        if (wait_rc == TEE_SUBPROC_TIMEOUT)         why = "ghostscript_timeout";
        else if (wait_rc == TEE_SUBPROC_SPAWN_FAIL) why = "fork_failed";
        snprintf(reason, reason_size, "%s", why);
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
