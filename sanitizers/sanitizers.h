#ifndef PIGCLOUD_TEE_SANITIZERS_H
#define PIGCLOUD_TEE_SANITIZERS_H

#include <stddef.h>

#include "../protocol.h"

#define SANITIZE_CLEAN     0
#define SANITIZE_MODIFIED  1
#define SANITIZE_REJECTED  2
#define SANITIZE_ERROR    -1

#define MAX_IMAGE_WIDTH   16384
#define MAX_IMAGE_HEIGHT  16384
#define MAX_IMAGE_PIXELS  (100LL * 1000LL * 1000LL)

#define MAX_IMAGE_DECODE_BYTES  (512LL * 1024 * 1024)

#define ARCHIVE_MAX_DEPTH       8
#define ARCHIVE_MAX_ENTRIES     2000
#define ARCHIVE_EXPANSION_MULT  200
#define ARCHIVE_EXPANSION_MIN   (10 * 1024 * 1024)
#define ARCHIVE_EXPANSION_MAX   (2LL * 1024 * 1024 * 1024)
#define ARCHIVE_INFLATE_SCRATCH (32 * 1024)

#define TEE_SUBPROC_WALL_CAP_SECS       300
#define TEE_SCAN_CONVERTER_BUDGET_SECS  420

_Static_assert(TEE_SCAN_WALL_CAP_SECS > TEE_SCAN_CONVERTER_BUDGET_SECS,
    "per-scan wall cap must exceed the converter budget it contains");
_Static_assert(TEE_SCAN_WALL_CAP_SECS < 600,
    "per-scan wall cap must stay under the systemd watchdog");

#define TEE_PDF_MAX_INPUT_BYTES    (1024LL * 1024 * 1024)
#define TEE_AUDIO_MAX_INPUT_BYTES  (1024LL * 1024 * 1024)
#define TEE_VIDEO_MAX_INPUT_BYTES  (5LL * 1024 * 1024 * 1024)

#define TEE_SUBPROC_MAX_OUTPUT_BYTES (5LL * 1024 * 1024 * 1024)

void tee_subproc_progress_tick(void);

#define REASON_BUF_SIZE 512

int sanitize_raster_image(
    const unsigned char *data, size_t len,
    const char *mime, const char *ext,
    unsigned char **out, size_t *out_len,
    char *reason, size_t reason_size
);

int sanitize_svg(
    const unsigned char *data, size_t len,
    unsigned char **out, size_t *out_len,
    char *reason, size_t reason_size
);

int sanitize_text(
    const unsigned char *data, size_t len,
    unsigned char **out, size_t *out_len,
    char *reason, size_t reason_size
);

int inspect_archive(
    const unsigned char *data, size_t len,
    const char *mime, const char *ext,
    char *reason, size_t reason_size
);

int sanitize_pdf(
    const unsigned char *data, size_t len,
    unsigned char **out, size_t *out_len,
    char *reason, size_t reason_size
);

int sanitize_video(
    const unsigned char *data, size_t len,
    const char *ext,
    unsigned char **out, size_t *out_len,
    char *reason, size_t reason_size
);

int sanitize_audio(
    const unsigned char *data, size_t len,
    const char *ext,
    unsigned char **out, size_t *out_len,
    char *reason, size_t reason_size
);

#endif
