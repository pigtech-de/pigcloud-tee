#ifndef PIGCLOUD_TEE_CLAMAV_H
#define PIGCLOUD_TEE_CLAMAV_H

#include <stddef.h>

typedef enum {
    CLAMAV_VERDICT_CLEAN       = 0,
    CLAMAV_VERDICT_INFECTED    = 1,
    CLAMAV_VERDICT_UNAVAILABLE = 2,
    CLAMAV_VERDICT_ERROR       = 3,
    CLAMAV_VERDICT_TOO_LARGE   = 4
} clamav_verdict_t;

clamav_verdict_t clamav_scan_buffer(
    const unsigned char *data, size_t len,
    char *signature_out, size_t signature_out_size
);

typedef struct clamav_stream clamav_stream_t;

clamav_stream_t *clamav_stream_begin(void);
int clamav_stream_feed(clamav_stream_t *s, const unsigned char *data, size_t len);
clamav_verdict_t clamav_stream_finish(clamav_stream_t *s,
                                     char *signature_out, size_t signature_out_size);

#endif
