#ifndef PIGCLOUD_TEE_SCANNER_H
#define PIGCLOUD_TEE_SCANNER_H

#include <stddef.h>
#include "protocol.h"

int scanner_init(void);

typedef void (*scanner_progress_cb)(void);
void scanner_set_progress_cb(scanner_progress_cb cb);

int scanner_inspect(
    const unsigned char *plaintext,
    size_t plaintext_len,
    const char *filename,
    int skip_av,
    scan_result_t *result,
    unsigned char **sanitized_out,
    size_t *sanitized_len
);

void scanner_destroy(void);

#endif
