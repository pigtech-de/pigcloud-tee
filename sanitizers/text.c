#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include "sanitizers.h"

static const unsigned char UTF8_BOM[] = { 0xEF, 0xBB, 0xBF };

int sanitize_text(
    const unsigned char *data, size_t len,
    unsigned char **out, size_t *out_len,
    char *reason, size_t reason_size)
{
    *out = NULL;
    *out_len = 0;

    if (len == 0) {
        return SANITIZE_CLEAN;
    }

    if (len >= 3 && memcmp(data, UTF8_BOM, 3) == 0) {
        size_t new_len = len - 3;
        if (new_len == 0) {
            *out = malloc(1);
            if (!*out) {
                snprintf(reason, reason_size, "malloc_failed");
                return SANITIZE_ERROR;
            }
            (*out)[0] = '\0';
            *out_len = 0;
            return SANITIZE_MODIFIED;
        }

        *out = malloc(new_len);
        if (!*out) {
            snprintf(reason, reason_size, "malloc_failed");
            return SANITIZE_ERROR;
        }
        memcpy(*out, data + 3, new_len);
        *out_len = new_len;
        snprintf(reason, reason_size, "bom_stripped");
        return SANITIZE_MODIFIED;
    }

    return SANITIZE_CLEAN;
}
