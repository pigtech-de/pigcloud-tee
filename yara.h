#ifndef PIGCLOUD_TEE_YARA_H
#define PIGCLOUD_TEE_YARA_H

#include <stddef.h>

typedef enum {
    PIGCLOUD_YARA_CLEAN       = 0,
    PIGCLOUD_YARA_MATCH       = 1,
    PIGCLOUD_YARA_UNAVAILABLE = 2,
    PIGCLOUD_YARA_TIMEOUT     = 3
} pigcloud_yara_verdict_t;

int pigcloud_yara_init(void);

pigcloud_yara_verdict_t pigcloud_yara_scan(
    const unsigned char *data, size_t len,
    char *rule_name_out, size_t rule_name_size
);

void pigcloud_yara_destroy(void);

#endif
