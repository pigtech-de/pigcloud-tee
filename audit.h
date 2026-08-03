#ifndef PIGCLOUD_TEE_AUDIT_H
#define PIGCLOUD_TEE_AUDIT_H

#include <stdint.h>

typedef struct {
    uint64_t user_id;
    const char *plaintext_sha256;
    const char *verdict;
    const char *reason;
    uint64_t duration_ms;
} audit_entry_t;

int audit_init(void);

void audit_shutdown(void);

void audit_record(const audit_entry_t *entry);

void audit_request_reseed(void);

uint64_t audit_write_failures(void);

#endif
