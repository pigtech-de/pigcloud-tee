#ifndef PIGCLOUD_TEE_ATTESTATION_H
#define PIGCLOUD_TEE_ATTESTATION_H

#include <stddef.h>
#include <stdint.h>

#include "protocol.h"

typedef enum {
    ATTEST_MODE_NONE,
    ATTEST_MODE_EPID,
} attest_mode_t;

typedef struct {
    unsigned char enclave_pk[32];
    char enclave_pk_b64[64];
    unsigned char enclave_pk_kyber[KYBER_PUBLIC_KEY_SIZE];
    char *enclave_pk_kyber_b64;
    unsigned char enclave_pk_ed25519[32];
    char enclave_pk_ed25519_b64[64];
    unsigned char enclave_pk_mldsa[MLDSA44_PUBLIC_KEY_SIZE];
    char *enclave_pk_mldsa_b64;
    char *sgx_quote_b64;
    char *ias_report_b64;
    char *ias_signature_b64;
    char *ias_cert_chain;
    char mrenclave_hex[65];
} attestation_data_t;

int attestation_init(void);

const unsigned char *attestation_get_public_key(void);

const unsigned char *attestation_get_secret_key(void);

const unsigned char *attestation_get_kyber_public_key(void);

const unsigned char *attestation_get_kyber_seed(void);

const unsigned char *attestation_get_ed25519_public_key(void);
const unsigned char *attestation_get_ed25519_secret_key(void);
const unsigned char *attestation_get_mldsa_public_key(void);
const unsigned char *attestation_get_mldsa_secret_key(void);

attest_mode_t attestation_get_mode(void);

int attestation_get_data(attestation_data_t *out, const unsigned char *nonce);

void attestation_data_free(attestation_data_t *data);

void attestation_destroy(void);

uint64_t attestation_get_epoch(void);

void attestation_maybe_refresh(void);

#endif
