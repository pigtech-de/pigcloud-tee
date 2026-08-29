#ifndef PIGCLOUD_TEE_CRYPTO_H
#define PIGCLOUD_TEE_CRYPTO_H

#include <stddef.h>
#include <stdint.h>

#include "protocol.h"

typedef void (*tee_crypto_progress_cb)(void);

void tee_crypto_set_progress_cb(tee_crypto_progress_cb cb);

typedef int (*tee_chunk_cb)(const unsigned char *chunk, size_t len, void *userdata);

#define TEE_UNSEAL_REASON_BLOB_TOO_SHORT      "unseal_blob_too_short"
#define TEE_UNSEAL_REASON_X25519_ECDH         "unseal_x25519_ecdh_failed"
#define TEE_UNSEAL_REASON_X25519_RECIPIENT_PK "unseal_x25519_recipient_pk_failed"
#define TEE_UNSEAL_REASON_MLKEM_UNAVAILABLE   "unseal_mlkem_unavailable"
#define TEE_UNSEAL_REASON_MLKEM_PARAM         "unseal_mlkem_param_mismatch"
#define TEE_UNSEAL_REASON_MLKEM_KEYPAIR       "unseal_mlkem_keypair_failed"
#define TEE_UNSEAL_REASON_MLKEM_DECAPS        "unseal_mlkem_decaps_failed"
#define TEE_UNSEAL_REASON_KDF_SALT_OVERFLOW   "unseal_kdf_salt_overflow"
#define TEE_UNSEAL_REASON_KDF_IKM_OVERFLOW    "unseal_kdf_ikm_overflow"
#define TEE_UNSEAL_REASON_AEAD_AUTH           "unseal_aead_auth_failed"

int tee_unseal_hybrid_data_key(
    const unsigned char *sealed, size_t sealed_len,
    const unsigned char *enclave_x25519_sk,
    const unsigned char *enclave_kyber_seed,
    unsigned char data_key_out[E2EE_KEY_SIZE],
    const char **reason_out
);

typedef struct {
    unsigned char bytes[32];
    int produced;
} tee_output_digest_t;

int tee_sign_hash(
    const unsigned char hash[32],
    const unsigned char *enclave_ed25519_sk,
    const unsigned char *enclave_mldsa_sk,
    unsigned char sig_ed25519_out[E2EE_ED25519_SIG_SIZE],
    unsigned char sig_mldsa_out[MLDSA44_SIGNATURE_SIZE]
);

int tee_decrypt_file(
    const char *ciphertext_path,
    const unsigned char data_key[E2EE_KEY_SIZE],
    const unsigned char nonce[E2EE_NONCE_SIZE],
    int expected_chunks,
    const char *expected_sha256,
    int meta_version,
    unsigned char **plaintext_out,
    size_t *plaintext_len
);

int tee_decrypt_file_cb(
    const char *ciphertext_path,
    const unsigned char data_key[E2EE_KEY_SIZE],
    const unsigned char nonce[E2EE_NONCE_SIZE],
    int expected_chunks,
    const char *expected_sha256,
    int meta_version,
    tee_chunk_cb chunk_cb,
    void *chunk_cb_userdata,
    char *derived_sha256_hex,
    unsigned char **plaintext_out,
    size_t *plaintext_len
);

int tee_encrypt_file(
    const unsigned char *plaintext,
    size_t plaintext_len,
    const unsigned char data_key[E2EE_KEY_SIZE],
    const char *output_path,
    unsigned char new_nonce_out[E2EE_NONCE_SIZE],
    int *new_chunks_out,
    char new_sha256_out[SHA256_HEX_BUF],
    tee_output_digest_t *ciphertext_digest_out
);

int tee_verify_metadata_mac(
    const unsigned char data_key[E2EE_KEY_SIZE],
    int version,
    const char *nonce_b64,
    int chunk_size,
    int chunks,
    const char *plaintext_sha256,
    int64_t plaintext_size,
    const char *expected_mac_hex
);

int tee_compute_metadata_mac(
    const unsigned char data_key[E2EE_KEY_SIZE],
    int version,
    const char *nonce_b64,
    int chunk_size,
    int chunks,
    const char *plaintext_sha256,
    int64_t plaintext_size,
    char mac_hex_out[SHA256_HEX_BUF]
);

#endif
