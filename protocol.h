#ifndef PIGCLOUD_TEE_PROTOCOL_H
#define PIGCLOUD_TEE_PROTOCOL_H

#include <stdint.h>

#define PROTOCOL_MAX_MSG_SIZE (16 * 1024 * 1024)

#define SCANNER_SOCKET_PATH "/run/pigcloud-tee/scanner.sock"

#define SIGNER_SOCKET_PATH "/run/pigcloud-tee/signer.sock"

#define QUARANTINE_PATH_PREFIX "/var/www/pigtech/private/uploads/quarantine/"

#define QUARANTINE_SANITIZED_SUBDIR "sanitized/"

#define TEE_MAX_PLAINTEXT_SIZE (5ULL * 1024 * 1024 * 1024)

#define TEE_SCAN_WALL_CAP_SECS 540

#define OP_SCAN          "scan"
#define OP_ATTESTATION   "get_attestation"
#define OP_HEALTH        "health"
#define OP_METRICS       "metrics"
#define OP_UNSEAL        "unseal"
#define OP_SIGN          "sign"

#define TEE_ATTEST_NONCE_SIZE 32

#define VERDICT_CLEAN     "clean"
#define VERDICT_SANITIZED "sanitized"
#define VERDICT_REJECTED  "rejected"
#define VERDICT_ERROR     "error"

#define REASON_SCANNER_BUSY      "scanner_busy"
#define TEE_BUSY_RETRY_AFTER_MS  2000

#define E2EE_CHUNK_SIZE       (1024 * 1024)
#define E2EE_KEY_SIZE         32
#define E2EE_NONCE_SIZE       24
#define E2EE_TAG_SIZE         16
#define E2EE_CHUNK_AD_SIZE    4
#define E2EE_LEN_PREFIX_SIZE  4
#define E2EE_METADATA_VERSION 2

#define KYBER_PUBLIC_KEY_SIZE    1184
#define KYBER_SEED_SIZE          64
#define KYBER_SECRET_KEY_SIZE    2400
#define KYBER_CIPHERTEXT_SIZE    1088
#define KYBER_SHARED_SECRET_SIZE 32

#define HYBRID_HEADER_SIZE       (32 + KYBER_CIPHERTEXT_SIZE + E2EE_NONCE_SIZE)

#define HYBRID_SEALED_DATA_KEY_SIZE (HYBRID_HEADER_SIZE + E2EE_KEY_SIZE + E2EE_TAG_SIZE)

#define HYBRID_KDF_INFO          "pigcloud-hybrid-seal-v2"

#define TEE_SIGNATURE_DOMAIN     "pigcloud-tee-file-signature-v1"

#define E2EE_ED25519_SIG_SIZE    64
#define E2EE_ED25519_PK_SIZE     32

#define MLDSA44_PUBLIC_KEY_SIZE  1312
#define MLDSA44_SECRET_KEY_SIZE  2560
#define MLDSA44_SIGNATURE_SIZE   2420

#define E2EE_MAX_CHUNK_CIPHERTEXT (E2EE_CHUNK_SIZE + E2EE_TAG_SIZE + 1024)

typedef struct {
    char file_path[4096];
    uint64_t user_id;
    unsigned char tee_sealed_key[HYBRID_SEALED_DATA_KEY_SIZE];
    size_t tee_sealed_key_len;
    int meta_version;
    unsigned char meta_nonce[E2EE_NONCE_SIZE];
    int meta_chunk_size;
    int meta_chunks;
    char meta_plaintext_sha256[65];
    int64_t meta_plaintext_size;
    char meta_metadata_mac[65];
    char original_filename[256];
} scan_request_t;

typedef struct {
    const char *verdict;
    char reason[512];
    char detected_mime[256];
    char sanitized_path[4128];
    int has_new_meta;
    unsigned char new_nonce[E2EE_NONCE_SIZE];
    int new_chunks;
    char new_plaintext_sha256[65];
    int64_t new_plaintext_size;
    char new_metadata_mac[65];
    int has_tee_signature;
    unsigned char tee_signature_ed25519[E2EE_ED25519_SIG_SIZE];
    unsigned char tee_signature_mldsa[MLDSA44_SIGNATURE_SIZE];
    int av_unavailable;
    int yara_unavailable;
    uint64_t duration_ms;
} scan_result_t;

#endif
