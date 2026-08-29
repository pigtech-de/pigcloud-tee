#define _GNU_SOURCE

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <fcntl.h>
#include <unistd.h>

#include <sodium.h>
#include <oqs/oqs.h>

#include "crypto.h"
#include "protocol.h"

static tee_crypto_progress_cb g_progress_cb = NULL;

void tee_crypto_set_progress_cb(tee_crypto_progress_cb cb)
{
    g_progress_cb = cb;
}

static inline void notify_progress(void)
{
    if (g_progress_cb) {
        g_progress_cb();
    }
}

static uint32_t read_be32(const unsigned char *buf)
{
    return ((uint32_t)buf[0] << 24)
         | ((uint32_t)buf[1] << 16)
         | ((uint32_t)buf[2] <<  8)
         | ((uint32_t)buf[3]);
}

static void write_be32(unsigned char *buf, uint32_t val)
{
    buf[0] = (unsigned char)(val >> 24);
    buf[1] = (unsigned char)(val >> 16);
    buf[2] = (unsigned char)(val >>  8);
    buf[3] = (unsigned char)(val);
}

static void hex_encode(const unsigned char *data, size_t len, char *out)
{
    static const char hex[] = "0123456789abcdef";
    for (size_t i = 0; i < len; i++) {
        out[i * 2]     = hex[data[i] >> 4];
        out[i * 2 + 1] = hex[data[i] & 0x0f];
    }
    out[len * 2] = '\0';
}

static int sha256_hex(const unsigned char *data, size_t len, char out[SHA256_HEX_BUF])
{
    unsigned char hash[crypto_hash_sha256_BYTES];
    if (crypto_hash_sha256(hash, data, len) != 0) {
        return -1;
    }
    hex_encode(hash, sizeof(hash), out);
    return 0;
}

static int unseal_fail(const char **reason_out, const char *reason)
{
    if (reason_out) {
        *reason_out = reason;
    }
    return -1;
}

static int derive_hybrid_wrap_key(
    const unsigned char *mlkem_ct,         size_t mlkem_ct_len,
    const unsigned char *eph_pk,           size_t eph_pk_len,
    const unsigned char *recipient_pk,     size_t recipient_pk_len,
    const unsigned char *ss_x,             size_t ss_x_len,
    const unsigned char *ss_k,             size_t ss_k_len,
    unsigned char out[E2EE_KEY_SIZE],
    const char **reason_out)
{
    unsigned char salt[KYBER_CIPHERTEXT_SIZE + 32 + 32];
    size_t salt_len = mlkem_ct_len + eph_pk_len + recipient_pk_len;
    if (salt_len > sizeof(salt)) {
        return unseal_fail(reason_out, TEE_UNSEAL_REASON_KDF_SALT_OVERFLOW);
    }
    memcpy(salt, mlkem_ct, mlkem_ct_len);
    memcpy(salt + mlkem_ct_len, eph_pk, eph_pk_len);
    memcpy(salt + mlkem_ct_len + eph_pk_len, recipient_pk, recipient_pk_len);

    unsigned char ikm[64];
    if (ss_x_len + ss_k_len > sizeof(ikm)) {
        sodium_memzero(salt, sizeof(salt));
        return unseal_fail(reason_out, TEE_UNSEAL_REASON_KDF_IKM_OVERFLOW);
    }
    memcpy(ikm, ss_x, ss_x_len);
    memcpy(ikm + ss_x_len, ss_k, ss_k_len);

    unsigned char prk[crypto_auth_hmacsha256_BYTES];
    {
        crypto_auth_hmacsha256_state state;
        crypto_auth_hmacsha256_init(&state, salt, salt_len);
        crypto_auth_hmacsha256_update(&state, ikm, ss_x_len + ss_k_len);
        crypto_auth_hmacsha256_final(&state, prk);
    }
    sodium_memzero(salt, sizeof(salt));
    sodium_memzero(ikm, sizeof(ikm));

    {
        const unsigned char counter = 0x01;
        crypto_auth_hmacsha256_state state;
        crypto_auth_hmacsha256_init(&state, prk, sizeof(prk));
        crypto_auth_hmacsha256_update(&state,
            (const unsigned char *)HYBRID_KDF_INFO,
            sizeof(HYBRID_KDF_INFO) - 1);
        crypto_auth_hmacsha256_update(&state, &counter, 1);
        crypto_auth_hmacsha256_final(&state, out);
    }
    sodium_memzero(prk, sizeof(prk));
    return 0;
}

int tee_unseal_hybrid_data_key(
    const unsigned char *sealed, size_t sealed_len,
    const unsigned char *enclave_x25519_sk,
    const unsigned char *enclave_kyber_seed,
    unsigned char data_key_out[E2EE_KEY_SIZE],
    const char **reason_out)
{
    if (reason_out) {
        *reason_out = NULL;
    }
    if (sealed_len < HYBRID_HEADER_SIZE + E2EE_KEY_SIZE + E2EE_TAG_SIZE) {
        return unseal_fail(reason_out, TEE_UNSEAL_REASON_BLOB_TOO_SHORT);
    }

    const unsigned char *eph_pk = sealed;
    const unsigned char *mlkem_ct = sealed + 32;
    const unsigned char *aead_nonce = sealed + 32 + KYBER_CIPHERTEXT_SIZE;
    const unsigned char *aead_ct = sealed + HYBRID_HEADER_SIZE;
    size_t aead_ct_len = sealed_len - HYBRID_HEADER_SIZE;

    unsigned char ss_x[crypto_scalarmult_BYTES];
    if (crypto_scalarmult(ss_x, enclave_x25519_sk, eph_pk) != 0) {
        return unseal_fail(reason_out, TEE_UNSEAL_REASON_X25519_ECDH);
    }

    unsigned char recipient_pk[crypto_scalarmult_BYTES];
    if (crypto_scalarmult_base(recipient_pk, enclave_x25519_sk) != 0) {
        sodium_memzero(ss_x, sizeof(ss_x));
        return unseal_fail(reason_out, TEE_UNSEAL_REASON_X25519_RECIPIENT_PK);
    }

    OQS_KEM *kem = OQS_KEM_new(OQS_KEM_alg_ml_kem_768);
    if (!kem) {
        sodium_memzero(ss_x, sizeof(ss_x));
        return unseal_fail(reason_out, TEE_UNSEAL_REASON_MLKEM_UNAVAILABLE);
    }
    if (kem->length_secret_key != KYBER_SECRET_KEY_SIZE
        || kem->length_ciphertext != KYBER_CIPHERTEXT_SIZE
        || kem->length_shared_secret != KYBER_SHARED_SECRET_SIZE) {
        OQS_KEM_free(kem);
        sodium_memzero(ss_x, sizeof(ss_x));
        return unseal_fail(reason_out, TEE_UNSEAL_REASON_MLKEM_PARAM);
    }

    unsigned char tmp_pk[KYBER_PUBLIC_KEY_SIZE];
    unsigned char tmp_sk[KYBER_SECRET_KEY_SIZE];
    if (OQS_KEM_keypair_derand(kem, tmp_pk, tmp_sk, enclave_kyber_seed) != OQS_SUCCESS) {
        OQS_KEM_free(kem);
        sodium_memzero(ss_x, sizeof(ss_x));
        sodium_memzero(tmp_sk, sizeof(tmp_sk));
        return unseal_fail(reason_out, TEE_UNSEAL_REASON_MLKEM_KEYPAIR);
    }
    sodium_memzero(tmp_pk, sizeof(tmp_pk));

    unsigned char ss_k[KYBER_SHARED_SECRET_SIZE];
    if (OQS_KEM_decaps(kem, ss_k, mlkem_ct, tmp_sk) != OQS_SUCCESS) {
        sodium_memzero(tmp_sk, sizeof(tmp_sk));
        sodium_memzero(ss_x, sizeof(ss_x));
        OQS_KEM_free(kem);
        return unseal_fail(reason_out, TEE_UNSEAL_REASON_MLKEM_DECAPS);
    }
    sodium_memzero(tmp_sk, sizeof(tmp_sk));
    OQS_KEM_free(kem);

    unsigned char wrap_key[E2EE_KEY_SIZE];
    int rc = derive_hybrid_wrap_key(
        mlkem_ct, KYBER_CIPHERTEXT_SIZE,
        eph_pk, 32,
        recipient_pk, sizeof(recipient_pk),
        ss_x, sizeof(ss_x),
        ss_k, sizeof(ss_k),
        wrap_key, reason_out);
    sodium_memzero(ss_x, sizeof(ss_x));
    sodium_memzero(ss_k, sizeof(ss_k));
    sodium_memzero(recipient_pk, sizeof(recipient_pk));
    if (rc != 0) {
        sodium_memzero(wrap_key, sizeof(wrap_key));
        return -1;
    }

    unsigned long long out_len = 0;
    int aead_rc = crypto_aead_xchacha20poly1305_ietf_decrypt(
        data_key_out, &out_len, NULL,
        aead_ct, aead_ct_len,
        NULL, 0,
        aead_nonce, wrap_key);
    sodium_memzero(wrap_key, sizeof(wrap_key));
    if (aead_rc != 0 || out_len != E2EE_KEY_SIZE) {
        sodium_memzero(data_key_out, E2EE_KEY_SIZE);
        return unseal_fail(reason_out, TEE_UNSEAL_REASON_AEAD_AUTH);
    }
    return 0;
}

int tee_sign_hash(
    const unsigned char hash[32],
    const unsigned char *enclave_ed25519_sk,
    const unsigned char *enclave_mldsa_sk,
    unsigned char sig_ed25519_out[E2EE_ED25519_SIG_SIZE],
    unsigned char sig_mldsa_out[MLDSA44_SIGNATURE_SIZE])
{
    const size_t domain_len = sizeof(TEE_SIGNATURE_DOMAIN) - 1;
    unsigned char input[domain_len + 32];
    memcpy(input, TEE_SIGNATURE_DOMAIN, domain_len);
    memcpy(input + domain_len, hash, 32);

    if (crypto_sign_detached(sig_ed25519_out, NULL,
                             input, sizeof(input),
                             enclave_ed25519_sk) != 0) {
        sodium_memzero(input, sizeof(input));
        return -1;
    }

    OQS_SIG *sig = OQS_SIG_new(OQS_SIG_alg_ml_dsa_44);
    if (!sig) {
        sodium_memzero(input, sizeof(input));
        return -1;
    }
    size_t mldsa_sig_len = 0;
    if (OQS_SIG_sign(sig, sig_mldsa_out, &mldsa_sig_len,
                     input, sizeof(input),
                     enclave_mldsa_sk) != OQS_SUCCESS
        || mldsa_sig_len != MLDSA44_SIGNATURE_SIZE) {
        OQS_SIG_free(sig);
        sodium_memzero(input, sizeof(input));
        return -1;
    }
    OQS_SIG_free(sig);
    sodium_memzero(input, sizeof(input));
    return 0;
}

int tee_decrypt_file(
    const char *ciphertext_path,
    const unsigned char data_key[E2EE_KEY_SIZE],
    const unsigned char nonce[E2EE_NONCE_SIZE],
    int expected_chunks,
    const char *expected_sha256,
    int meta_version,
    unsigned char **plaintext_out,
    size_t *plaintext_len)
{
    return tee_decrypt_file_cb(ciphertext_path, data_key, nonce,
                               expected_chunks, expected_sha256, meta_version,
                               NULL, NULL, NULL,
                               plaintext_out, plaintext_len);
}

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
    size_t *plaintext_len)
{
    if (expected_chunks <= 0 || meta_version < E2EE_METADATA_VERSION) {
        return -1;
    }

    int cfd = open(ciphertext_path, O_RDONLY | O_NOFOLLOW | O_CLOEXEC);
    if (cfd < 0) {
        return -1;
    }
    FILE *fp = fdopen(cfd, "rb");
    if (!fp) {
        close(cfd);
        return -1;
    }

    if (fseek(fp, 0, SEEK_END) != 0) {
        fclose(fp);
        return -1;
    }
    long file_size = ftell(fp);
    if (fseek(fp, 0, SEEK_SET) != 0 || file_size < 0 ||
        (size_t)file_size > TEE_MAX_PLAINTEXT_SIZE) {
        fclose(fp);
        return -1;
    }

    size_t alloc_size = (size_t)file_size;
    if (alloc_size == 0) {
        alloc_size = 1;
    }
    unsigned char *result = malloc(alloc_size);
    if (!result) {
        fclose(fp);
        return -1;
    }

    crypto_hash_sha256_state sha_state;
    crypto_hash_sha256_init(&sha_state);

    unsigned char current_nonce[E2EE_NONCE_SIZE];
    memcpy(current_nonce, nonce, E2EE_NONCE_SIZE);

    unsigned char len_buf[E2EE_LEN_PREFIX_SIZE];
    size_t total_plaintext = 0;
    int chunk_index = 0;

    unsigned char *chunk_ct = malloc(E2EE_MAX_CHUNK_CIPHERTEXT);
    unsigned char *chunk_pt = malloc(E2EE_MAX_CHUNK_CIPHERTEXT);
    if (!chunk_ct || !chunk_pt) {
        free(chunk_ct); free(chunk_pt);
        free(result);
        fclose(fp);
        return -1;
    }

    while (1) {
        size_t rd = fread(len_buf, 1, E2EE_LEN_PREFIX_SIZE, fp);
        if (rd == 0 && feof(fp)) {
            break;
        }
        if (rd != E2EE_LEN_PREFIX_SIZE) {
            goto decrypt_fail;
        }

        uint32_t chunk_len = read_be32(len_buf);
        if (chunk_len > E2EE_MAX_CHUNK_CIPHERTEXT) {
            goto decrypt_fail;
        }

        if (fread(chunk_ct, 1, chunk_len, fp) != chunk_len) {
            goto decrypt_fail;
        }

        unsigned char chunk_ad[E2EE_CHUNK_AD_SIZE];
        write_be32(chunk_ad, (uint32_t)chunk_index);

        unsigned long long pt_len = 0;
        int rc = crypto_aead_xchacha20poly1305_ietf_decrypt(
            chunk_pt, &pt_len, NULL,
            chunk_ct, chunk_len,
            chunk_ad, E2EE_CHUNK_AD_SIZE,
            current_nonce, data_key
        );

        if (rc != 0) {
            goto decrypt_fail;
        }

        if (total_plaintext + pt_len > alloc_size) {
            goto decrypt_fail;
        }
        memcpy(result + total_plaintext, chunk_pt, pt_len);
        crypto_hash_sha256_update(&sha_state, chunk_pt, pt_len);
        total_plaintext += pt_len;

        if (chunk_cb) {
            if (chunk_cb(chunk_pt, pt_len, chunk_cb_userdata) != 0) {
                goto decrypt_fail;
            }
        }

        sodium_increment(current_nonce, E2EE_NONCE_SIZE);
        chunk_index++;

        notify_progress();
    }

    sodium_memzero(chunk_pt, E2EE_MAX_CHUNK_CIPHERTEXT);
    free(chunk_ct);
    free(chunk_pt);
    fclose(fp);
    goto decrypt_verify;

decrypt_fail:
    sodium_memzero(chunk_pt, E2EE_MAX_CHUNK_CIPHERTEXT);
    free(chunk_ct);
    free(chunk_pt);
    free(result);
    fclose(fp);
    return -1;

decrypt_verify:

    if (chunk_index != expected_chunks) {
        sodium_memzero(result, total_plaintext);
        free(result);
        return -1;
    }

    unsigned char computed[crypto_hash_sha256_BYTES];
    crypto_hash_sha256_final(&sha_state, computed);
    if (derived_sha256_hex) {
        sodium_bin2hex(derived_sha256_hex, SHA256_HEX_BUF, computed, sizeof(computed));
    }

    if (expected_sha256 && expected_sha256[0] != '\0') {
        unsigned char expected_bin[crypto_hash_sha256_BYTES];
        if (sodium_hex2bin(expected_bin, sizeof(expected_bin),
                           expected_sha256, SHA256_HEX_LEN,
                           NULL, NULL, NULL) != 0) {
            sodium_memzero(result, total_plaintext);
            free(result);
            return -1;
        }
        if (sodium_memcmp(computed, expected_bin, sizeof(computed)) != 0) {
            sodium_memzero(result, total_plaintext);
            free(result);
            return -1;
        }
    }

    *plaintext_out = result;
    *plaintext_len = total_plaintext;
    return 0;
}

int tee_encrypt_file(
    const unsigned char *plaintext,
    size_t plaintext_len,
    const unsigned char data_key[E2EE_KEY_SIZE],
    const char *output_path,
    unsigned char new_nonce_out[E2EE_NONCE_SIZE],
    int *new_chunks_out,
    char new_sha256_out[SHA256_HEX_BUF],
    tee_output_digest_t *ciphertext_digest_out)
{
    unsigned char nonce[E2EE_NONCE_SIZE];
    randombytes_buf(nonce, E2EE_NONCE_SIZE);
    memcpy(new_nonce_out, nonce, E2EE_NONCE_SIZE);

    if (sha256_hex(plaintext, plaintext_len, new_sha256_out) != 0) {
        return -1;
    }

    FILE *fp = fopen(output_path, "wb");
    if (!fp) {
        return -1;
    }

    crypto_hash_sha256_state ct_hash;
    crypto_hash_sha256_init(&ct_hash);

    unsigned char current_nonce[E2EE_NONCE_SIZE];
    memcpy(current_nonce, nonce, E2EE_NONCE_SIZE);
    int chunks = 0;
    size_t offset = 0;

    while (offset < plaintext_len || (plaintext_len == 0 && chunks == 0)) {
        size_t chunk_pt_len = plaintext_len - offset;
        if (chunk_pt_len > E2EE_CHUNK_SIZE) {
            chunk_pt_len = E2EE_CHUNK_SIZE;
        }

        unsigned char chunk_ad[E2EE_CHUNK_AD_SIZE];
        write_be32(chunk_ad, (uint32_t)chunks);

        size_t ct_max_len = chunk_pt_len + crypto_aead_xchacha20poly1305_ietf_ABYTES;
        unsigned char *ct = malloc(ct_max_len);
        if (!ct) {
            fclose(fp);
            return -1;
        }

        unsigned long long ct_len = 0;
        if (crypto_aead_xchacha20poly1305_ietf_encrypt(
                ct, &ct_len,
                plaintext + offset, chunk_pt_len,
                chunk_ad, E2EE_CHUNK_AD_SIZE,
                NULL, current_nonce, data_key) != 0) {
            free(ct);
            fclose(fp);
            return -1;
        }

        unsigned char len_buf[E2EE_LEN_PREFIX_SIZE];
        write_be32(len_buf, (uint32_t)ct_len);
        if (fwrite(len_buf, 1, E2EE_LEN_PREFIX_SIZE, fp) != E2EE_LEN_PREFIX_SIZE ||
            fwrite(ct, 1, ct_len, fp) != ct_len) {
            free(ct);
            fclose(fp);
            return -1;
        }
        crypto_hash_sha256_update(&ct_hash, len_buf, E2EE_LEN_PREFIX_SIZE);
        crypto_hash_sha256_update(&ct_hash, ct, ct_len);

        free(ct);
        sodium_increment(current_nonce, E2EE_NONCE_SIZE);
        chunks++;
        offset += chunk_pt_len;

        notify_progress();

        if (plaintext_len == 0) {
            break;
        }
    }

    if (fclose(fp) != 0) {
        return -1;
    }
    if (ciphertext_digest_out) {
        crypto_hash_sha256_final(&ct_hash, ciphertext_digest_out->bytes);
        ciphertext_digest_out->produced = 1;
    }
    *new_chunks_out = chunks;
    return 0;
}

static int build_metadata_canonical(
    int version, const char *nonce_b64, int chunk_size, int chunks,
    const char *plaintext_sha256, int64_t plaintext_size,
    char *buf, size_t buf_size)
{
    int n = snprintf(buf, buf_size,
        "[%d,\"%s\",%d,%d,\"%s\",%lld]",
        version, nonce_b64, chunk_size, chunks,
        plaintext_sha256, (long long)plaintext_size);
    if (n < 0 || (size_t)n >= buf_size) {
        return -1;
    }
    return n;
}

int tee_verify_metadata_mac(
    const unsigned char data_key[E2EE_KEY_SIZE],
    int version, const char *nonce_b64, int chunk_size, int chunks,
    const char *plaintext_sha256, int64_t plaintext_size,
    const char *expected_mac_hex)
{
    if (!expected_mac_hex || expected_mac_hex[0] == '\0') {
        return -1;
    }

    char canonical[1024];
    int clen = build_metadata_canonical(
        version, nonce_b64, chunk_size, chunks,
        plaintext_sha256, plaintext_size,
        canonical, sizeof(canonical));
    if (clen < 0) {
        return -1;
    }

    unsigned char mac[crypto_auth_hmacsha256_BYTES];
    crypto_auth_hmacsha256_state state;
    crypto_auth_hmacsha256_init(&state, data_key, E2EE_KEY_SIZE);
    crypto_auth_hmacsha256_update(&state, (const unsigned char *)canonical, (unsigned long long)clen);
    crypto_auth_hmacsha256_final(&state, mac);

    unsigned char expected_bin[crypto_auth_hmacsha256_BYTES];
    if (sodium_hex2bin(expected_bin, sizeof(expected_bin),
                       expected_mac_hex, SHA256_HEX_LEN,
                       NULL, NULL, NULL) != 0) {
        return -1;
    }
    if (sodium_memcmp(mac, expected_bin, sizeof(mac)) != 0) {
        return -1;
    }
    return 0;
}

int tee_compute_metadata_mac(
    const unsigned char data_key[E2EE_KEY_SIZE],
    int version, const char *nonce_b64, int chunk_size, int chunks,
    const char *plaintext_sha256, int64_t plaintext_size,
    char mac_hex_out[SHA256_HEX_BUF])
{
    char canonical[1024];
    int clen = build_metadata_canonical(
        version, nonce_b64, chunk_size, chunks,
        plaintext_sha256, plaintext_size,
        canonical, sizeof(canonical));
    if (clen < 0) {
        return -1;
    }

    unsigned char mac[crypto_auth_hmacsha256_BYTES];
    crypto_auth_hmacsha256_state state;
    crypto_auth_hmacsha256_init(&state, data_key, E2EE_KEY_SIZE);
    crypto_auth_hmacsha256_update(&state, (const unsigned char *)canonical, (unsigned long long)clen);
    crypto_auth_hmacsha256_final(&state, mac);

    hex_encode(mac, sizeof(mac), mac_hex_out);
    return 0;
}
