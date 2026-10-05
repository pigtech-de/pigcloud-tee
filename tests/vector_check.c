#define _GNU_SOURCE

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <sodium.h>
#include <oqs/oqs.h>

#include "../crypto.h"
#include "../protocol.h"
#include "../vendor/cjson/cJSON.h"

static int g_failures = 0;

static void check(int ok, const char *label)
{
    if (ok) {
        printf("PASS %s\n", label);
    } else {
        printf("FAIL %s\n", label);
        g_failures++;
    }
}

static unsigned char *b64_field(const cJSON *obj, const char *key, size_t *out_len)
{
    const cJSON *item = cJSON_GetObjectItemCaseSensitive(obj, key);
    if (!cJSON_IsString(item) || !item->valuestring) {
        fprintf(stderr, "missing string field %s\n", key);
        exit(1);
    }
    size_t b64_len = strlen(item->valuestring);
    unsigned char *bin = malloc(b64_len);
    if (!bin) {
        fprintf(stderr, "oom decoding %s\n", key);
        exit(1);
    }
    size_t bin_len = 0;
    if (sodium_base642bin(bin, b64_len, item->valuestring, b64_len,
                          NULL, &bin_len, NULL,
                          sodium_base64_VARIANT_ORIGINAL) != 0) {
        fprintf(stderr, "base64 decode failed for %s\n", key);
        exit(1);
    }
    *out_len = bin_len;
    return bin;
}

static const char *str_field(const cJSON *obj, const char *key)
{
    const cJSON *item = cJSON_GetObjectItemCaseSensitive(obj, key);
    if (!cJSON_IsString(item) || !item->valuestring) {
        fprintf(stderr, "missing string field %s\n", key);
        exit(1);
    }
    return item->valuestring;
}

static double num_field(const cJSON *obj, const char *key)
{
    const cJSON *item = cJSON_GetObjectItemCaseSensitive(obj, key);
    if (!cJSON_IsNumber(item)) {
        fprintf(stderr, "missing number field %s\n", key);
        exit(1);
    }
    return item->valuedouble;
}

static void temp_template(char *out, size_t size, const char *stem)
{
    const char *dir = getenv("TMPDIR");
    if (!dir || !*dir) {
        dir = "/tmp";
    }
    int n = snprintf(out, size, "%s/%s-XXXXXX", dir, stem);
    if (n < 0 || (size_t)n >= size) {
        fprintf(stderr, "temp path too long\n");
        exit(1);
    }
}

static void write_temp(const unsigned char *data, size_t len, char *path_out, size_t path_size)
{
    temp_template(path_out, path_size, "pigcloud-vector");
    int fd = mkstemp(path_out);
    if (fd < 0) {
        fprintf(stderr, "mkstemp failed\n");
        exit(1);
    }
    size_t off = 0;
    while (off < len) {
        ssize_t n = write(fd, data + off, len - off);
        if (n <= 0) {
            fprintf(stderr, "temp write failed\n");
            exit(1);
        }
        off += (size_t)n;
    }
    close(fd);
}

static cJSON *load_fixture(const char *path)
{
    FILE *f = fopen(path, "rb");
    if (!f) {
        fprintf(stderr, "cannot open %s\n", path);
        exit(1);
    }
    fseek(f, 0, SEEK_END);
    long fsize = ftell(f);
    fseek(f, 0, SEEK_SET);
    if (fsize <= 0) {
        fprintf(stderr, "empty fixture %s\n", path);
        exit(1);
    }
    char *raw = malloc((size_t)fsize + 1);
    if (!raw || fread(raw, 1, (size_t)fsize, f) != (size_t)fsize) {
        fprintf(stderr, "fixture read failed: %s\n", path);
        exit(1);
    }
    fclose(f);
    raw[fsize] = '\0';

    cJSON *v = cJSON_Parse(raw);
    free(raw);
    if (!v) {
        fprintf(stderr, "fixture JSON parse failed: %s\n", path);
        exit(1);
    }
    return v;
}

static const cJSON *obj_field(const cJSON *obj, const char *key)
{
    const cJSON *item = cJSON_GetObjectItemCaseSensitive(obj, key);
    if (!cJSON_IsObject(item)) {
        fprintf(stderr, "missing object field %s\n", key);
        exit(1);
    }
    return item;
}

static unsigned char *domain_input(const char *domain, const unsigned char hash[32], size_t *len_out)
{
    size_t domain_len = strlen(domain);
    unsigned char *input = malloc(domain_len + 32);
    if (!input) {
        fprintf(stderr, "oom building signing input\n");
        exit(1);
    }
    memcpy(input, domain, domain_len);
    memcpy(input + domain_len, hash, 32);
    *len_out = domain_len + 32;
    return input;
}

static int mldsa_verifies(OQS_SIG *alg, const unsigned char *msg, size_t msg_len,
                          const unsigned char *sig, size_t sig_len, const unsigned char *pk)
{
    return OQS_SIG_verify(alg, msg, msg_len, sig, sig_len, pk) == OQS_SUCCESS;
}

static void check_file_signature_vector(const char *path)
{
    cJSON *v = load_fixture(path);
    check(strcmp(str_field(v, "vector_kind"), "file_signature_v1") == 0,
          "file_signature_v1 vector_kind");

    const cJSON *domains = obj_field(v, "domains");
    const char *tee_domain = str_field(domains, "tee");
    const char *owner_domain = str_field(domains, "owner");
    check(strcmp(tee_domain, TEE_SIGNATURE_DOMAIN) == 0,
          "TEE_SIGNATURE_DOMAIN equals the vector's tee domain");

    size_t ct_len = 0;
    unsigned char *ct = b64_field(v, "ciphertext_b64", &ct_len);
    unsigned char hash[32];
    crypto_hash_sha256(hash, ct, ct_len);
    unsigned char want_hash[32];
    size_t want_len = 0;
    const char *want_hex = str_field(v, "ciphertext_sha256_hex");
    check(sodium_hex2bin(want_hash, sizeof(want_hash), want_hex, strlen(want_hex),
                         NULL, &want_len, NULL) == 0
              && want_len == 32 && memcmp(hash, want_hash, 32) == 0,
          "sha256 of the vector ciphertext equals ciphertext_sha256_hex");

    size_t tee_input_len = 0, owner_input_len = 0;
    unsigned char *tee_input = domain_input(tee_domain, hash, &tee_input_len);
    unsigned char *owner_input = domain_input(owner_domain, hash, &owner_input_len);

    OQS_SIG *mldsa = OQS_SIG_new(OQS_SIG_alg_ml_dsa_44);
    if (!mldsa) {
        fprintf(stderr, "liboqs has no ML-DSA-44\n");
        exit(1);
    }

    const cJSON *pub = obj_field(v, "signing_pub");
    const cJSON *tee = obj_field(v, "tee");
    size_t pub_ed_len = 0, pub_ml_len = 0, sig_ed_len = 0, sig_ml_len = 0;
    unsigned char *pub_ed = b64_field(pub, "ed25519_b64", &pub_ed_len);
    unsigned char *pub_ml = b64_field(pub, "mldsa44_b64", &pub_ml_len);
    unsigned char *sig_ed = b64_field(tee, "sig_ed25519_b64", &sig_ed_len);
    unsigned char *sig_ml = b64_field(tee, "sig_mldsa44_b64", &sig_ml_len);
    check(pub_ed_len == E2EE_ED25519_PK_SIZE && pub_ml_len == MLDSA44_PUBLIC_KEY_SIZE
              && sig_ed_len == E2EE_ED25519_SIG_SIZE && sig_ml_len == MLDSA44_SIGNATURE_SIZE,
          "file_signature_v1 field sizes");
    check(crypto_sign_verify_detached(sig_ed, tee_input, tee_input_len, pub_ed) == 0
              && mldsa_verifies(mldsa, tee_input, tee_input_len, sig_ml, sig_ml_len, pub_ml),
          "the Go-signed tee pair verifies over the vector's domain || sha256(ct)");

    unsigned char ed_pk[crypto_sign_PUBLICKEYBYTES];
    unsigned char ed_sk[crypto_sign_SECRETKEYBYTES];
    crypto_sign_keypair(ed_pk, ed_sk);
    unsigned char *ml_pk = malloc(mldsa->length_public_key);
    unsigned char *ml_sk = malloc(mldsa->length_secret_key);
    if (!ml_pk || !ml_sk || OQS_SIG_keypair(mldsa, ml_pk, ml_sk) != OQS_SUCCESS) {
        fprintf(stderr, "ML-DSA-44 keypair failed\n");
        exit(1);
    }

    unsigned char out_ed[E2EE_ED25519_SIG_SIZE];
    unsigned char out_ml[MLDSA44_SIGNATURE_SIZE];
    int rc = tee_sign_hash(hash, ed_sk, ml_sk, out_ed, out_ml);
    check(rc == 0, "tee_sign_hash signs the vector ciphertext hash");
    check(rc == 0 && crypto_sign_verify_detached(out_ed, tee_input, tee_input_len, ed_pk) == 0,
          "tee_sign_hash Ed25519 verifies over the vector's tee-domain input");
    check(rc == 0 && mldsa_verifies(mldsa, tee_input, tee_input_len, out_ml, sizeof(out_ml), ml_pk),
          "tee_sign_hash ML-DSA-44 verifies over the vector's tee-domain input");
    check(rc == 0 && crypto_sign_verify_detached(out_ed, owner_input, owner_input_len, ed_pk) != 0
              && !mldsa_verifies(mldsa, owner_input, owner_input_len, out_ml, sizeof(out_ml), ml_pk),
          "an enclave signature does not verify under the owner domain");

    unsigned char other_hash[32];
    memcpy(other_hash, hash, 32);
    other_hash[0] ^= 0x01;
    size_t other_len = 0;
    unsigned char *other_input = domain_input(tee_domain, other_hash, &other_len);
    check(rc == 0 && crypto_sign_verify_detached(out_ed, other_input, other_len, ed_pk) != 0
              && !mldsa_verifies(mldsa, other_input, other_len, out_ml, sizeof(out_ml), ml_pk),
          "an enclave signature does not verify over a different ciphertext hash");

    sodium_memzero(ed_sk, sizeof(ed_sk));
    OQS_MEM_secure_free(ml_sk, mldsa->length_secret_key);
    free(ml_pk);
    OQS_SIG_free(mldsa);
    free(other_input);
    free(tee_input);
    free(owner_input);
    free(pub_ed);
    free(pub_ml);
    free(sig_ed);
    free(sig_ml);
    free(ct);
    cJSON_Delete(v);
}

int main(int argc, char **argv)
{
    if (argc != 3) {
        fprintf(stderr, "usage: %s <chunked_file_v1.json> <file_signature_v1.json>\n", argv[0]);
        return 1;
    }
    if (sodium_init() < 0) {
        fprintf(stderr, "sodium_init failed\n");
        return 1;
    }

    cJSON *v = load_fixture(argv[1]);

    check(strcmp(str_field(v, "vector_kind"), "chunked_file_v1") == 0, "vector_kind");

    const cJSON *recipient = cJSON_GetObjectItemCaseSensitive(v, "recipient");
    const cJSON *meta = cJSON_GetObjectItemCaseSensitive(v, "metadata");
    const cJSON *ptspec = cJSON_GetObjectItemCaseSensitive(v, "plaintext");
    if (!recipient || !meta || !ptspec) {
        fprintf(stderr, "fixture missing recipient/metadata/plaintext\n");
        return 1;
    }

    size_t sk_len, seed_len, dk_len, sealed_len, ct_len, nonce_len;
    unsigned char *x25519_sk = b64_field(recipient, "x25519_sk_b64", &sk_len);
    unsigned char *kyber_seed = b64_field(recipient, "mlkem_seed_b64", &seed_len);
    unsigned char *data_key = b64_field(v, "data_key_b64", &dk_len);
    unsigned char *sealed = b64_field(v, "sealed_data_key_b64", &sealed_len);
    unsigned char *ciphertext = b64_field(v, "ciphertext_b64", &ct_len);
    unsigned char *nonce = b64_field(meta, "nonce_b64", &nonce_len);

    check(sk_len == 32 && seed_len == KYBER_SEED_SIZE && dk_len == E2EE_KEY_SIZE
              && sealed_len == HYBRID_SEALED_DATA_KEY_SIZE && nonce_len == E2EE_NONCE_SIZE,
          "field sizes");

    unsigned char unsealed[E2EE_KEY_SIZE];
    const char *reason = "sentinel";
    int rc = tee_unseal_hybrid_data_key(sealed, sealed_len, x25519_sk, kyber_seed,
                                        unsealed, &reason);
    check(rc == 0, "tee_unseal_hybrid_data_key succeeds");
    check(rc == 0 && sodium_memcmp(unsealed, data_key, E2EE_KEY_SIZE) == 0,
          "unsealed data key matches fixture");
    check(reason == NULL, "successful unseal clears the failure reason");

    int version = (int)num_field(meta, "version");
    int chunk_size = (int)num_field(meta, "chunk_size");
    int chunks = (int)num_field(meta, "chunks");
    int64_t plaintext_size = (int64_t)num_field(meta, "plaintext_size");
    const char *sha256_hex = str_field(meta, "plaintext_sha256");
    const char *nonce_b64 = str_field(meta, "nonce_b64");
    const char *mac_hex = str_field(meta, "metadata_mac");

    check(chunk_size == E2EE_CHUNK_SIZE, "fixture chunk_size matches E2EE_CHUNK_SIZE");

    char ct_path[512];
    write_temp(ciphertext, ct_len, ct_path, sizeof(ct_path));
    unsigned char *plaintext = NULL;
    size_t plaintext_len = 0;
    rc = tee_decrypt_file(ct_path, data_key, nonce, chunks, sha256_hex, version,
                          &plaintext, &plaintext_len);
    check(rc == 0, "tee_decrypt_file succeeds");

    int want_size = (int)num_field(ptspec, "size");
    check(rc == 0 && plaintext_len == (size_t)want_size, "plaintext length matches");
    if (rc == 0 && plaintext_len == (size_t)want_size) {
        int match = 1;
        for (size_t i = 0; i < plaintext_len; i++) {
            if (plaintext[i] != (unsigned char)(i % 251)) {
                match = 0;
                break;
            }
        }
        check(match, "plaintext matches byte pattern");
    }
    if (plaintext) {
        free(plaintext);
    }

    check(tee_verify_metadata_mac(data_key, version, nonce_b64, chunk_size, chunks,
                                  sha256_hex, plaintext_size, mac_hex) == 0,
          "tee_verify_metadata_mac accepts fixture MAC");

    {
        char derived[SHA256_HEX_BUF] = {0};
        unsigned char *derived_pt = NULL;
        size_t derived_pt_len = 0;
        int drc = tee_decrypt_file_cb(ct_path, data_key, nonce, chunks, NULL, version,
                                      NULL, NULL, derived, &derived_pt, &derived_pt_len);
        check(drc == 0, "decrypt succeeds without a declared digest");
        check(drc == 0 && strcmp(derived, sha256_hex) == 0,
              "the derived digest equals the fixture's plaintext_sha256");
        check(drc == 0 && tee_verify_metadata_mac(data_key, version, nonce_b64, chunk_size,
                                                  chunks, derived, plaintext_size, mac_hex) == 0,
              "the MAC verifies against the derived digest");
        if (derived_pt) {
            free(derived_pt);
        }

        char wrong[SHA256_HEX_BUF];
        memcpy(wrong, sha256_hex, SHA256_HEX_LEN + 1);
        wrong[0] = (char)(wrong[0] == 'a' ? 'b' : 'a');
        unsigned char *rejected_pt = NULL;
        size_t rejected_pt_len = 0;
        check(tee_decrypt_file_cb(ct_path, data_key, nonce, chunks, wrong, version,
                                  NULL, NULL, NULL, &rejected_pt, &rejected_pt_len) != 0,
              "a declared digest that disagrees with the bytes is still rejected");
        if (rejected_pt) {
            free(rejected_pt);
        }
    }

    {
        unsigned char sample[4096];
        for (size_t i = 0; i < sizeof(sample); i++) {
            sample[i] = (unsigned char)(i * 7 + 1);
        }
        char enc_path[512];
        temp_template(enc_path, sizeof(enc_path), "pigcloud-vector-enc");
        int efd = mkstemp(enc_path);
        check(efd >= 0, "mkstemp for encrypt output");
        if (efd >= 0) {
            close(efd);
        }
        unsigned char enc_nonce[E2EE_NONCE_SIZE];
        int enc_chunks = 0;
        char enc_sha[SHA256_HEX_BUF];
        tee_output_digest_t ct_digest = {0};
        int erc = tee_encrypt_file(sample, sizeof(sample), data_key, enc_path,
                                   enc_nonce, &enc_chunks, enc_sha, &ct_digest);
        check(erc == 0, "tee_encrypt_file succeeds");
        check(erc == 0 && ct_digest.produced,
              "tee_encrypt_file marks the digest as enclave-produced");

        unsigned char file_hash[32];
        int match = 0;
        if (erc == 0) {
            FILE *ef = fopen(enc_path, "rb");
            if (ef) {
                crypto_hash_sha256_state hst;
                crypto_hash_sha256_init(&hst);
                unsigned char rb[8192];
                size_t rn;
                while ((rn = fread(rb, 1, sizeof(rb), ef)) > 0) {
                    crypto_hash_sha256_update(&hst, rb, rn);
                }
                fclose(ef);
                crypto_hash_sha256_final(&hst, file_hash);
                match = (memcmp(ct_digest.bytes, file_hash, sizeof(file_hash)) == 0);
            }
        }
        check(erc == 0 && match,
              "ciphertext_digest_out equals sha256 of written ciphertext (TEE-CR-12)");
        unlink(enc_path);
    }

    ciphertext[ct_len / 2] ^= 0x01;
    unlink(ct_path);
    write_temp(ciphertext, ct_len, ct_path, sizeof(ct_path));
    unsigned char *tampered_pt = NULL;
    size_t tampered_len = 0;
    check(tee_decrypt_file(ct_path, data_key, nonce, chunks, sha256_hex, version,
                           &tampered_pt, &tampered_len) != 0,
          "tampered ciphertext rejected");
    ciphertext[ct_len / 2] ^= 0x01;

    check(tee_verify_metadata_mac(data_key, version, nonce_b64, chunk_size, chunks + 1,
                                  sha256_hex, plaintext_size, mac_hex) != 0,
          "tampered metadata rejected");

    sealed[0] ^= 0x01;
    reason = NULL;
    check(tee_unseal_hybrid_data_key(sealed, sealed_len, x25519_sk, kyber_seed,
                                     unsealed, &reason) != 0,
          "tampered sealed blob rejected");
    check(reason != NULL && strcmp(reason, TEE_UNSEAL_REASON_AEAD_AUTH) == 0,
          "tampered ephemeral PK names the AEAD failure");
    sealed[0] ^= 0x01;

    sealed[32 + 16] ^= 0x01;
    reason = NULL;
    check(tee_unseal_hybrid_data_key(sealed, sealed_len, x25519_sk, kyber_seed,
                                     unsealed, &reason) != 0
              && reason != NULL && strcmp(reason, TEE_UNSEAL_REASON_AEAD_AUTH) == 0,
          "tampered mlkem ciphertext names the AEAD failure");
    sealed[32 + 16] ^= 0x01;

    reason = NULL;
    check(tee_unseal_hybrid_data_key(sealed, HYBRID_HEADER_SIZE, x25519_sk, kyber_seed,
                                     unsealed, &reason) != 0
              && reason != NULL && strcmp(reason, TEE_UNSEAL_REASON_BLOB_TOO_SHORT) == 0,
          "truncated blob names the length guard, not the AEAD failure");

    {
        size_t rx_len = 0, rk_len = 0;
        unsigned char *recipient_x25519_pk = b64_field(recipient, "x25519_pk_b64", &rx_len);
        unsigned char *recipient_kyber_pk = b64_field(recipient, "mlkem_pk_b64", &rk_len);
        check(recipient_x25519_pk && rx_len == 32, "fixture carries the recipient X25519 PK");
        check(recipient_kyber_pk && rk_len == KYBER_PUBLIC_KEY_SIZE, "fixture carries the recipient ML-KEM PK");

        unsigned char digest[E2EE_KEY_SIZE];
        for (size_t i = 0; i < sizeof(digest); i++) {
            digest[i] = (unsigned char)(0xA0 ^ i);
        }
        unsigned char produced[HYBRID_HEADER_SIZE + E2EE_KEY_SIZE + E2EE_TAG_SIZE];
        size_t produced_len = 0;
        int seal_rc = -1;
        if (recipient_x25519_pk && recipient_kyber_pk && rx_len == 32) {
            seal_rc = tee_seal_hybrid(digest, sizeof(digest),
                                      recipient_x25519_pk, recipient_kyber_pk,
                                      produced, sizeof(produced), &produced_len);
        }
        check(seal_rc == 0, "tee_seal_hybrid produces a blob");
        check(seal_rc == 0 && produced_len == sizeof(produced),
              "the sealed blob is header + payload + tag, the layout every impl unseals");

        unsigned char reopened[E2EE_KEY_SIZE];
        const char *seal_reason = NULL;
        check(seal_rc == 0 && tee_unseal_hybrid_data_key(produced, produced_len,
                                                         x25519_sk, kyber_seed,
                                                         reopened, &seal_reason) == 0,
              "the fixture's recipient keys open what the enclave sealed");
        check(seal_rc == 0 && memcmp(reopened, digest, sizeof(digest)) == 0,
              "the payload survives the seal round trip");

        produced[0] ^= 0x01;
        seal_reason = NULL;
        check(seal_rc == 0 && tee_unseal_hybrid_data_key(produced, produced_len,
                                                         x25519_sk, kyber_seed,
                                                         reopened, &seal_reason) != 0,
              "a tampered enclave-sealed blob is rejected too");

        free(recipient_x25519_pk);
        free(recipient_kyber_pk);
    }

    unlink(ct_path);
    free(x25519_sk);
    free(kyber_seed);
    free(data_key);
    free(sealed);
    free(ciphertext);
    free(nonce);
    cJSON_Delete(v);

    check_file_signature_vector(argv[2]);

    if (g_failures > 0) {
        fprintf(stderr, "%d conformance check(s) failed\n", g_failures);
        return 1;
    }
    printf("all TEE conformance checks passed\n");
    return 0;
}
