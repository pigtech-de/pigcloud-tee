#define _POSIX_C_SOURCE 200809L

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <fcntl.h>
#include <unistd.h>
#include <errno.h>
#include <sys/stat.h>
#include <time.h>
#include <sodium.h>
#include <oqs/oqs.h>

#include "attestation.h"

#ifndef KEYPAIR_DIR
#define KEYPAIR_DIR        "/var/lib/pigcloud-tee-signer"
#endif
#define KEYPAIR_FILE       KEYPAIR_DIR "/keypair.bin"
#define KEYPAIR_TMP_FILE   KEYPAIR_DIR "/keypair.bin.tmp"
#define KEYPAIR_MAGIC_PLAINTEXT "PCK3"
#define KEYPAIR_MAGIC_SEALED    "PCK4"
#define KEYPAIR_MAGIC_LEN  4
#define KEYPAIR_FILE_SIZE  (KEYPAIR_MAGIC_LEN \
                            + crypto_box_PUBLICKEYBYTES \
                            + crypto_box_SECRETKEYBYTES \
                            + KYBER_PUBLIC_KEY_SIZE \
                            + KYBER_SEED_SIZE \
                            + crypto_sign_PUBLICKEYBYTES \
                            + crypto_sign_SECRETKEYBYTES \
                            + MLDSA44_PUBLIC_KEY_SIZE \
                            + MLDSA44_SECRET_KEY_SIZE)

static unsigned char s_pk[crypto_box_PUBLICKEYBYTES];
static unsigned char s_sk[crypto_box_SECRETKEYBYTES];
static unsigned char s_kyber_pk[KYBER_PUBLIC_KEY_SIZE];
static unsigned char s_kyber_seed[KYBER_SEED_SIZE];
static unsigned char s_ed25519_pk[crypto_sign_PUBLICKEYBYTES];
static unsigned char s_ed25519_sk[crypto_sign_SECRETKEYBYTES];
static unsigned char s_mldsa_pk[MLDSA44_PUBLIC_KEY_SIZE];
static unsigned char s_mldsa_sk[MLDSA44_SECRET_KEY_SIZE];
static int s_initialized = 0;

static uint64_t s_epoch = 0;

static unsigned char s_keypair_kek[crypto_aead_xchacha20poly1305_ietf_KEYBYTES];
static int s_have_kek = 0;

static int save_keypair_to_disk(void);

static void load_keypair_kek(void)
{
    const char *hex = getenv("TEE_KEYPAIR_KEK");
    if (!hex) {
        return;
    }
    size_t hexlen = strlen(hex);
    if (hexlen != crypto_aead_xchacha20poly1305_ietf_KEYBYTES * 2 ||
        sodium_hex2bin(s_keypair_kek, sizeof(s_keypair_kek),
                       hex, hexlen, NULL, NULL, NULL) != 0) {
        fprintf(stderr, "WARNING: TEE_KEYPAIR_KEK malformed — keypair stays plaintext at rest\n");
        return;
    }
    sodium_mlock(s_keypair_kek, sizeof(s_keypair_kek));
    s_have_kek = 1;
}

static void parse_keypair_body(const unsigned char *body)
{
    size_t off = 0;
    memcpy(s_pk, body + off, crypto_box_PUBLICKEYBYTES); off += crypto_box_PUBLICKEYBYTES;
    memcpy(s_sk, body + off, crypto_box_SECRETKEYBYTES); off += crypto_box_SECRETKEYBYTES;
    memcpy(s_kyber_pk, body + off, KYBER_PUBLIC_KEY_SIZE); off += KYBER_PUBLIC_KEY_SIZE;
    memcpy(s_kyber_seed, body + off, KYBER_SEED_SIZE); off += KYBER_SEED_SIZE;
    memcpy(s_ed25519_pk, body + off, crypto_sign_PUBLICKEYBYTES); off += crypto_sign_PUBLICKEYBYTES;
    memcpy(s_ed25519_sk, body + off, crypto_sign_SECRETKEYBYTES); off += crypto_sign_SECRETKEYBYTES;
    memcpy(s_mldsa_pk, body + off, MLDSA44_PUBLIC_KEY_SIZE); off += MLDSA44_PUBLIC_KEY_SIZE;
    memcpy(s_mldsa_sk, body + off, MLDSA44_SECRET_KEY_SIZE);
}

enum {
    KEYPAIR_BODY_SIZE = KEYPAIR_FILE_SIZE - KEYPAIR_MAGIC_LEN,
    KEYPAIR_NPUB      = crypto_aead_xchacha20poly1305_ietf_NPUBBYTES,
    KEYPAIR_ABYTES    = crypto_aead_xchacha20poly1305_ietf_ABYTES,
    KEYPAIR_SEALED_SIZE = KEYPAIR_MAGIC_LEN + KEYPAIR_NPUB + KEYPAIR_BODY_SIZE + KEYPAIR_ABYTES,
};

static int load_keypair_from_disk(void)
{
    int fd = open(KEYPAIR_FILE, O_RDONLY | O_NOFOLLOW | O_CLOEXEC);
    if (fd < 0) {
        return -1;
    }

    unsigned char filebuf[KEYPAIR_SEALED_SIZE];
    ssize_t total = 0;
    while ((size_t)total < sizeof(filebuf)) {
        ssize_t n = read(fd, filebuf + total, sizeof(filebuf) - (size_t)total);
        if (n < 0) {
            if (errno == EINTR) continue;
            close(fd);
            sodium_memzero(filebuf, sizeof(filebuf));
            return -1;
        }
        if (n == 0) break;
        total += n;
    }
    close(fd);

    unsigned char body[KEYPAIR_BODY_SIZE];
    int legacy = 0;

    if (total == (ssize_t)KEYPAIR_FILE_SIZE
        && memcmp(filebuf, KEYPAIR_MAGIC_PLAINTEXT, KEYPAIR_MAGIC_LEN) == 0) {
        memcpy(body, filebuf + KEYPAIR_MAGIC_LEN, KEYPAIR_BODY_SIZE);
        legacy = 1;
    } else if (total == (ssize_t)KEYPAIR_SEALED_SIZE
        && memcmp(filebuf, KEYPAIR_MAGIC_SEALED, KEYPAIR_MAGIC_LEN) == 0) {
        if (!s_have_kek) {
            sodium_memzero(filebuf, sizeof(filebuf));
            return -1;
        }
        const unsigned char *nonce = filebuf + KEYPAIR_MAGIC_LEN;
        const unsigned char *ct = filebuf + KEYPAIR_MAGIC_LEN + KEYPAIR_NPUB;
        unsigned long long mlen = 0;
        if (crypto_aead_xchacha20poly1305_ietf_decrypt(
                body, &mlen, NULL,
                ct, KEYPAIR_BODY_SIZE + KEYPAIR_ABYTES,
                NULL, 0, nonce, s_keypair_kek) != 0
            || mlen != KEYPAIR_BODY_SIZE) {
            sodium_memzero(filebuf, sizeof(filebuf));
            sodium_memzero(body, sizeof(body));
            return -1;
        }
    } else {
        sodium_memzero(filebuf, sizeof(filebuf));
        return -1;
    }
    sodium_memzero(filebuf, sizeof(filebuf));

    parse_keypair_body(body);
    sodium_memzero(body, sizeof(body));

    if (legacy && s_have_kek) {
        if (save_keypair_to_disk() == 0) {
            fprintf(stderr, "INFO: migrated plaintext keypair to sealed at-rest format\n");
        }
    }
    return 0;
}

static int save_keypair_to_disk(void)
{
    if (mkdir(KEYPAIR_DIR, 0700) != 0 && errno != EEXIST) {
        return -1;
    }
    unlink(KEYPAIR_TMP_FILE);

    int fd = open(KEYPAIR_TMP_FILE, O_WRONLY | O_CREAT | O_TRUNC | O_NOFOLLOW | O_CLOEXEC, 0600);
    if (fd < 0) {
        return -1;
    }

    unsigned char body[KEYPAIR_BODY_SIZE];
    size_t off = 0;
    memcpy(body + off, s_pk, crypto_box_PUBLICKEYBYTES); off += crypto_box_PUBLICKEYBYTES;
    memcpy(body + off, s_sk, crypto_box_SECRETKEYBYTES); off += crypto_box_SECRETKEYBYTES;
    memcpy(body + off, s_kyber_pk, KYBER_PUBLIC_KEY_SIZE); off += KYBER_PUBLIC_KEY_SIZE;
    memcpy(body + off, s_kyber_seed, KYBER_SEED_SIZE); off += KYBER_SEED_SIZE;
    memcpy(body + off, s_ed25519_pk, crypto_sign_PUBLICKEYBYTES); off += crypto_sign_PUBLICKEYBYTES;
    memcpy(body + off, s_ed25519_sk, crypto_sign_SECRETKEYBYTES); off += crypto_sign_SECRETKEYBYTES;
    memcpy(body + off, s_mldsa_pk, MLDSA44_PUBLIC_KEY_SIZE); off += MLDSA44_PUBLIC_KEY_SIZE;
    memcpy(body + off, s_mldsa_sk, MLDSA44_SECRET_KEY_SIZE);

    unsigned char filebuf[KEYPAIR_SEALED_SIZE];
    size_t flen;
    if (s_have_kek) {
        memcpy(filebuf, KEYPAIR_MAGIC_SEALED, KEYPAIR_MAGIC_LEN);
        unsigned char *nonce = filebuf + KEYPAIR_MAGIC_LEN;
        randombytes_buf(nonce, KEYPAIR_NPUB);
        unsigned long long clen = 0;
        crypto_aead_xchacha20poly1305_ietf_encrypt(
            filebuf + KEYPAIR_MAGIC_LEN + KEYPAIR_NPUB, &clen,
            body, KEYPAIR_BODY_SIZE, NULL, 0, NULL, nonce, s_keypair_kek);
        flen = KEYPAIR_MAGIC_LEN + KEYPAIR_NPUB + (size_t)clen;
    } else {
        memcpy(filebuf, KEYPAIR_MAGIC_PLAINTEXT, KEYPAIR_MAGIC_LEN);
        memcpy(filebuf + KEYPAIR_MAGIC_LEN, body, KEYPAIR_BODY_SIZE);
        flen = KEYPAIR_MAGIC_LEN + KEYPAIR_BODY_SIZE;
    }
    sodium_memzero(body, sizeof(body));

    ssize_t written = 0;
    while ((size_t)written < flen) {
        ssize_t n = write(fd, filebuf + written, flen - (size_t)written);
        if (n < 0) {
            if (errno == EINTR) continue;
            sodium_memzero(filebuf, sizeof(filebuf));
            close(fd);
            unlink(KEYPAIR_TMP_FILE);
            return -1;
        }
        written += n;
    }
    sodium_memzero(filebuf, sizeof(filebuf));

    if (fsync(fd) != 0) {
        close(fd);
        unlink(KEYPAIR_TMP_FILE);
        return -1;
    }
    close(fd);

    if (rename(KEYPAIR_TMP_FILE, KEYPAIR_FILE) != 0) {
        unlink(KEYPAIR_TMP_FILE);
        return -1;
    }

    int dfd = open(KEYPAIR_DIR, O_RDONLY | O_CLOEXEC);
    if (dfd >= 0) {
        fsync(dfd);
        close(dfd);
    }
    return 0;
}

static int generate_hybrid_keypair(void)
{
    if (crypto_box_keypair(s_pk, s_sk) != 0) {
        return -1;
    }

    OQS_KEM *kem = OQS_KEM_new(OQS_KEM_alg_ml_kem_768);
    if (!kem) {
        return -1;
    }
    if (kem->length_public_key != KYBER_PUBLIC_KEY_SIZE) {
        OQS_KEM_free(kem);
        return -1;
    }

    randombytes_buf(s_kyber_seed, KYBER_SEED_SIZE);

    unsigned char tmp_sk[KYBER_SECRET_KEY_SIZE];
    if (OQS_KEM_keypair_derand(kem, s_kyber_pk, tmp_sk, s_kyber_seed) != OQS_SUCCESS) {
        OQS_KEM_free(kem);
        sodium_memzero(tmp_sk, sizeof(tmp_sk));
        sodium_memzero(s_kyber_seed, sizeof(s_kyber_seed));
        return -1;
    }
    sodium_memzero(tmp_sk, sizeof(tmp_sk));
    OQS_KEM_free(kem);
    return 0;
}

static int generate_signing_keypair(void)
{
    if (crypto_sign_keypair(s_ed25519_pk, s_ed25519_sk) != 0) {
        return -1;
    }

    OQS_SIG *sig = OQS_SIG_new(OQS_SIG_alg_ml_dsa_44);
    if (!sig) {
        sodium_memzero(s_ed25519_sk, sizeof(s_ed25519_sk));
        return -1;
    }
    if (sig->length_public_key != MLDSA44_PUBLIC_KEY_SIZE
        || sig->length_secret_key != MLDSA44_SECRET_KEY_SIZE
        || sig->length_signature != MLDSA44_SIGNATURE_SIZE) {
        OQS_SIG_free(sig);
        sodium_memzero(s_ed25519_sk, sizeof(s_ed25519_sk));
        return -1;
    }
    if (OQS_SIG_keypair(sig, s_mldsa_pk, s_mldsa_sk) != OQS_SUCCESS) {
        OQS_SIG_free(sig);
        sodium_memzero(s_ed25519_sk, sizeof(s_ed25519_sk));
        sodium_memzero(s_mldsa_sk, sizeof(s_mldsa_sk));
        return -1;
    }
    OQS_SIG_free(sig);
    return 0;
}

int attestation_init(void)
{
    if (s_initialized) {
        return 0;
    }

    if (sodium_init() < 0) {
        return -1;
    }

    OQS_init();

    load_keypair_kek();

    if (load_keypair_from_disk() == 0) {
        fprintf(stderr, "INFO: loaded persisted hybrid enclave keypair from %s\n",
                KEYPAIR_FILE);
    } else {
        if (access(KEYPAIR_FILE, F_OK) == 0) {
            fprintf(stderr, "FATAL: keypair exists at %s but could not be loaded; "
                            "refusing to generate a new one and rotate the enclave PK\n",
                    KEYPAIR_FILE);
            return -1;
        }
        if (generate_hybrid_keypair() != 0) {
            return -1;
        }
        if (generate_signing_keypair() != 0) {
            return -1;
        }
        if (save_keypair_to_disk() == 0) {
            fprintf(stderr, "INFO: persisted new hybrid enclave keypair set to %s\n",
                    KEYPAIR_FILE);
        } else {
            fprintf(stderr,
                    "WARNING: keypair persistence failed (errno=%d): "
                    "PKs will rotate on next restart\n",
                    errno);
        }
    }

    sodium_mlock(s_sk, sizeof(s_sk));
    sodium_mlock(s_kyber_seed, sizeof(s_kyber_seed));
    sodium_mlock(s_ed25519_sk, sizeof(s_ed25519_sk));
    sodium_mlock(s_mldsa_sk, sizeof(s_mldsa_sk));

    s_epoch = (uint64_t)time(NULL);

    s_initialized = 1;
    return 0;
}

uint64_t attestation_get_epoch(void)
{
    return s_epoch;
}

const unsigned char *attestation_get_public_key(void)
{
    return s_pk;
}

const unsigned char *attestation_get_secret_key(void)
{
    return s_sk;
}

const unsigned char *attestation_get_kyber_public_key(void)
{
    return s_kyber_pk;
}

const unsigned char *attestation_get_kyber_seed(void)
{
    return s_kyber_seed;
}

const unsigned char *attestation_get_ed25519_public_key(void)
{
    return s_ed25519_pk;
}

const unsigned char *attestation_get_ed25519_secret_key(void)
{
    return s_ed25519_sk;
}

const unsigned char *attestation_get_mldsa_public_key(void)
{
    return s_mldsa_pk;
}

const unsigned char *attestation_get_mldsa_secret_key(void)
{
    return s_mldsa_sk;
}

int attestation_get_data(attestation_data_t *out)
{
    if (!s_initialized) {
        return -1;
    }

    memset(out, 0, sizeof(*out));
    memcpy(out->enclave_pk, s_pk, sizeof(s_pk));
    memcpy(out->enclave_pk_kyber, s_kyber_pk, KYBER_PUBLIC_KEY_SIZE);
    memcpy(out->enclave_pk_ed25519, s_ed25519_pk, sizeof(s_ed25519_pk));
    memcpy(out->enclave_pk_mldsa, s_mldsa_pk, MLDSA44_PUBLIC_KEY_SIZE);

    sodium_bin2base64(out->enclave_pk_b64, sizeof(out->enclave_pk_b64),
                      s_pk, sizeof(s_pk), sodium_base64_VARIANT_ORIGINAL);
    sodium_bin2base64(out->enclave_pk_ed25519_b64, sizeof(out->enclave_pk_ed25519_b64),
                      s_ed25519_pk, sizeof(s_ed25519_pk),
                      sodium_base64_VARIANT_ORIGINAL);

    size_t kyber_b64_max = sodium_base64_ENCODED_LEN(KYBER_PUBLIC_KEY_SIZE,
                              sodium_base64_VARIANT_ORIGINAL);
    out->enclave_pk_kyber_b64 = malloc(kyber_b64_max);
    if (!out->enclave_pk_kyber_b64) {
        return -1;
    }
    sodium_bin2base64(out->enclave_pk_kyber_b64, kyber_b64_max,
                      s_kyber_pk, KYBER_PUBLIC_KEY_SIZE,
                      sodium_base64_VARIANT_ORIGINAL);

    size_t mldsa_b64_max = sodium_base64_ENCODED_LEN(MLDSA44_PUBLIC_KEY_SIZE,
                              sodium_base64_VARIANT_ORIGINAL);
    out->enclave_pk_mldsa_b64 = malloc(mldsa_b64_max);
    if (!out->enclave_pk_mldsa_b64) {
        return -1;
    }
    sodium_bin2base64(out->enclave_pk_mldsa_b64, mldsa_b64_max,
                      s_mldsa_pk, MLDSA44_PUBLIC_KEY_SIZE,
                      sodium_base64_VARIANT_ORIGINAL);

    return 0;
}

void attestation_data_free(attestation_data_t *data)
{
    if (!data) {
        return;
    }
    free(data->enclave_pk_kyber_b64);
    free(data->enclave_pk_mldsa_b64);
    data->enclave_pk_kyber_b64 = NULL;
    data->enclave_pk_mldsa_b64 = NULL;
}

void attestation_destroy(void)
{
    sodium_munlock(s_sk, sizeof(s_sk));
    sodium_memzero(s_pk, sizeof(s_pk));
    sodium_memzero(s_kyber_pk, sizeof(s_kyber_pk));
    sodium_munlock(s_kyber_seed, sizeof(s_kyber_seed));
    sodium_memzero(s_ed25519_pk, sizeof(s_ed25519_pk));
    sodium_munlock(s_ed25519_sk, sizeof(s_ed25519_sk));
    sodium_memzero(s_mldsa_pk, sizeof(s_mldsa_pk));
    sodium_munlock(s_mldsa_sk, sizeof(s_mldsa_sk));
    if (s_have_kek) {
        sodium_munlock(s_keypair_kek, sizeof(s_keypair_kek));
        s_have_kek = 0;
    }
    s_initialized = 0;
}
