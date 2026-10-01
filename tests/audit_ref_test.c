#define _GNU_SOURCE

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "../audit.c"

static int failures = 0;

static void check(int condition, const char *what)
{
    if (condition) {
        printf("  ok   %s\n", what);
        return;
    }
    printf("  FAIL %s\n", what);
    failures++;
}

static const char *DIGEST_A =
    "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";
static const char *DIGEST_B =
    "ea69963306b2ed5b8506b657b5f806d9b86771b636ebc76fa78413014b3e04d1";

int main(void)
{
    if (sodium_init() < 0) {
        fprintf(stderr, "sodium_init failed\n");
        return 1;
    }
    setenv("TEE_AUDIT_HMAC_KEY", "harness-key-not-a-real-secret", 1);
    if (audit_init() != 0) {
        fprintf(stderr, "audit_init failed\n");
        return 1;
    }

    printf("keyed content reference\n");
    char ref_a[SHA256_HEX_BUF];
    char ref_a_again[SHA256_HEX_BUF];
    char ref_b[SHA256_HEX_BUF];
    char ref_empty[SHA256_HEX_BUF];
    audit_content_ref(DIGEST_A, ref_a);
    audit_content_ref(DIGEST_A, ref_a_again);
    audit_content_ref(DIGEST_B, ref_b);
    audit_content_ref("", ref_empty);

    check(strcmp(ref_a, DIGEST_A) != 0,
          "the reference is not the digest a known-file set would match");
    check(strlen(ref_a) == 64, "the reference is a 64-char hex string");
    check(strcmp(ref_a, ref_a_again) == 0,
          "the same digest under the same key gives the same reference");
    check(strcmp(ref_a, ref_b) != 0, "distinct digests give distinct references");
    check(ref_empty[0] == '\0', "a scan with no digest carries no reference");

    printf("canonical record\n");
    audit_entry_t entry = {
        .user_id = 1001,
        .plaintext_sha256 = DIGEST_A,
        .verdict = "sanitized",
        .reason = "",
        .duration_ms = 42,
    };
    char sig_hex[SHA256_HEX_BUF];
    char *canonical = NULL;
    int rc = build_canonical_and_sign(&entry, "2026-06-29T12:34:56+00:00",
                                      "2026-06-29", g_audit_prev, 7,
                                      sig_hex, &canonical);
    check(rc == 0 && canonical != NULL, "the record builds");
    if (canonical) {
        check(strstr(canonical, "\"plaintext_sha256\"") == NULL,
              "the written record carries no bare plaintext digest");
        check(strstr(canonical, "\"plaintext_ref\"") != NULL,
              "the written record carries the keyed reference");
        check(strstr(canonical, DIGEST_A) == NULL,
              "the digest appears nowhere in the record bytes");
        check(strstr(canonical, ref_a) != NULL,
              "the reference in the record is the one the key produces");
        check(strlen(sig_hex) == 64, "the chain signature still covers the record");
        free(canonical);
    }

    audit_shutdown();
    printf(failures ? "\nFAILED (%d)\n" : "\nAll audit reference checks passed.\n", failures);
    return failures ? 1 : 0;
}
