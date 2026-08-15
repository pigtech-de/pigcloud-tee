#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

#include "../sanitizers/image.c"

static int g_fail = 0;

static void check(const char *name, int ok)
{
    printf("%-46s %s\n", name, ok ? "ok" : "FAIL");
    if (!ok) g_fail = 1;
}

static void put_be32(unsigned char *p, uint32_t v)
{
    p[0] = (unsigned char)(v >> 24); p[1] = (unsigned char)(v >> 16);
    p[2] = (unsigned char)(v >> 8);  p[3] = (unsigned char)v;
}

static void put_le32(unsigned char *p, uint32_t v)
{
    p[0] = (unsigned char)v;         p[1] = (unsigned char)(v >> 8);
    p[2] = (unsigned char)(v >> 16); p[3] = (unsigned char)(v >> 24);
}

static size_t png_chunk(unsigned char *buf, size_t at, const char *type,
                        const unsigned char *payload, uint32_t plen)
{
    put_be32(buf + at, plen);
    memcpy(buf + at + 4, type, 4);
    if (plen && payload) memcpy(buf + at + 8, payload, plen);
    put_be32(buf + at + 8 + plen, 0);
    return at + 12 + plen;
}

static size_t build_png(unsigned char *buf, int animated, const char *extra_type,
                        const unsigned char *extra_payload, uint32_t extra_len,
                        size_t tail_junk)
{
    static const unsigned char sig[8] = {0x89,'P','N','G',0x0D,0x0A,0x1A,0x0A};
    unsigned char ihdr[13] = {0};
    unsigned char actl[8] = {0, 0, 0, 4, 0, 0, 0, 0};
    memcpy(buf, sig, 8);
    size_t at = png_chunk(buf, 8, "IHDR", ihdr, sizeof ihdr);
    if (extra_type) at = png_chunk(buf, at, extra_type, extra_payload, extra_len);
    if (animated)   at = png_chunk(buf, at, "acTL", actl, sizeof actl);
    at = png_chunk(buf, at, "IDAT", (const unsigned char *)"x", 1);
    at = png_chunk(buf, at, "IEND", NULL, 0);
    for (size_t k = 0; k < tail_junk; k++) buf[at + k] = 0x41;
    return at + tail_junk;
}

static size_t webp_chunk(unsigned char *buf, size_t at, const char *fourcc,
                         const unsigned char *payload, uint32_t plen)
{
    memcpy(buf + at, fourcc, 4);
    put_le32(buf + at + 4, plen);
    if (plen && payload) memcpy(buf + at + 8, payload, plen);
    size_t end = at + 8 + plen;
    if (plen & 1u) buf[end++] = 0;
    return end;
}

static size_t build_webp(unsigned char *buf, int animated, const char *extra_type,
                         const unsigned char *extra_payload, uint32_t extra_len,
                         int riff_slack, size_t tail_junk)
{
    unsigned char vp8x[10] = {0};
    unsigned char anim[6] = {0};
    memcpy(buf, "RIFF", 4);
    memcpy(buf + 8, "WEBP", 4);
    unsigned char anmf[16] = {0};
    size_t at = webp_chunk(buf, 12, "VP8X", vp8x, sizeof vp8x);
    if (extra_type) at = webp_chunk(buf, at, extra_type, extra_payload, extra_len);
    if (animated) {
        at = webp_chunk(buf, at, "ANIM", anim, sizeof anim);
        at = webp_chunk(buf, at, "ANMF", anmf, sizeof anmf);
        at = webp_chunk(buf, at, "ANMF", anmf, sizeof anmf);
    }
    at = webp_chunk(buf, at, "VP8 ", (const unsigned char *)"xy", 2);
    for (size_t k = 0; k < tail_junk; k++) buf[at + k] = 0x41;
    size_t total = at + tail_junk;
    put_le32(buf + 4, (uint32_t)((long)total - 8 + riff_slack));
    return total;
}

static void png_cases(void)
{
    unsigned char buf[4096];
    int actl, iend;

    size_t n = build_png(buf, 1, NULL, NULL, 0, 0);
    png_walk_chunks(buf, n, &actl, &iend);
    check("apng: acTL before IDAT detected", actl == 1);
    check("apng: chain closes at IEND", iend == 1);

    n = build_png(buf, 0, NULL, NULL, 0, 0);
    png_walk_chunks(buf, n, &actl, &iend);
    check("static png: no acTL", actl == 0);

    n = build_png(buf, 0, "tEXt", (const unsigned char *)"acTL____", 8, 0);
    png_walk_chunks(buf, n, &actl, &iend);
    check("spoof: acTL inside tEXt is not animation", actl == 0);

    n = build_png(buf, 1, NULL, NULL, 0, 32);
    png_walk_chunks(buf, n, &actl, &iend);
    check("apng + appended payload: acTL seen", actl == 1);
    check("apng + appended payload: chain not closed", iend == 0);

    unsigned char late[4096];
    static const unsigned char sig[8] = {0x89,'P','N','G',0x0D,0x0A,0x1A,0x0A};
    unsigned char ihdr[13] = {0}, actl_payload[8] = {0};
    memcpy(late, sig, 8);
    size_t at = png_chunk(late, 8, "IHDR", ihdr, sizeof ihdr);
    at = png_chunk(late, at, "IDAT", (const unsigned char *)"x", 1);
    at = png_chunk(late, at, "acTL", actl_payload, sizeof actl_payload);
    at = png_chunk(late, at, "IEND", NULL, 0);
    png_walk_chunks(late, at, &actl, &iend);
    check("acTL after IDAT is not animation", actl == 0);

    png_walk_chunks(buf, 4, &actl, &iend);
    check("truncated png: no crash, not animated", actl == 0 && iend == 0);

    unsigned char one[4096];
    static const unsigned char sig1[8] = {0x89,'P','N','G',0x0D,0x0A,0x1A,0x0A};
    unsigned char ihdr1[13] = {0};
    unsigned char actl_one[8] = {0, 0, 0, 1, 0, 0, 0, 0};
    memcpy(one, sig1, 8);
    size_t p = png_chunk(one, 8, "IHDR", ihdr1, sizeof ihdr1);
    p = png_chunk(one, p, "acTL", actl_one, sizeof actl_one);
    p = png_chunk(one, p, "IDAT", (const unsigned char *)"x", 1);
    p = png_chunk(one, p, "IEND", NULL, 0);
    png_walk_chunks(one, p, &actl, &iend);
    check("acTL with num_frames=1 is not animation", actl == 0);
}

static void webp_cases(void)
{
    unsigned char buf[4096];
    int anim, exact;

    size_t n = build_webp(buf, 1, NULL, NULL, 0, 0, 0);
    webp_walk_chunks(buf, n, &anim, &exact);
    check("animated webp: ANIM chunk detected", anim == 1);
    check("animated webp: riff size exact", exact == 1);

    n = build_webp(buf, 0, NULL, NULL, 0, 0, 0);
    webp_walk_chunks(buf, n, &anim, &exact);
    check("static webp: no ANIM", anim == 0);

    n = build_webp(buf, 0, "EXIF", (const unsigned char *)"ANIM__", 6, 0, 0);
    webp_walk_chunks(buf, n, &anim, &exact);
    check("spoof: ANIM inside EXIF is not animation", anim == 0);

    n = build_webp(buf, 1, NULL, NULL, 0, 0, 24);
    webp_walk_chunks(buf, n, &anim, &exact);
    check("animated webp + appended payload rejected", anim == 1 && exact == 0);

    n = build_webp(buf, 1, NULL, NULL, 0, -16, 0);
    webp_walk_chunks(buf, n, &anim, &exact);
    check("webp with short riff size not exact", exact == 0);

    webp_walk_chunks(buf, 6, &anim, &exact);
    check("truncated webp: no crash, not animated", anim == 0 && exact == 0);

    unsigned char notriff[64];
    memset(notriff, 0x41, sizeof notriff);
    webp_walk_chunks(notriff, sizeof notriff, &anim, &exact);
    check("non-riff buffer is not animated", anim == 0 && exact == 0);

    unsigned char hdr_only[4096];
    unsigned char vp8x0[10] = {0}, anim0[6] = {0};
    memcpy(hdr_only, "RIFF", 4);
    memcpy(hdr_only + 8, "WEBP", 4);
    size_t q = webp_chunk(hdr_only, 12, "VP8X", vp8x0, sizeof vp8x0);
    q = webp_chunk(hdr_only, q, "ANIM", anim0, sizeof anim0);
    q = webp_chunk(hdr_only, q, "VP8 ", (const unsigned char *)"xy", 2);
    put_le32(hdr_only + 4, (uint32_t)(q - 8));
    webp_walk_chunks(hdr_only, q, &anim, &exact);
    check("ANIM without any ANMF frame is not animation", anim == 0);
}

static void sanitize_cases(void)
{
    unsigned char buf[4096];
    unsigned char *out = NULL;
    size_t out_len = 0;
    char reason[256];

    size_t n = build_png(buf, 1, NULL, NULL, 0, 0);
    int rc = sanitize_raster_image(buf, n, "image/png", "png", &out, &out_len,
                                   reason, sizeof reason);
    check("apng verdict is CLEAN passthrough",
          rc == SANITIZE_CLEAN && strcmp(reason, "png_animated_passthrough") == 0);
    free(out); out = NULL;

    n = build_png(buf, 1, NULL, NULL, 0, 32);
    rc = sanitize_raster_image(buf, n, "image/png", "png", &out, &out_len,
                               reason, sizeof reason);
    check("apng with appended payload REJECTED",
          rc == SANITIZE_REJECTED && strcmp(reason, "png_trailing_data") == 0);
    free(out); out = NULL;

    n = build_webp(buf, 1, NULL, NULL, 0, 0, 0);
    rc = sanitize_raster_image(buf, n, "image/webp", "webp", &out, &out_len,
                               reason, sizeof reason);
    check("animated webp verdict is CLEAN passthrough",
          rc == SANITIZE_CLEAN && strcmp(reason, "webp_animated_passthrough") == 0);
    free(out); out = NULL;

    n = build_webp(buf, 1, NULL, NULL, 0, 0, 24);
    rc = sanitize_raster_image(buf, n, "image/webp", "webp", &out, &out_len,
                               reason, sizeof reason);
    check("animated webp with appended payload REJECTED",
          rc == SANITIZE_REJECTED && strcmp(reason, "webp_trailing_data") == 0);
    free(out); out = NULL;

    gdImagePtr im = gdImageCreateTrueColor(8, 8);
    int png_size = 0;
    void *png_bytes = gdImagePngPtr(im, &png_size);
    rc = sanitize_raster_image(png_bytes, (size_t)png_size, "image/png", "png",
                               &out, &out_len, reason, sizeof reason);
    check("static png is re-encoded, not passed through",
          rc == SANITIZE_MODIFIED && out_len > 0);
    gdFree(png_bytes); free(out); out = NULL;

    int webp_size = 0;
    void *webp_bytes = gdImageWebpPtr(im, &webp_size);
    if (webp_bytes && webp_size > 0) {
        rc = sanitize_raster_image(webp_bytes, (size_t)webp_size, "image/webp",
                                   "webp", &out, &out_len, reason, sizeof reason);
        check("static webp is re-encoded, not passed through",
              rc == SANITIZE_MODIFIED && out_len > 0);
        gdFree(webp_bytes); free(out); out = NULL;
    }
    gdImageDestroy(im);
}

int main(void)
{
    printf("== png ==\n");        png_cases();
    printf("\n== webp ==\n");     webp_cases();
    printf("\n== sanitize ==\n"); sanitize_cases();
    printf("\n%s\n", g_fail ? "FAILURES" : "all passed");
    return g_fail;
}
