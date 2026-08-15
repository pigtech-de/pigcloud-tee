#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <stdint.h>
#include <gd.h>
#include "sanitizers.h"
#include "../scanner_whitelist.h"

typedef enum {
    IMG_JPEG,
    IMG_PNG,
    IMG_GIF,
    IMG_WEBP,
    IMG_BMP,
    IMG_UNSUPPORTED
} image_type_t;

static int probe_image_dimensions(const unsigned char *data, size_t len,
                                  image_type_t type,
                                  int64_t *w_out, int64_t *h_out)
{
    if (type == IMG_PNG) {
        if (len < 24) return -1;
        static const unsigned char sig[] = {0x89,'P','N','G',0x0D,0x0A,0x1A,0x0A};
        if (memcmp(data, sig, 8) != 0) return -1;
        if (memcmp(data + 12, "IHDR", 4) != 0) return -1;
        uint32_t w = ((uint32_t)data[16] << 24) | ((uint32_t)data[17] << 16) |
                     ((uint32_t)data[18] << 8)  |  (uint32_t)data[19];
        uint32_t h = ((uint32_t)data[20] << 24) | ((uint32_t)data[21] << 16) |
                     ((uint32_t)data[22] << 8)  |  (uint32_t)data[23];
        *w_out = (int64_t)w;
        *h_out = (int64_t)h;
        return 0;
    }

    if (type == IMG_GIF) {
        if (len < 10) return -1;
        if (memcmp(data, "GIF87a", 6) != 0 && memcmp(data, "GIF89a", 6) != 0) return -1;
        *w_out = (int64_t)data[6] | ((int64_t)data[7] << 8);
        *h_out = (int64_t)data[8] | ((int64_t)data[9] << 8);
        return 0;
    }

    if (type == IMG_JPEG) {
        if (len < 4 || data[0] != 0xFF || data[1] != 0xD8) return -1;
        size_t i = 2;
        while (i + 4 < len) {
            if (data[i] != 0xFF) return -1;
            unsigned char marker = data[i + 1];
            if (marker == 0xFF) { i++; continue; }
            if (marker == 0xD8 || marker == 0xD9 || (marker >= 0xD0 && marker <= 0xD7)) {
                i += 2; continue;
            }
            size_t seg_len = ((size_t)data[i + 2] << 8) | data[i + 3];
            if (seg_len < 2 || i + 2 + seg_len > len) return -1;
            int is_sof = (marker >= 0xC0 && marker <= 0xCF) &&
                         marker != 0xC4 && marker != 0xC8 && marker != 0xCC;
            if (is_sof) {
                if (seg_len < 7 || i + 2 + 7 > len) return -1;
                *h_out = ((int64_t)data[i + 5] << 8) | data[i + 6];
                *w_out = ((int64_t)data[i + 7] << 8) | data[i + 8];
                return 0;
            }
            i += 2 + seg_len;
        }
        return -1;
    }

    if (type == IMG_BMP) {
        if (len < 18 || data[0] != 'B' || data[1] != 'M') {
            *w_out = 0; *h_out = 0; return 0;
        }
        uint32_t dib = (uint32_t)data[14] | ((uint32_t)data[15] << 8) |
                       ((uint32_t)data[16] << 16) | ((uint32_t)data[17] << 24);
        if (dib == 12 && len >= 22) {
            *w_out = (int64_t)((uint32_t)data[18] | ((uint32_t)data[19] << 8));
            *h_out = (int64_t)((uint32_t)data[20] | ((uint32_t)data[21] << 8));
            return 0;
        }
        if (dib >= 40 && len >= 26) {
            int32_t w = (int32_t)((uint32_t)data[18] | ((uint32_t)data[19] << 8) |
                                  ((uint32_t)data[20] << 16) | ((uint32_t)data[21] << 24));
            int32_t h = (int32_t)((uint32_t)data[22] | ((uint32_t)data[23] << 8) |
                                  ((uint32_t)data[24] << 16) | ((uint32_t)data[25] << 24));
            *w_out = w < 0 ? -(int64_t)w : (int64_t)w;
            *h_out = h < 0 ? -(int64_t)h : (int64_t)h;
            return 0;
        }
        *w_out = 0; *h_out = 0;
        return 0;
    }

    *w_out = 0;
    *h_out = 0;
    return 0;
}

static image_type_t detect_image_type(const char *mime, const char *ext)
{
    if (mime) {
        if (strcasecmp(mime, "image/jpeg") == 0) return IMG_JPEG;
        if (strcasecmp(mime, "image/png") == 0)  return IMG_PNG;
        if (strcasecmp(mime, "image/gif") == 0)  return IMG_GIF;
        if (strcasecmp(mime, "image/webp") == 0) return IMG_WEBP;
        if (strcasecmp(mime, "image/bmp") == 0 ||
            strcasecmp(mime, "image/x-ms-bmp") == 0) return IMG_BMP;
    }

    if (ext) {
        if (strcasecmp(ext, "jpg") == 0 || strcasecmp(ext, "jpeg") == 0) return IMG_JPEG;
        if (strcasecmp(ext, "png") == 0)  return IMG_PNG;
        if (strcasecmp(ext, "gif") == 0)  return IMG_GIF;
        if (strcasecmp(ext, "webp") == 0) return IMG_WEBP;
        if (strcasecmp(ext, "bmp") == 0)  return IMG_BMP;
    }

    return IMG_UNSUPPORTED;
}

static gdImagePtr decode_image(const unsigned char *data, size_t len, image_type_t type)
{
    switch (type) {
    case IMG_JPEG: return gdImageCreateFromJpegPtr((int)len, (void *)data);
    case IMG_PNG:  return gdImageCreateFromPngPtr((int)len, (void *)data);
    case IMG_GIF:  return gdImageCreateFromGifPtr((int)len, (void *)data);
    case IMG_WEBP: return gdImageCreateFromWebpPtr((int)len, (void *)data);
    case IMG_BMP:  return gdImageCreateFromBmpPtr((int)len, (void *)data);
    default:       return NULL;
    }
}

static void *encode_image(gdImagePtr img, image_type_t type, int *out_size)
{
    switch (type) {
    case IMG_JPEG: return gdImageJpegPtr(img, out_size, 90);
    case IMG_PNG:  return gdImagePngPtrEx(img, out_size, 6);
    case IMG_GIF:  return gdImageGifPtr(img, out_size);
    case IMG_WEBP: return gdImageWebpPtrEx(img, out_size, 90);
    case IMG_BMP:  return gdImageBmpPtr(img, out_size, 0);
    default:       *out_size = 0; return NULL;
    }
}

static int gif_skip_subblocks(const unsigned char *data, size_t len, size_t *i)
{
    for (int guard = 0; guard < GIF_MAX_BLOCKS; guard++) {
        if (*i >= len) return 0;
        unsigned char n = data[*i];
        (*i)++;
        if (n == 0) return 1;
        if ((size_t)n > len - *i) return 0;
        *i += n;
    }
    return 0;
}

static void gif_walk_blocks(const unsigned char *data, size_t len,
                            int *frames, int *ends_at_trailer)
{
    *frames = 0;
    *ends_at_trailer = 0;
    if (len < 13) return;
    if (memcmp(data, "GIF87a", 6) != 0 && memcmp(data, "GIF89a", 6) != 0) return;

    size_t i = 6;
    if (i + 7 > len) return;
    unsigned char screen = data[i + 4];
    i += 7;
    if (screen & 0x80) {
        size_t gct = 3u << ((screen & 0x07) + 1);
        if (gct > len - i) return;
        i += gct;
    }

    for (int guard = 0; guard < GIF_MAX_BLOCKS; guard++) {
        if (i >= len) return;
        unsigned char block = data[i];
        if (block == 0x3B) {
            *ends_at_trailer = (i + 1 == len);
            return;
        }
        if (block == 0x21) {
            if (i + 2 > len) return;
            i += 2;
            if (!gif_skip_subblocks(data, len, &i)) return;
            continue;
        }
        if (block == 0x2C) {
            if (i + 10 > len) return;
            unsigned char local = data[i + 9];
            i += 10;
            if (local & 0x80) {
                size_t lct = 3u << ((local & 0x07) + 1);
                if (lct > len - i) return;
                i += lct;
            }
            if (i >= len) return;
            i++;
            if (!gif_skip_subblocks(data, len, &i)) return;
            (*frames)++;
            continue;
        }
        return;
    }
}

static void png_walk_chunks(const unsigned char *data, size_t len,
                            int *has_actl, int *ends_at_iend)
{
    *has_actl = 0;
    *ends_at_iend = 0;
    if (len < 8) return;

    size_t i = 8;
    int seen_idat = 0;
    for (int guard = 0; guard < 4096; guard++) {
        if (i + 12 > len) return;
        uint32_t clen = ((uint32_t)data[i] << 24) | ((uint32_t)data[i + 1] << 16) |
                        ((uint32_t)data[i + 2] << 8) | (uint32_t)data[i + 3];
        if (clen > 0x7FFFFFFFu || (size_t)clen + 12 > len - i) return;
        const unsigned char *type = data + i + 4;
        if (!seen_idat && clen == 8 && memcmp(type, "acTL", 4) == 0) {
            const unsigned char *p = data + i + 8;
            uint32_t frames = ((uint32_t)p[0] << 24) | ((uint32_t)p[1] << 16) |
                              ((uint32_t)p[2] << 8) | (uint32_t)p[3];
            *has_actl = (frames > 1);
        }
        if (memcmp(type, "IDAT", 4) == 0) {
            seen_idat = 1;
        }
        if (memcmp(type, "IEND", 4) == 0) {
            *ends_at_iend = (i + 12 + (size_t)clen == len);
            return;
        }
        i += 12 + (size_t)clen;
    }
}

static void webp_walk_chunks(const unsigned char *data, size_t len,
                             int *has_anim, int *exact_riff)
{
    *has_anim = 0;
    *exact_riff = 0;
    if (len < 12 || memcmp(data, "RIFF", 4) != 0 || memcmp(data + 8, "WEBP", 4) != 0) {
        return;
    }
    uint32_t riff_size = (uint32_t)data[4] | ((uint32_t)data[5] << 8) |
                         ((uint32_t)data[6] << 16) | ((uint32_t)data[7] << 24);
    int size_exact = ((size_t)riff_size + 8 == len);

    size_t i = 12;
    int seen_anim = 0, frames = 0;
    for (int guard = 0; guard < 4096; guard++) {
        if (i == len) { *exact_riff = size_exact; break; }
        if (i + 8 > len) break;
        uint32_t csize = (uint32_t)data[i + 4] | ((uint32_t)data[i + 5] << 8) |
                         ((uint32_t)data[i + 6] << 16) | ((uint32_t)data[i + 7] << 24);
        if (csize > 0x7FFFFFFFu) break;
        size_t padded = (size_t)csize + ((csize & 1u) ? 1u : 0u);
        if (padded + 8 > len - i) break;
        if (memcmp(data + i, "ANIM", 4) == 0) {
            seen_anim = 1;
        }
        if (memcmp(data + i, "ANMF", 4) == 0) {
            frames++;
        }
        i += 8 + padded;
    }
    *has_anim = (seen_anim && frames > 0);
}

static int ext_is_opaque(const char *ext)
{
    if (!ext || ext[0] == '\0') return 0;
    for (int i = 0; OPAQUE_BINARY_EXTS[i]; i++) {
        if (strcasecmp(ext, OPAQUE_BINARY_EXTS[i]) == 0) return 1;
    }
    return 0;
}

int sanitize_raster_image(
    const unsigned char *data, size_t len,
    const char *mime, const char *ext,
    unsigned char **out, size_t *out_len,
    char *reason, size_t reason_size)
{
    *out = NULL;
    *out_len = 0;

    image_type_t type = detect_image_type(mime, ext);

    if (type == IMG_UNSUPPORTED) {
        if (ext_is_opaque(ext)) {
            snprintf(reason, reason_size, "opaque_image_passthrough");
            return SANITIZE_CLEAN;
        }
        snprintf(reason, reason_size, "unsupported_image_format");
        return SANITIZE_ERROR;
    }

    if (len > MAX_IMAGE_DECODE_BYTES) {
        snprintf(reason, reason_size, "image_too_large");
        return SANITIZE_REJECTED;
    }

    int64_t probe_w = 0, probe_h = 0;
    if (probe_image_dimensions(data, len, type, &probe_w, &probe_h) != 0) {
        snprintf(reason, reason_size, "image_header_malformed");
        return SANITIZE_REJECTED;
    }
    if (probe_w > 0 && probe_h > 0) {
        if (probe_w > MAX_IMAGE_WIDTH || probe_h > MAX_IMAGE_HEIGHT) {
            snprintf(reason, reason_size, "image_dimensions_exceeded");
            return SANITIZE_REJECTED;
        }
        if (probe_w * probe_h > MAX_IMAGE_PIXELS) {
            snprintf(reason, reason_size, "image_pixel_count_exceeded");
            return SANITIZE_REJECTED;
        }
    }

    int gif_frames = 0, gif_ends_at_trailer = 0;
    if (type == IMG_GIF) {
        gif_walk_blocks(data, len, &gif_frames, &gif_ends_at_trailer);
    }
    if (type == IMG_GIF && gif_frames > 1) {
        if (!gif_ends_at_trailer) {
            snprintf(reason, reason_size, "gif_trailing_data");
            return SANITIZE_REJECTED;
        }
        snprintf(reason, reason_size, "gif_animated_passthrough");
        return SANITIZE_CLEAN;
    }

    if (type == IMG_PNG) {
        int has_actl = 0, ends_at_iend = 0;
        png_walk_chunks(data, len, &has_actl, &ends_at_iend);
        if (has_actl) {
            if (!ends_at_iend) {
                snprintf(reason, reason_size, "png_trailing_data");
                return SANITIZE_REJECTED;
            }
            snprintf(reason, reason_size, "png_animated_passthrough");
            return SANITIZE_CLEAN;
        }
    }

    if (type == IMG_WEBP) {
        int has_anim = 0, exact_riff = 0;
        webp_walk_chunks(data, len, &has_anim, &exact_riff);
        if (has_anim) {
            if (!exact_riff) {
                snprintf(reason, reason_size, "webp_trailing_data");
                return SANITIZE_REJECTED;
            }
            snprintf(reason, reason_size, "webp_animated_passthrough");
            return SANITIZE_CLEAN;
        }
    }

    gdImagePtr img = decode_image(data, len, type);
    if (!img) {
        if (type == IMG_GIF && data[len - 1] != 0x3B) {
            snprintf(reason, reason_size, "gif_trailing_data");
            return SANITIZE_REJECTED;
        }
        snprintf(reason, reason_size, "image_decode_failed");
        return SANITIZE_ERROR;
    }

    int w = gdImageSX(img);
    int h = gdImageSY(img);
    if (w <= 0 || h <= 0 || w > MAX_IMAGE_WIDTH || h > MAX_IMAGE_HEIGHT ||
        (int64_t)w * (int64_t)h > MAX_IMAGE_PIXELS) {
        snprintf(reason, reason_size, "image_dimensions_invalid");
        gdImageDestroy(img);
        return SANITIZE_REJECTED;
    }

    gdImagePtr clean = gdImageCreateTrueColor(w, h);
    if (!clean) {
        snprintf(reason, reason_size, "image_alloc_failed");
        gdImageDestroy(img);
        return SANITIZE_ERROR;
    }

    if (type == IMG_PNG || type == IMG_GIF || type == IMG_WEBP) {
        gdImageAlphaBlending(clean, 0);
        gdImageSaveAlpha(clean, 1);
        gdImageFilledRectangle(clean, 0, 0, w - 1, h - 1,
                               gdTrueColorAlpha(0, 0, 0, 127));
    }

    gdImageAlphaBlending(clean, 1);
    gdImageCopy(clean, img, 0, 0, 0, 0, w, h);
    gdImageDestroy(img);

    int encoded_size = 0;
    void *encoded = encode_image(clean, type, &encoded_size);
    gdImageDestroy(clean);

    if (!encoded || encoded_size <= 0) {
        if (encoded) gdFree(encoded);
        snprintf(reason, reason_size, "image_encode_failed");
        return SANITIZE_ERROR;
    }

    *out = malloc((size_t)encoded_size);
    if (!*out) {
        gdFree(encoded);
        snprintf(reason, reason_size, "malloc_failed");
        return SANITIZE_ERROR;
    }
    memcpy(*out, encoded, (size_t)encoded_size);
    *out_len = (size_t)encoded_size;
    gdFree(encoded);

    return SANITIZE_MODIFIED;
}
