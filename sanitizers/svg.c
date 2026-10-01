#define _GNU_SOURCE

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <ctype.h>
#include <expat.h>
#include "sanitizers.h"

static const char *ALLOWED_ELEMENTS[] = {
    "svg", "g", "path", "rect", "circle", "ellipse", "line",
    "polyline", "polygon", "text", "tspan", "image", "defs",
    "lineargradient", "radialgradient", "stop", "clippath",
    "mask", "pattern", "use", "metadata", "title", "desc",
    NULL
};

static const char *ALLOWED_ATTRIBUTES[] = {
    "id", "class", "xmlns", "xmlns:xlink", "version",
    "x", "y", "width", "height", "viewbox", "preserveaspectratio",
    "d", "points", "x1", "y1", "x2", "y2", "rx", "ry", "cx", "cy", "r",
    "fx", "fy", "transform",
    "fill", "fill-opacity", "fill-rule",
    "stroke", "stroke-opacity", "stroke-width", "stroke-linecap",
    "stroke-linejoin", "stroke-miterlimit",
    "stroke-dasharray", "stroke-dashoffset",
    "opacity", "color", "paint-order", "vector-effect",
    "stop-color", "stop-opacity",
    "gradientunits", "gradienttransform", "spreadmethod",
    "patternunits", "patterntransform", "patterncontentunits",
    "maskunits", "maskcontentunits",
    "clippathunits", "clip-rule", "clip-path", "mask",
    "marker-start", "marker-mid", "marker-end",
    "markerunits", "markerwidth", "markerheight", "refx", "refy",
    "orient",
    "font-family", "font-size", "font-weight", "font-style", "font-variant",
    "text-anchor", "dominant-baseline", "alignment-baseline",
    "text-decoration", "letter-spacing", "word-spacing",
    "dx", "dy", "rotate", "lengthadjust", "textlength",
    "display", "visibility", "overflow", "pointer-events",
    "style",
    "href", "xlink:href",
    NULL
};

static const char *FRAGMENT_ONLY_ELEMENTS[] = {
    "image", "use", NULL
};

static int str_in_list(const char *needle, const char **list)
{
    for (int i = 0; list[i]; i++) {
        if (strcasecmp(needle, list[i]) == 0) return 1;
    }
    return 0;
}

static int str_starts_with_ci(const char *str, const char *prefix)
{
    while (*prefix) {
        if (tolower((unsigned char)*str) != tolower((unsigned char)*prefix))
            return 0;
        str++;
        prefix++;
    }
    return 1;
}

#define SVG_MAX_OUTPUT_MULTIPLIER 4
#define SVG_MAX_OUTPUT_FLOOR      (1 * 1024 * 1024)

typedef struct {
    char *buf;
    size_t len;
    size_t cap;
    size_t max_len;
    int depth;
    int skip_depth;
    int found_svg;
    int error;
    char err_msg[256];
} svg_state_t;

static int buf_append(svg_state_t *st, const char *data, size_t dlen)
{
    if (st->error) return -1;
    if (st->max_len && st->len + dlen > st->max_len) {
        st->error = 1;
        snprintf(st->err_msg, sizeof(st->err_msg), "svg_output_too_large");
        return -1;
    }
    while (st->len + dlen + 1 > st->cap) {
        size_t newcap = st->cap ? st->cap * 2 : 4096;
        if (st->max_len && newcap > st->max_len + 1) {
            newcap = st->max_len + 1;
        }
        char *tmp = realloc(st->buf, newcap);
        if (!tmp) {
            st->error = 1;
            snprintf(st->err_msg, sizeof(st->err_msg), "svg_oom");
            return -1;
        }
        st->buf = tmp;
        st->cap = newcap;
    }
    memcpy(st->buf + st->len, data, dlen);
    st->len += dlen;
    st->buf[st->len] = '\0';
    return 0;
}

static int buf_append_str(svg_state_t *st, const char *s)
{
    return buf_append(st, s, strlen(s));
}

static int buf_append_escaped(svg_state_t *st, const char *s)
{
    while (*s) {
        switch (*s) {
        case '&':  buf_append_str(st, "&amp;");  break;
        case '<':  buf_append_str(st, "&lt;");   break;
        case '>':  buf_append_str(st, "&gt;");   break;
        case '"':  buf_append_str(st, "&quot;");  break;
        case '\'': buf_append_str(st, "&#39;");   break;
        default:   buf_append(st, s, 1);          break;
        }
        if (st->error) return -1;
        s++;
    }
    return 0;
}

static const char *local_name(const char *name)
{
    return name;
}

static void XMLCALL start_element(void *userdata, const char *name, const char **atts)
{
    svg_state_t *st = (svg_state_t *)userdata;
    if (st->error) return;

    if (st->skip_depth >= 0) {
        st->depth++;
        return;
    }

    const char *lname = local_name(name);

    const char *colon = strchr(lname, ':');
    const char *match_name = colon ? colon + 1 : lname;

    if (!str_in_list(match_name, ALLOWED_ELEMENTS)) {
        st->skip_depth = st->depth;
        st->depth++;
        return;
    }

    if (!st->found_svg) {
        if (strcasecmp(match_name, "svg") != 0) {
            st->error = 1;
            snprintf(st->err_msg, sizeof(st->err_msg), "svg_root_not_svg");
            return;
        }
        st->found_svg = 1;
    }

    int is_fragment_only = str_in_list(match_name, FRAGMENT_ONLY_ELEMENTS);

    buf_append_str(st, "<");
    buf_append_str(st, match_name);

    for (int i = 0; atts[i]; i += 2) {
        const char *aname = atts[i];
        const char *aval  = atts[i + 1];

        char aname_lower[128];
        size_t alen = strlen(aname);
        if (alen >= sizeof(aname_lower)) continue;
        for (size_t j = 0; j <= alen; j++)
            aname_lower[j] = (char)tolower((unsigned char)aname[j]);

        if (aname_lower[0] == 'o' && aname_lower[1] == 'n') continue;

        if (!str_in_list(aname_lower, ALLOWED_ATTRIBUTES)) continue;

        if (strcasecmp(aname_lower, "href") == 0 ||
            strcasecmp(aname_lower, "xlink:href") == 0) {

            if (aval[0] == '\0') continue;
            if (str_starts_with_ci(aval, "javascript:")) continue;
            if (str_starts_with_ci(aval, "data:")) continue;

            if (is_fragment_only && aval[0] != '#') continue;

            if (aval[0] != '#' &&
                !str_starts_with_ci(aval, "http://") &&
                !str_starts_with_ci(aval, "https://")) {
                continue;
            }
        }

        if (strcasecmp(aname_lower, "style") == 0) {
            if (strcasestr(aval, "expression(") ||
                strcasestr(aval, "javascript:") ||
                strcasestr(aval, "@import") ||
                strcasestr(aval, "behavior:") ||
                strcasestr(aval, "behaviour:")) {
                continue;
            }
        }

        buf_append_str(st, " ");
        buf_append_str(st, aname_lower);
        buf_append_str(st, "=\"");
        buf_append_escaped(st, aval);
        buf_append_str(st, "\"");
    }

    buf_append_str(st, ">");
    st->depth++;
}

static void XMLCALL end_element(void *userdata, const char *name)
{
    svg_state_t *st = (svg_state_t *)userdata;
    if (st->error) return;

    st->depth--;

    if (st->skip_depth >= 0) {
        if (st->depth <= st->skip_depth) {
            st->skip_depth = -1;
        }
        return;
    }

    const char *lname = local_name(name);
    const char *colon = strchr(lname, ':');
    const char *match_name = colon ? colon + 1 : lname;

    buf_append_str(st, "</");
    buf_append_str(st, match_name);
    buf_append_str(st, ">");
}

static void XMLCALL character_data(void *userdata, const char *s, int len)
{
    svg_state_t *st = (svg_state_t *)userdata;
    if (st->error || st->skip_depth >= 0) return;

    for (int i = 0; i < len && !st->error; i++) {
        switch (s[i]) {
        case '&': buf_append_str(st, "&amp;");  break;
        case '<': buf_append_str(st, "&lt;");   break;
        case '>': buf_append_str(st, "&gt;");   break;
        default:  buf_append(st, &s[i], 1);     break;
        }
    }
}

int sanitize_svg(
    const unsigned char *data, size_t len,
    unsigned char **out, size_t *out_len,
    char *reason, size_t reason_size)
{
    *out = NULL;
    *out_len = 0;

    if (len == 0) {
        snprintf(reason, reason_size, "svg_empty");
        return SANITIZE_REJECTED;
    }

    size_t scan_len = len < 256 ? len : 256;
    for (size_t i = 0; i + 8 < scan_len; i++) {
        if (data[i] == '<' && data[i + 1] == '!') {
            if (strncasecmp((const char *)data + i, "<!DOCTYPE", 9) == 0) {
                snprintf(reason, reason_size, "svg_doctype_rejected");
                return SANITIZE_REJECTED;
            }
        }
    }

    svg_state_t st = {0};
    st.skip_depth = -1;
    size_t max_out = len * SVG_MAX_OUTPUT_MULTIPLIER;
    st.max_len = max_out > SVG_MAX_OUTPUT_FLOOR ? max_out : SVG_MAX_OUTPUT_FLOOR;

    XML_Parser parser = XML_ParserCreate(NULL);
    if (!parser) {
        snprintf(reason, reason_size, "xml_parser_create_failed");
        return SANITIZE_ERROR;
    }

    XML_SetParamEntityParsing(parser, XML_PARAM_ENTITY_PARSING_NEVER);

    XML_SetUserData(parser, &st);
    XML_SetElementHandler(parser, start_element, end_element);
    XML_SetCharacterDataHandler(parser, character_data);

    enum XML_Status status = XML_Parse(parser, (const char *)data, (int)len, 1);

    if (status == XML_STATUS_ERROR || st.error) {
        if (st.error && st.err_msg[0]) {
            snprintf(reason, reason_size, "%s", st.err_msg);
        } else {
            snprintf(reason, reason_size, "svg_malformed");
        }
        XML_ParserFree(parser);
        free(st.buf);
        return SANITIZE_REJECTED;
    }

    XML_ParserFree(parser);

    if (!st.found_svg) {
        free(st.buf);
        snprintf(reason, reason_size, "svg_no_root_element");
        return SANITIZE_REJECTED;
    }

    if (!st.buf || st.len == 0) {
        free(st.buf);
        snprintf(reason, reason_size, "svg_empty_result");
        return SANITIZE_REJECTED;
    }

    *out = (unsigned char *)st.buf;
    *out_len = st.len;

    return SANITIZE_MODIFIED;
}
