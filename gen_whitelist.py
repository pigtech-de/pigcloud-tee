#!/usr/bin/env python3

from __future__ import annotations

import json
import sys
from collections import defaultdict
from pathlib import Path

OPAQUE_TYPES = {"certificate", "database", "font"}

SCAN_VALUES = {"opaque", "archive"}

INSPECTABLE_ARCHIVE_MIMES = {
    "application/zip", "application/x-zip-compressed",
    "application/x-tar", "application/x-gtar",
    "application/gzip", "application/x-gzip",
    "application/x-bzip", "application/x-bzip2",
    "application/x-7z-compressed",
    "application/vnd.rar", "application/x-rar-compressed",
    "application/x-xz", "application/zstd",
    "application/x-lzip", "application/x-lzma",
    "application/java-archive", "application/x-java-archive",
    "application/vnd.android.package-archive",
    "application/epub+zip",
}

EXTRA_MIME_ALIASES: dict[str, list[str]] = {
    "application/x-pkcs12": ["application/pkcs12"],
    "application/x-x509-ca-cert": ["application/x-x509-user-cert"],
    "application/x-pem-file": ["application/pem-certificate-chain"],
    "application/pgp-signature": ["application/pgp-keys"],
    "application/vnd.sqlite3": ["application/x-sqlite3"],
    "application/x-msdownload": ["application/x-dosexec", "application/vnd.microsoft.portable-executable"],
    "application/java-archive": ["application/x-java-archive"],
    "application/x-tar": ["application/x-gtar", "application/x-ustar"],
    "font/ttf": ["application/x-font-ttf", "application/font-sfnt", "application/x-font-truetype"],
    "font/otf": ["application/x-font-otf", "application/font-sfnt", "application/vnd.ms-opentype"],
    "font/woff": ["application/font-woff"],
    "font/woff2": ["application/font-woff2"],
    "audio/aiff": ["audio/x-aiff"],
    "audio/midi": ["audio/x-midi"],
    "audio/ogg": [
        "application/ogg",
        "audio/x-ogg",
        "audio/vorbis",
        "audio/x-vorbis",
        "audio/x-vorbis+ogg",
        "audio/x-opus+ogg",
        "audio/x-flac+ogg",
        "audio/x-speex+ogg",
    ],
    "audio/flac": ["audio/x-flac"],
    "audio/webm": ["video/webm"],
    "image/x-icon": ["image/vnd.microsoft.icon"],
    "image/svg+xml": ["application/svg+xml"],
    "application/x-yaml": ["application/yaml"],
    "application/xml": ["text/xml"],
    "application/xml-dtd": ["application/xml", "text/xml"],
    "application/gzip": ["application/x-gzip"],
    "application/x-bzip2": ["application/x-bzip"],
    "application/rtf": ["text/rtf"],
    "application/json5": ["application/json"],
    "application/x-ndjson": ["application/json"],
    "application/x-ipynb+json": ["application/json"],
    "application/geo+json": ["application/json"],
    "application/manifest+json": ["application/json"],
    "application/gpx+xml": ["application/xml", "text/xml"],
    "application/vnd.google-earth.kml+xml": ["application/xml", "text/xml"],
    "application/vnd.comicbook-rar": ["application/x-rar-compressed", "application/x-rar", "application/vnd.rar"],
    "application/vnd.rar": ["application/x-rar-compressed", "application/x-rar"],
    "application/vnd.ms-outlook": ["application/x-ole-storage", "application/CDFV2"],
    "model/stl": ["text/plain"],
    "model/obj": ["text/plain"],
    "model/gltf+json": ["application/json", "text/plain"],
    "model/x-ply": ["text/plain"],
    "model/step": ["text/plain"],
    "image/vnd.dxf": ["text/plain"],
    "model/vnd.collada+xml": ["text/xml", "application/xml"],
    "application/postscript": ["application/pdf"],
    "application/x-fictionbook+xml": ["text/xml", "application/xml"],
    "application/vnd.corel-draw": ["application/zip", "application/x-vnd.corel.zcf.draw.document+zip"],
    "application/x-hdf": ["application/x-hdf5"],
}

ZIP_ALIASES = ["application/zip", "application/x-zip-compressed"]

PREFIX_BUCKETS = ("image/", "text/", "audio/", "video/", "font/", "model/")

TYPE_TO_PREFIX = {
    "image": "image/",
    "text":  "text/",
    "audio": "audio/",
    "video": "video/",
    "font":  "font/",
    "model": "model/",
}

BANNED_EXACT_MIMES = {"application/octet-stream", "application/unknown"}

def c_ext_list(exts: list[str]) -> str:
    return ", ".join(f'"{e}"' for e in exts)

def build(registry_path: Path) -> dict:
    data = json.loads(registry_path.read_text(encoding="utf-8"))
    exts = data["extensions"]

    mime_to_exts: dict[str, set[str]] = defaultdict(set)
    prefix_to_exts: dict[str, set[str]] = {p: set() for p in PREFIX_BUCKETS}
    opaque: set[str] = set()
    archive_exts: set[str] = set()

    for ext, info in exts.items():
        typ = info.get("type")
        mime = info.get("mime")
        scan = set(info.get("scan", []))
        if not scan <= SCAN_VALUES:
            print(f"gen_whitelist: {ext} has unknown scan value(s) {scan - SCAN_VALUES}", file=sys.stderr)
            sys.exit(1)

        if typ in TYPE_TO_PREFIX:
            prefix_to_exts[TYPE_TO_PREFIX[typ]].add(ext)
        if mime:
            mime_to_exts[mime].add(ext)
            for alias in EXTRA_MIME_ALIASES.get(mime, []):
                mime_to_exts[alias].add(ext)
            if info.get("zipBased"):
                for alias in ZIP_ALIASES:
                    mime_to_exts[alias].add(ext)

        if typ in OPAQUE_TYPES or "opaque" in scan:
            opaque.add(ext)
        if "archive" in scan:
            archive_exts.add(ext)

    return {
        "mime_to_exts": mime_to_exts,
        "prefix_to_exts": prefix_to_exts,
        "opaque": sorted(opaque),
        "archive_exts": sorted(archive_exts),
        "archive_mimes": sorted(INSPECTABLE_ARCHIVE_MIMES),
    }

def emit_header(data: dict) -> str:
    return """\
/* AUTO-GENERATED by tee/gen_whitelist.py — do not edit. */
/* Source of truth: private/file-types.json */
/* Regenerate: `make scanner_whitelist.h` (or just `make`). */

#ifndef PIGCLOUD_TEE_SCANNER_WHITELIST_H
#define PIGCLOUD_TEE_SCANNER_WHITELIST_H

#include <stddef.h>  /* NULL */

typedef struct {
    const char *mime;
    const char *extensions[64];
} mime_entry_t;

typedef struct {
    const char *prefix;
    const char *extensions[256];
} mime_prefix_t;

/* All arrays are NULL-terminated. Defined in scanner_whitelist.c. */
extern const mime_entry_t EXACT_MIMES[];
extern const mime_prefix_t PREFIX_MIMES[];
extern const char *const OPAQUE_BINARY_EXTS[];
extern const char *const INSPECTABLE_ARCHIVE_MIMES[];
extern const char *const INSPECTABLE_ARCHIVE_EXTS[];

#endif /* PIGCLOUD_TEE_SCANNER_WHITELIST_H */
"""

def emit_source(data: dict) -> str:
    out: list[str] = [
        "/* AUTO-GENERATED by tee/gen_whitelist.py — do not edit. */",
        "/* Source of truth: private/file-types.json */",
        "",
        '#include "scanner_whitelist.h"',
        "",
        "/* Inner-array initializers intentionally leave trailing slots NULL-",
        " * initialised (per C rules). Silence -Wmissing-field-initializers so",
        " * the main build stays quiet. */",
        "#if defined(__GNUC__) || defined(__clang__)",
        "# pragma GCC diagnostic ignored \"-Wmissing-field-initializers\"",
        "#endif",
        "",
        "const mime_entry_t EXACT_MIMES[] = {",
    ]
    for mime in sorted(data["mime_to_exts"].keys()):
        if mime in BANNED_EXACT_MIMES:
            continue
        exts_for_mime = sorted(data["mime_to_exts"][mime])
        if len(exts_for_mime) > 63:
            print(f"gen_whitelist: {mime} has {len(exts_for_mime)} extensions; raise mime_entry_t.extensions[]", file=sys.stderr)
            sys.exit(1)
        out.append(f'    {{"{mime}", {{{c_ext_list(exts_for_mime)}, NULL}}}},')
    out.append("    {NULL, {NULL}}")
    out.append("};")

    out.append("")
    out.append("const mime_prefix_t PREFIX_MIMES[] = {")
    for prefix in PREFIX_BUCKETS:
        exts_for_prefix = sorted(data["prefix_to_exts"][prefix])
        out.append(f'    {{"{prefix}", {{{c_ext_list(exts_for_prefix)}, NULL}}}},')
    out.append("    {NULL, {NULL}}")
    out.append("};")

    def emit_cstr_array(name: str, items: list[str]) -> None:
        out.append("")
        out.append(f"const char *const {name}[] = {{")
        for item in items:
            out.append(f'    "{item}",')
        out.append("    NULL")
        out.append("};")

    emit_cstr_array("OPAQUE_BINARY_EXTS", data["opaque"])
    emit_cstr_array("INSPECTABLE_ARCHIVE_MIMES", data["archive_mimes"])
    emit_cstr_array("INSPECTABLE_ARCHIVE_EXTS", data["archive_exts"])

    return "\n".join(out) + "\n"

def main() -> int:
    if len(sys.argv) != 4:
        print("usage: gen_whitelist.py <file-types.json> <out.h> <out.c>", file=sys.stderr)
        return 1
    data = build(Path(sys.argv[1]))
    Path(sys.argv[2]).write_text(emit_header(data), encoding="utf-8")
    Path(sys.argv[3]).write_text(emit_source(data), encoding="utf-8")
    return 0

if __name__ == "__main__":
    sys.exit(main())
