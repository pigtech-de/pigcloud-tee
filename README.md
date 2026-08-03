# PigCloud TEE Scanner

The server-side file scanner of [PigCloud](https://pigcloud.de). It runs inside
an Intel SGX enclave (via [Gramine](https://gramineproject.io/)), so uploaded
files are scanned and sanitized without the host ever holding plaintext or
keys outside the enclave boundary.

What it does per file: ClamAV and YARA scanning, format-aware sanitization
(images, SVG, PDF, archives, audio, video, text), MIME/extension admission
against the shared file-type registry, and remote attestation so clients can
verify exactly this code is what processes their uploads. A separate split
signer holds the long-lived keys; the scanner only ever gets an oracle.

## Why this repo exists

PigCloud clients pin the enclave measurement (MRENCLAVE) and the enclave
public key. This mirror lets you read the code behind that measurement and
reproduce the build. It is updated whenever the production scanner is rebuilt,
so the tree here corresponds to the enclave actually running.

## Build

```bash
make            # native binary, no SGX required
make test       # vector + admission tests
```

Dependencies: libsodium, liboqs, libmagic, libgd, libexpat, libsystemd,
libyara, libseccomp, zlib. The whitelist sources
(`scanner_whitelist.{h,c}`) are generated from `file-types.json` by
`gen_whitelist.py` during the build.

For the SGX build, `manifest.template` is the Gramine manifest;
`gramine-sgx-get-token` reports the resulting MRENCLAVE.

## Source, issues, and license

This repository is a source mirror published for review and measurement
reproduction. It does not accept pull requests; reports go to
[pigcloud-issues](https://github.com/pigtech-de/pigcloud-issues/issues).
`vendor/cjson` is [cJSON](https://github.com/DaveGamble/cJSON) (MIT), included
verbatim.

The source is available under the
[PolyForm Internal Use License 1.0.0](LICENSE): you may read, audit, and build
it for your own internal or personal use. Any other use, including
redistribution, needs written permission from PigTech.
