# PigCloud TEE Scanner

File inspection and sanitization with a separate signing service and an optional SGX build.

## Commands

- Native build: `make`
- Tests: `make test`
- Dependencies: libsodium, liboqs, libmagic, libgd, libexpat, libsystemd, libyara, libseccomp and zlib.
- Build input: `file-types.json`; `gen_whitelist.py` generates the scanner whitelist.
- Production uses ordinary hardened services; SGX support does not imply production enclave isolation or verified attestation.
- SGX configuration: `manifest.template`; verify the deployment's attestation status before relying on enclave isolation.

## References

- [Gramine](https://gramineproject.io/)
- [Report an issue](https://github.com/pigtech-de/pigcloud-issues/issues)
- [Source license](LICENSE)
- [Vendored cJSON](https://github.com/DaveGamble/cJSON)
