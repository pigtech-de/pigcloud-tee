# PigCloud Upload Scanner

File inspection and sanitization with a separate signing service.

## Commands

- Native build: `make`
- Tests: `make test`
- Dependencies: libsodium, liboqs, libmagic, libgd, libexpat, libsystemd, libyara, libseccomp and zlib.
- Build input: `file-types.json`; `gen_whitelist.py` generates the scanner whitelist.
- Both services run as ordinary hardened processes with no enclave isolation or hardware attestation.

## References

- [Report an issue](https://github.com/pigtech-de/pigcloud-issues/issues)
- [Source license](LICENSE)
- [Vendored cJSON](https://github.com/DaveGamble/cJSON)
