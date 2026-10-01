#!/usr/bin/env python3
import base64, hashlib, os, shutil, subprocess, sys, tempfile, zipfile

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from e2e_test import (ipc_request, encrypt_e2ee, hybrid_seal, create_test_jpeg,
                      cleanup_scan_artifacts, metadata_mac, self_check,
                      CHUNK_SIZE)
from nacl.utils import random as nacl_random

def _read(path):
    with open(path, "rb") as f:
        return f.read()

def _run(cmd):
    try:
        subprocess.run(cmd, check=True, capture_output=True, timeout=60)
        return True
    except (subprocess.CalledProcessError, subprocess.TimeoutExpired, FileNotFoundError):
        return None

def build_corpus(workdir):
    corpus = [("image/jpeg", "bake.jpg", create_test_jpeg())]
    missing = []

    def generated(mime, name, args):
        path = os.path.join(workdir, name)
        if _run(args + [path]):
            corpus.append((mime, name, _read(path)))
        else:
            missing.append(name)

    lavfi = ["ffmpeg", "-y", "-f", "lavfi", "-i"]
    generated("image/png", "bake.png",
              lavfi + ["color=c=red:s=32x32", "-frames:v", "1"])
    generated("image/gif", "bake.gif",
              lavfi + ["color=c=blue:s=32x32", "-frames:v", "1"])
    generated("image/webp", "bake.webp",
              lavfi + ["color=c=green:s=32x32", "-frames:v", "1"])
    generated("video/mp4", "bake.mp4",
              lavfi + ["testsrc=d=1:s=64x64", "-c:v", "libx264", "-pix_fmt", "yuv420p"])
    generated("video/webm", "bake.webm",
              lavfi + ["testsrc=d=1:s=64x64", "-c:v", "libvpx"])
    generated("audio/mpeg", "bake.mp3",
              lavfi + ["sine=f=440:d=1", "-c:a", "libmp3lame"])
    generated("audio/wav", "bake.wav", lavfi + ["sine=f=440:d=1"])

    ps = os.path.join(workdir, "bake.ps")
    with open(ps, "w") as f:
        f.write("%!PS\n/Helvetica findfont 24 scalefont setfont\n"
                "72 720 moveto (bake) show\nshowpage\n")
    pdf = os.path.join(workdir, "bake.pdf")
    if _run(["gs", "-q", "-dNOPAUSE", "-dBATCH", "-sDEVICE=pdfwrite",
             "-sOutputFile=" + pdf, ps]):
        corpus.append(("application/pdf", "bake.pdf", _read(pdf)))
    else:
        missing.append("bake.pdf")

    svg = (b'<?xml version="1.0"?><svg xmlns="http://www.w3.org/2000/svg" '
           b'width="32" height="32"><rect width="32" height="32" fill="red"/></svg>')
    corpus.append(("image/svg+xml", "bake.svg", svg))

    corpus.append(("text/plain", "bake.txt", b"bake corpus line\n" * 32))

    zpath = os.path.join(workdir, "bake.zip")
    with zipfile.ZipFile(zpath, "w", zipfile.ZIP_DEFLATED) as z:
        z.writestr("inner.txt", "bake corpus zip entry\n" * 16)
    corpus.append(("application/zip", "bake.zip", _read(zpath)))

    return corpus, missing

def scan_one(enclave_pk, enclave_pk_kyber, quarantine, filename, plaintext):
    pt_sha = hashlib.sha256(plaintext).hexdigest()
    data_key = nacl_random(32)
    nonce = nacl_random(24)
    ciphertext = encrypt_e2ee(plaintext, data_key, nonce)
    num_chunks = max(1, (len(plaintext) + CHUNK_SIZE - 1) // CHUNK_SIZE)
    sealed = hybrid_seal(data_key, enclave_pk, enclave_pk_kyber)

    test_file = os.path.join(quarantine, "bake_" + os.urandom(8).hex())
    with open(test_file, "wb") as f:
        f.write(ciphertext)

    nonce_b64 = base64.b64encode(nonce).decode()
    mac = metadata_mac(data_key, nonce_b64, num_chunks, pt_sha, len(plaintext))

    try:
        result = ipc_request({
            "op": "scan",
            "file_path": test_file,
            "user_id": 1,
            "tee_sealed_key": base64.b64encode(sealed).decode(),
            "encryption_meta": {
                "version": 2, "nonce": nonce_b64, "chunk_size": CHUNK_SIZE,
                "chunks": num_chunks, "plaintext_sha256": pt_sha,
                "plaintext_size": len(plaintext), "metadata_mac": mac,
            },
            "original_filename": filename,
        })
    finally:
        cleanup_scan_artifacts(test_file, quarantine)

    return result

def main():
    print("Verifying harness against committed vectors...")
    self_check()

    print("Fetching enclave keys...")
    attest = ipc_request({"op": "get_attestation"})
    enclave_pk = base64.b64decode(attest["enclave_public_key"])
    enclave_pk_kyber = base64.b64decode(attest["enclave_public_key_kyber"])
    if len(enclave_pk) != 32 or len(enclave_pk_kyber) != 1184:
        print("FAIL: enclave keys wrong length: x25519={} kyber={}".format(
            len(enclave_pk), len(enclave_pk_kyber)))
        return 1

    quarantine = os.environ.get("TEE_TEST_DIR",
                                "/var/www/pigtech/private/uploads/quarantine")
    os.makedirs(quarantine, exist_ok=True)

    workdir = tempfile.mkdtemp(prefix="tee-bake-")
    try:
        corpus, missing = build_corpus(workdir)
        print("Corpus: {} files\n".format(len(corpus)))

        errors = 0
        for _mime, filename, plaintext in corpus:
            res = scan_one(enclave_pk, enclave_pk_kyber, quarantine, filename, plaintext)
            verdict = res.get("verdict", "?")
            reason = res.get("reason", "")
            mime = res.get("detected_mime", "")
            if verdict not in ("clean", "sanitized"):
                errors += 1
                if res.get("busy"):
                    reason = (reason or "scanner_busy") + " (shed, not scanned)"
            print("  {:<24} {:>10}  mime={:<28} {}".format(
                filename, verdict, mime or "-", reason or ""))
    finally:
        shutil.rmtree(workdir, ignore_errors=True)

    print("\n{} scans, {} errored".format(len(corpus), errors))
    if missing:
        print("INCOMPLETE BAKE: no generator for {}".format(", ".join(missing)))
        print("  Those sanitizers stayed unexercised; install ffmpeg/ghostscript")
        print("  and re-run before flipping TEE_SECCOMP_MODE=enforce.")
    print("Now check for denials:")
    print("  sudo journalctl -k --since '15 min ago' | grep type=1326")
    return 1 if (errors or missing) else 0

if __name__ == "__main__":
    try:
        sys.exit(main())
    except RuntimeError as exc:
        print("\nFAIL: {}".format(exc))
        sys.exit(1)
