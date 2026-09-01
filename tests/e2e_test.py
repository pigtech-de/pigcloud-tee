#!/usr/bin/env python3
import socket, struct, json, os, hashlib, base64, sys, hmac, time
from nacl.utils import random as nacl_random
import nacl.bindings
import oqs
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes

SOCK_PATH = os.environ.get("TEE_SOCK", "/run/pigcloud-tee/scanner.sock")
CHUNK_SIZE = 1024 * 1024
KDF_INFO = b"pigcloud-hybrid-seal-v2"

EPH_PK_SIZE = 32
MLKEM_CT_SIZE = 1088
AEAD_NONCE_SIZE = 24
HYBRID_HEADER_SIZE = EPH_PK_SIZE + MLKEM_CT_SIZE + AEAD_NONCE_SIZE
SEALED_DATA_KEY_SIZE = HYBRID_HEADER_SIZE + 32 + 16

IPC_TIMEOUT = float(os.environ.get("TEE_IPC_TIMEOUT", "600"))

VECTOR_DIR = os.environ.get("TEE_VECTOR_DIR", os.path.join(
    os.path.dirname(os.path.abspath(__file__)), "..", "..", "tests", "vectors"))

def _recv_exact(sock, n):
    buf = b""
    while len(buf) < n:
        chunk = sock.recv(n - len(buf))
        if not chunk:
            raise IOError("scanner closed the connection after {} of {} bytes".format(
                len(buf), n))
        buf += chunk
    return buf

def ipc_request(msg_dict, timeout=None):
    sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    sock.settimeout(IPC_TIMEOUT if timeout is None else timeout)
    try:
        sock.connect(SOCK_PATH)
        payload = json.dumps(msg_dict).encode()
        sock.sendall(struct.pack(">I", len(payload)) + payload)
        rlen = struct.unpack(">I", _recv_exact(sock, 4))[0]
        return json.loads(_recv_exact(sock, rlen).decode())
    finally:
        sock.close()

def increment_nonce(nonce_bytes):
    arr = bytearray(nonce_bytes)
    for i in range(len(arr)):
        arr[i] = (arr[i] + 1) & 0xFF
        if arr[i] != 0:
            break
    return bytes(arr)

def create_test_jpeg():
    return bytes([
        0xFF, 0xD8, 0xFF, 0xE0, 0x00, 0x10, 0x4A, 0x46, 0x49, 0x46, 0x00, 0x01,
        0x01, 0x00, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0xFF, 0xDB, 0x00, 0x43,
        0x00, 0x08, 0x06, 0x06, 0x07, 0x06, 0x05, 0x08, 0x07, 0x07, 0x07, 0x09,
        0x09, 0x08, 0x0A, 0x0C, 0x14, 0x0D, 0x0C, 0x0B, 0x0B, 0x0C, 0x19, 0x12,
        0x13, 0x0F, 0x14, 0x1D, 0x1A, 0x1F, 0x1E, 0x1D, 0x1A, 0x1C, 0x1C, 0x20,
        0x24, 0x2E, 0x27, 0x20, 0x22, 0x2C, 0x23, 0x1C, 0x1C, 0x28, 0x37, 0x29,
        0x2C, 0x30, 0x31, 0x34, 0x34, 0x34, 0x1F, 0x27, 0x39, 0x3D, 0x38, 0x32,
        0x3C, 0x2E, 0x33, 0x34, 0x32, 0xFF, 0xC0, 0x00, 0x0B, 0x08, 0x00, 0x01,
        0x00, 0x01, 0x01, 0x01, 0x11, 0x00, 0xFF, 0xC4, 0x00, 0x1F, 0x00, 0x00,
        0x01, 0x05, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
        0x09, 0x0A, 0x0B, 0xFF, 0xC4, 0x00, 0xB5, 0x10, 0x00, 0x02, 0x01, 0x03,
        0x03, 0x02, 0x04, 0x03, 0x05, 0x05, 0x04, 0x04, 0x00, 0x00, 0x01, 0x7D,
        0x01, 0x02, 0x03, 0x00, 0x04, 0x11, 0x05, 0x12, 0x21, 0x31, 0x41, 0x06,
        0x13, 0x51, 0x61, 0x07, 0x22, 0x71, 0x14, 0x32, 0x81, 0x91, 0xA1, 0x08,
        0x23, 0x42, 0xB1, 0xC1, 0x15, 0x52, 0xD1, 0xF0, 0x24, 0x33, 0x62, 0x72,
        0x82, 0x09, 0x0A, 0x16, 0x17, 0x18, 0x19, 0x1A, 0x25, 0x26, 0x27, 0x28,
        0x29, 0x2A, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x3A, 0x43, 0x44, 0x45,
        0x46, 0x47, 0x48, 0x49, 0x4A, 0x53, 0x54, 0x55, 0x56, 0x57, 0x58, 0x59,
        0x5A, 0x63, 0x64, 0x65, 0x66, 0x67, 0x68, 0x69, 0x6A, 0x73, 0x74, 0x75,
        0x76, 0x77, 0x78, 0x79, 0x7A, 0x83, 0x84, 0x85, 0x86, 0x87, 0x88, 0x89,
        0x8A, 0x92, 0x93, 0x94, 0x95, 0x96, 0x97, 0x98, 0x99, 0x9A, 0xA2, 0xA3,
        0xA4, 0xA5, 0xA6, 0xA7, 0xA8, 0xA9, 0xAA, 0xB2, 0xB3, 0xB4, 0xB5, 0xB6,
        0xB7, 0xB8, 0xB9, 0xBA, 0xC2, 0xC3, 0xC4, 0xC5, 0xC6, 0xC7, 0xC8, 0xC9,
        0xCA, 0xD2, 0xD3, 0xD4, 0xD5, 0xD6, 0xD7, 0xD8, 0xD9, 0xDA, 0xE1, 0xE2,
        0xE3, 0xE4, 0xE5, 0xE6, 0xE7, 0xE8, 0xE9, 0xEA, 0xF1, 0xF2, 0xF3, 0xF4,
        0xF5, 0xF6, 0xF7, 0xF8, 0xF9, 0xFA, 0xFF, 0xDA, 0x00, 0x08, 0x01, 0x01,
        0x00, 0x00, 0x3F, 0x00, 0x7B, 0x94, 0x11, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xFF, 0xD9
    ])

def encrypt_e2ee(plaintext, data_key, nonce):
    chunks = []
    offset = 0
    chunk_idx = 0
    current_nonce = nonce

    while offset < len(plaintext):
        chunk_data = plaintext[offset:offset + CHUNK_SIZE]
        ad = struct.pack(">I", chunk_idx)
        ciphertext = nacl.bindings.crypto_aead_xchacha20poly1305_ietf_encrypt(
            chunk_data, ad, current_nonce, data_key
        )
        chunks.append(struct.pack(">I", len(ciphertext)) + ciphertext)
        current_nonce = increment_nonce(current_nonce)
        offset += CHUNK_SIZE
        chunk_idx += 1

    return b"".join(chunks)

def _hybrid_wrap_key(mlkem_ct, eph_pub, recipient_pk, ss_x, ss_k):
    return HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=mlkem_ct + eph_pub + recipient_pk,
        info=KDF_INFO,
    ).derive(ss_x + ss_k)

def hybrid_seal(plaintext, x25519_pk, kyber_pk):
    eph_priv = nacl_random(32)
    eph_pub = nacl.bindings.crypto_scalarmult_base(eph_priv)
    ss_x = nacl.bindings.crypto_scalarmult(eph_priv, x25519_pk)

    with oqs.KeyEncapsulation("ML-KEM-768") as kem:
        ct_k, ss_k = kem.encap_secret(kyber_pk)

    wrap_key = _hybrid_wrap_key(ct_k, eph_pub, x25519_pk, ss_x, ss_k)
    nonce = nacl_random(AEAD_NONCE_SIZE)
    aead_ct = nacl.bindings.crypto_aead_xchacha20poly1305_ietf_encrypt(
        plaintext, b"", nonce, wrap_key
    )
    return eph_pub + ct_k + nonce + aead_ct

def hybrid_unseal(sealed, x25519_sk, kyber_seed):
    eph_pub = sealed[:EPH_PK_SIZE]
    ct_k = sealed[EPH_PK_SIZE:EPH_PK_SIZE + MLKEM_CT_SIZE]
    nonce = sealed[EPH_PK_SIZE + MLKEM_CT_SIZE:HYBRID_HEADER_SIZE]
    aead_ct = sealed[HYBRID_HEADER_SIZE:]

    ss_x = nacl.bindings.crypto_scalarmult(x25519_sk, eph_pub)
    recipient_pk = nacl.bindings.crypto_scalarmult_base(x25519_sk)
    with oqs.KeyEncapsulation("ML-KEM-768") as kem:
        kem.generate_keypair_seed(kyber_seed)
        ss_k = kem.decap_secret(ct_k)

    wrap_key = _hybrid_wrap_key(ct_k, eph_pub, recipient_pk, ss_x, ss_k)
    return nacl.bindings.crypto_aead_xchacha20poly1305_ietf_decrypt(
        aead_ct, b"", nonce, wrap_key
    )

def metadata_mac(data_key, nonce_b64, chunks, pt_sha, pt_size,
                 version=2, chunk_size=CHUNK_SIZE):
    canonical = json.dumps(
        [version, nonce_b64, chunk_size, chunks, pt_sha, pt_size],
        separators=(",", ":")
    )
    return hmac.new(data_key, canonical.encode(), hashlib.sha256).hexdigest()

def _load_vector(name):
    with open(os.path.join(VECTOR_DIR, name), "rb") as f:
        return json.load(f)

def _try_unseal(sealed, x25519_sk, kyber_seed):
    try:
        return hybrid_unseal(sealed, x25519_sk, kyber_seed)
    except Exception:
        return None

def self_check():
    try:
        hv = _load_vector("hybrid_seal_v1.json")
        cv = _load_vector("chunked_file_v1.json")
    except (IOError, OSError):
        print("   WARN: vectors absent under {}".format(os.path.normpath(VECTOR_DIR)))
        print("         seal construction UNVERIFIED; set TEE_VECTOR_DIR to enable")
        return False

    d = base64.b64decode
    bad = []

    x_sk, x_pk = d(hv["recipient"]["x25519_sk_b64"]), d(hv["recipient"]["x25519_pk_b64"])
    seed, mk_pk = d(hv["recipient"]["mlkem_seed_b64"]), d(hv["recipient"]["mlkem_pk_b64"])

    if hv["kdf_info"].encode() != KDF_INFO:
        bad.append("kdf_info: harness {!r} != vector {!r}".format(
            KDF_INFO.decode(), hv["kdf_info"]))
    if _try_unseal(d(hv["sealed_blob_b64"]), x_sk, seed) != d(hv["plaintext_b64"]):
        bad.append("hybrid_seal_v1: committed blob did not open, so the wrap key "
                   "diverged from production (KDF salt order, ikm order, info "
                   "string, or AEAD wiring)")

    probe = nacl_random(32)
    blob = hybrid_seal(probe, x_pk, mk_pk)
    if len(blob) != SEALED_DATA_KEY_SIZE:
        bad.append("sealed length {} != {} expected by the enclave".format(
            len(blob), SEALED_DATA_KEY_SIZE))
    elif _try_unseal(blob, x_sk, seed) != probe:
        bad.append("hybrid_seal round-trip failed")

    c_sk, c_pk = d(cv["recipient"]["x25519_sk_b64"]), d(cv["recipient"]["x25519_pk_b64"])
    c_seed, c_mkpk = d(cv["recipient"]["mlkem_seed_b64"]), d(cv["recipient"]["mlkem_pk_b64"])
    data_key, meta = d(cv["data_key_b64"]), cv["metadata"]

    if _try_unseal(d(cv["sealed_data_key_b64"]), c_sk, c_seed) != data_key:
        bad.append("chunked_file_v1: committed sealed data key did not open")
    if _try_unseal(hybrid_seal(data_key, c_pk, c_mkpk), c_sk, c_seed) != data_key:
        bad.append("chunked_file_v1: harness-sealed data key did not round-trip")

    plaintext = bytes((i % 251) for i in range(cv["plaintext"]["size"]))
    if hashlib.sha256(plaintext).hexdigest() != cv["plaintext"]["sha256_hex"]:
        bad.append("regenerated vector plaintext does not match its sha256")
    elif encrypt_e2ee(plaintext, data_key, d(meta["nonce_b64"])) != d(cv["ciphertext_b64"]):
        bad.append("encrypt_e2ee: chunk framing, AD, or nonce increment diverged")

    got_mac = metadata_mac(data_key, meta["nonce_b64"], meta["chunks"],
                           meta["plaintext_sha256"], meta["plaintext_size"],
                           version=meta["version"], chunk_size=meta["chunk_size"])
    if got_mac != meta["metadata_mac"]:
        bad.append("metadata MAC canonical form diverged: {} != {}".format(
            got_mac[:16], meta["metadata_mac"][:16]))

    if bad:
        raise RuntimeError(
            "harness diverged from tests/vectors/:\n     - " + "\n     - ".join(bad))
    print("   vectors OK: hybrid_seal_v1 + chunked_file_v1 (seal, chunks, MAC)")
    return True

TEE_SIGNATURE_DOMAIN = b"pigcloud-tee-file-signature-v1"

def verify_tee_signatures(result, attest, sanitized_path):
    import nacl.signing
    import nacl.exceptions

    bad = []
    sig_ed_b64 = result.get("tee_signature_ed25519", "")
    sig_ml_b64 = result.get("tee_signature_mldsa", "")
    if not sig_ed_b64 or not sig_ml_b64:
        return ["sanitized verdict carried no tee_signature pair "
                "(ed25519={}, mldsa={})".format(bool(sig_ed_b64), bool(sig_ml_b64))]

    try:
        with open(sanitized_path, "rb") as f:
            ciphertext = f.read()
    except (IOError, OSError) as exc:
        return ["cannot read sanitized output {}: {}".format(sanitized_path, exc)]

    signed_input = TEE_SIGNATURE_DOMAIN + hashlib.sha256(ciphertext).digest()

    pk_ed = base64.b64decode(attest.get("enclave_signing_pk_ed25519", ""))
    if len(pk_ed) != 32:
        bad.append("attestation ed25519 signing PK wrong size: {}".format(len(pk_ed)))
    else:
        try:
            nacl.signing.VerifyKey(pk_ed).verify(
                signed_input, base64.b64decode(sig_ed_b64))
        except nacl.exceptions.BadSignatureError:
            bad.append("tee_signature_ed25519 does not verify over "
                       "sha256(sanitized ciphertext): the enclave signed "
                       "something other than the bytes it wrote")

    pk_ml = base64.b64decode(attest.get("enclave_signing_pk_mldsa", ""))
    if len(pk_ml) != 1312:
        bad.append("attestation ml-dsa signing PK wrong size: {}".format(len(pk_ml)))
    else:
        try:
            with oqs.Signature("ML-DSA-44") as verifier:
                if not verifier.verify(signed_input,
                                       base64.b64decode(sig_ml_b64), pk_ml):
                    bad.append("tee_signature_mldsa does not verify over "
                               "sha256(sanitized ciphertext)")
        except Exception as exc:
            bad.append("ml-dsa verification error: {}".format(exc))

    return bad

def cleanup_scan_artifacts(test_file, quarantine):
    paths = [test_file,
             os.path.join(quarantine, "sanitized",
                          os.path.basename(test_file) + ".sanitized"),
             os.path.join(quarantine, "sanitized",
                          os.path.basename(test_file) + ".verdict")]
    for path in paths:
        try:
            os.unlink(path)
        except OSError:
            pass

def run_async_scan(async_file, quarantine, sealed, nonce_b64, num_chunks,
                   pt_sha, pt_size, mac, sync_verdict, attest):
    problems = []
    try:
        ack = ipc_request({
            "op": "scan",
            "async": True,
            "file_path": async_file,
            "user_id": 1,
            "tee_sealed_key": base64.b64encode(sealed).decode(),
            "encryption_meta": {
                "version": 2,
                "nonce": nonce_b64,
                "chunk_size": CHUNK_SIZE,
                "chunks": num_chunks,
                "plaintext_sha256": pt_sha,
                "plaintext_size": pt_size,
                "metadata_mac": mac
            },
            "original_filename": "test.jpg"
        })
        if ack.get("accepted") is not True:
            problems.append("expected {accepted: true}, got " + json.dumps(ack))
            return problems
        verdict_path = os.path.join(quarantine, "sanitized",
                                    os.path.basename(async_file) + ".verdict")
        deadline = time.time() + 120
        async_result = None
        while time.time() < deadline:
            if os.path.exists(verdict_path):
                with open(verdict_path) as vf:
                    async_result = json.load(vf)
                break
            time.sleep(0.2)
        if async_result is None:
            problems.append("no verdict file within 120s at " + verdict_path)
        elif async_result.get("verdict") != sync_verdict:
            problems.append("async verdict {} differs from sync {}".format(
                async_result.get("verdict"), sync_verdict))
        elif async_result.get("verdict") == "sanitized":
            problems.extend(verify_tee_signatures(
                async_result, attest, async_result.get("sanitized_path", "")))
    finally:
        cleanup_scan_artifacts(async_file, quarantine)
    return problems

def main():
    self_check_only = "--self-check" in sys.argv
    print("0. Verifying harness against committed vectors...")
    verified = self_check()
    if self_check_only:
        if not verified:
            print("\nFAIL: no vectors under {}; --self-check verified nothing. "
                  "Set TEE_VECTOR_DIR.".format(os.path.normpath(VECTOR_DIR)))
            return 1
        print("\nPASS: self-check only, scanner not contacted")
        return 0

    print("1. Getting enclave hybrid public keys...")
    attest = ipc_request({"op": "get_attestation"})
    pk_b64 = attest["enclave_public_key"]
    pk_kyber_b64 = attest["enclave_public_key_kyber"]
    enclave_pk = base64.b64decode(pk_b64)
    enclave_pk_kyber = base64.b64decode(pk_kyber_b64)
    print("   X25519 PK: " + pk_b64[:24] + "...")
    print("   ML-KEM-768 PK: " + pk_kyber_b64[:24] + "... (" + str(len(enclave_pk_kyber)) + " bytes)")
    if len(enclave_pk_kyber) != 1184:
        print("FAIL: kyber pk wrong length: {}".format(len(enclave_pk_kyber)))
        return 1

    print("2. Creating test JPEG...")
    plaintext = create_test_jpeg()
    pt_sha = hashlib.sha256(plaintext).hexdigest()
    print("   {} bytes, sha256={}...".format(len(plaintext), pt_sha[:16]))

    print("3. Encrypting...")
    data_key = nacl_random(32)
    nonce = nacl_random(24)
    ciphertext = encrypt_e2ee(plaintext, data_key, nonce)
    num_chunks = max(1, (len(plaintext) + CHUNK_SIZE - 1) // CHUNK_SIZE)
    print("   {} bytes ciphertext, {} chunk(s)".format(len(ciphertext), num_chunks))

    print("4. Hybrid-sealing data key (X25519 + ML-KEM-768)...")
    sealed = hybrid_seal(data_key, enclave_pk, enclave_pk_kyber)
    print("   {} bytes sealed key".format(len(sealed)))

    test_dir = os.environ.get("TEE_TEST_DIR", "/var/www/pigtech/private/uploads/quarantine")
    os.makedirs(test_dir, exist_ok=True)
    test_file = os.path.join(test_dir, "tee_e2e_" + os.urandom(8).hex())
    with open(test_file, "wb") as f:
        f.write(ciphertext)
    print("5. Wrote ciphertext to " + test_file)

    nonce_b64 = base64.b64encode(nonce).decode()
    mac = metadata_mac(data_key, nonce_b64, num_chunks, pt_sha, len(plaintext))

    print("6. Sending scan request...")
    sig_problems = []
    try:
        result = ipc_request({
            "op": "scan",
            "file_path": test_file,
            "user_id": 1,
            "tee_sealed_key": base64.b64encode(sealed).decode(),
            "encryption_meta": {
                "version": 2,
                "nonce": nonce_b64,
                "chunk_size": CHUNK_SIZE,
                "chunks": num_chunks,
                "plaintext_sha256": pt_sha,
                "plaintext_size": len(plaintext),
                "metadata_mac": mac
            },
            "original_filename": "test.jpg"
        })
        if result.get("verdict") == "sanitized":
            print("7. Verifying enclave signatures over the sanitized output...")
            sig_problems = verify_tee_signatures(
                result, attest, result.get("sanitized_path", ""))
            if not sig_problems:
                print("   ed25519 + ml-dsa verify against the attested signing PKs")
    finally:
        cleanup_scan_artifacts(test_file, test_dir)

    print("8. Async scan: ack after admission, verdict via file...")
    async_file = os.path.join(test_dir, "tee_e2e_" + os.urandom(8).hex())
    with open(async_file, "wb") as f:
        f.write(ciphertext)
    async_problems = run_async_scan(async_file, test_dir, sealed, nonce_b64,
                                    num_chunks, pt_sha, len(plaintext), mac,
                                    result.get("verdict"), attest)
    if not async_problems:
        print("   async verdict matches the synchronous one")

    print("\n=== RESULT ===")
    print(json.dumps(result, indent=2))

    v = result.get("verdict", "")
    m = result.get("detected_mime", "")
    if async_problems:
        print("\nFAIL: async scan:\n     - " + "\n     - ".join(async_problems))
        return 1
    if sig_problems:
        print("\nFAIL: enclave signature check failed:\n     - "
              + "\n     - ".join(sig_problems))
        return 1
    if v in ("clean", "sanitized") and "image" in m:
        if v == "clean":
            print("   NOTE: verdict=clean, so no signature pair was produced "
                  "or checked on this run")
        print("\nPASS: verdict={}, mime={}".format(v, m))
        return 0
    if result.get("busy"):
        print("\nFAIL: scanner shed the request (busy); retry when load drops")
        return 1
    print("\nFAIL: verdict={}, reason={}, mime={}".format(
        v, result.get("reason", ""), m))
    return 1

if __name__ == "__main__":
    try:
        sys.exit(main())
    except RuntimeError as exc:
        print("\nFAIL: {}".format(exc))
        sys.exit(1)
