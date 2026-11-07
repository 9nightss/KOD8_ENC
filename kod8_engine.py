#!/usr/bin/env python3
import os
import zlib
import base64
import hashlib
import hmac
import re
from typing import Tuple, Optional
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes
import pgpy

# ── Global Key Config ────────────────────────────────────────────────────────
KOD8_KEY = b"86247931"

STRATEGY_MAP = {
    "CL1": "ASCII Plain Text",   "CL2": "Numeric Strings",
    "CL3": "Document Files",     "CL4": "Image Data",
    "CL5": "Video Data",         "CL6": "Fallback Engine 1",
    "CL7": "Fallback Engine 2",  "CL8": "Turkish Special Chars",
}

_HDR_RE = re.compile(
    r"^#\s*KOD8\s+cipher_id:\s*(CL\d+)\s+salt:\s*([A-Za-z0-9+/=]+)(?:\s+bin:\s*([01]))?(?:\s+ext:\s*(\S+))?\s*$"
)

# ── Topological Primitives (Nodes) ───────────────────────────────────────────

def node_8_hkdf_expand(base_key: bytes, salt: bytes) -> Tuple[bytes, bytes]:
    #Node 8: Key Expansion (HKDF-SHA-384). Returns (AES_KEY, HMAC_KEY)
    hkdf = HKDF(
        algorithm=hashes.SHA384(),
        length=32 + 48,  # 32B for AES-256, 48B for HMAC-SHA-384
        salt=salt,
        info=b"KOD8-NCIA-COMPLIANT-PIPELINE"
    )
    key_material = hkdf.derive(base_key)
    return key_material[:32], key_material[32:]

def node_6_zlib_compress(data: bytes, compress: bool) -> bytes:
    #Node 6: Data Preparation (Zlib / Deflate)
    return zlib.compress(data, level=9) if compress else zlib.decompress(data)

def node_2_pq_wrap(data: bytes, wrap: bool) -> bytes:
    #Node 2: Post-Quantum Wrap (Placeholder for ML-KEM-768)
    # In a full deployment, encapsulate/decapsulate a PQ session key here.
    # For sandbox, we prepend a 32-byte dummy header to reserve the byte-space.
    if wrap:
        return (b"\x00" * 32) + data
    return data[32:]

def node_4_hmac_sign(data: bytes, hmac_key: bytes, sign: bool) -> bytes:
    #Node 4: Plaintext Auth (HMAC-SHA-384)
    h = hmac.new(hmac_key, digestmod=hashlib.sha384)
    if sign:
        h.update(data)
        return h.digest() + data
    expected_mac = data[:48]
    payload = data[48:]
    h.update(payload)
    if not hmac.compare_digest(h.digest(), expected_mac):
        raise ValueError("KOD8: Inner HMAC-SHA-384 verification failed.")
    return payload

def node_7_aes_gcm(data: bytes, aes_key: bytes, encrypt: bool) -> bytes:
    #Node 7: Bulk Encryption (AES-256-GCM)
    aesgcm = AESGCM(aes_key)
    if encrypt:
        nonce = os.urandom(12)
        return nonce + aesgcm.encrypt(nonce, data, None)
    nonce, ciphertext = data[:12], data[12:]
    return aesgcm.decrypt(nonce, ciphertext, None)

def node_9_framing(data: bytes, frame: bool) -> bytes:
    #Node 9: Ciphertext Framing (Uniform Chunk Padding)
    # Pads payload to nearest 1024 bytes to obscure original file size.
    if frame:
        pad_len = 1024 - (len(data) % 1024)
        return data + (b"\x80" + b"\x00" * (pad_len - 1))
    # Unframe
    pad_idx = data.rfind(b"\x80")
    if pad_idx == -1:
        raise ValueError("KOD8: Framing validation failed.")
    return data[:pad_idx]

def node_3_outer_hash(data: bytes, hash_it: bool) -> bytes:
    #Node 3: Outer Integrity (SHA-512)
    if hash_it:
        digest = hashlib.sha512(data).digest()
        return digest + data
    expected_digest, payload = data[:64], data[64:]
    if hashlib.sha512(payload).digest() != expected_digest:
        raise ValueError("KOD8: Outer SHA-512 integrity check failed.")
    return payload

def node_1_terminal_reverse(data: bytes, encode: bool) -> str:
    #Node 1: Terminal Encoding (Base64 + Reversal)
    if encode:
        b64_str = base64.b64encode(data).decode("ascii")
        return b64_str[::-1]  # The signature KOD8 reverse string trick
    b64_str = data[::-1]
    return base64.b64decode(b64_str, validate=True)

# ── Pipeline Execution ───────────────────────────────────────────────────────

def run_kod8_pipeline(data_str: str, is_file: bool = False, encrypt: bool = True,
                      list_id: Optional[str] = "CL1", key: Optional[bytes] = None) -> Tuple[str, str, str, str]:
    
    # Executes the NCIA compliant 8-node pipeline.
    # Returns: (list_id, salt_b64, is_bin_str, ext_str, final_body)
    
    active_key = KOD8_KEY if key is None else key

    if encrypt:
        raw_bytes = data_str.encode("utf-8") if not is_file else data_str
        salt = os.urandom(16)
        salt_b64 = base64.b64encode(salt).decode("ascii")
        
        aes_key, hmac_key = node_8_hkdf_expand(active_key, salt)
        stage_6 = node_6_zlib_compress(raw_bytes, compress=True)
        stage_2 = node_2_pq_wrap(stage_6, wrap=True)
        stage_4 = node_4_hmac_sign(stage_2, hmac_key, sign=True)
        stage_7 = node_7_aes_gcm(stage_4, aes_key, encrypt=True)
        stage_9 = node_9_framing(stage_7, frame=True)
        stage_3 = node_3_outer_hash(stage_9, hash_it=True)
        final_body = node_1_terminal_reverse(stage_3, encode=True)
        
        return list_id, salt_b64, final_body
        
    else:
        # data_str must be the reversed Base64 body ONLY. 
        # Header parsing must happen before calling this in decryption mode.
        salt = base64.b64decode(list_id.split(":")[1]) # Passing salt via hack for sandbox api parity
        aes_key, hmac_key = node_8_hkdf_expand(active_key, salt)
        
        stage_3 = node_1_terminal_reverse(data_str, encode=False)
        stage_9 = node_3_outer_hash(stage_3, hash_it=False)
        stage_7 = node_9_framing(stage_9, frame=False)
        stage_4 = node_7_aes_gcm(stage_7, aes_key, encrypt=False)
        stage_2 = node_4_hmac_sign(stage_4, hmac_key, sign=False)
        stage_6 = node_2_pq_wrap(stage_2, wrap=False)
        final_bytes = node_6_zlib_compress(stage_6, compress=False)
        
        return final_bytes

# ── Container & PGP Integrations ─────────────────────────────────────────────

def format_kod8_file(cid: str, salt_b64: str, is_bin: bool, ext: str, body: str) -> str:
    #Constructs the compliant `.kod8` file with the plaintext header
    bin_flag = "1" if is_bin else "0"
    ext_str = f"  ext: {ext}" if ext else ""
    header = f"# KOD8  cipher_id: {cid}  salt: {salt_b64}  bin: {bin_flag}{ext_str}"
    return f"{header}\n{body}"

def generate_pgp_signature(kod8_filepath: str, private_key_path: str, passphrase: str = None) -> str:
    #Generates a detached `.asc` OpenPGP signature for the final written KOD8 file
    priv_key, _ = pgpy.PGPKey.from_file(private_key_path)
    if passphrase and not priv_key.is_unlocked:
        with priv_key.unlock(passphrase):
            message = pgpy.PGPMessage.new(kod8_filepath, file=True)
            signature = priv_key.sign(message)
    else:
        message = pgpy.PGPMessage.new(kod8_filepath, file=True)
        signature = priv_key.sign(message)
        
    sig_path = f"{kod8_filepath}.asc"
    with open(sig_path, "w") as f:
        f.write(str(signature))
        
    return sig_path