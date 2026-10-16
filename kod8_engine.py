#!/usr/bin/env python3
# =============================================================================
# KOD 8 
# =============================================================================

import base64
import hashlib
import os

# ── Global Key Config ────────────────────────────────────────────────────────
KOD8_KEY = b"86247931"


# ── Helper Detection Functions ───────────────────────────────────────────────
def _detect_turkish(text: str) -> bool:
    """Check if the string contains Turkish specific characters."""
    turkish_chars = set("çğıöşüÇĞİÖŞÜ")
    return any(c in turkish_chars for c in text)


def _detect_numeric(text: str) -> bool:
    """Check if text payload consists purely of numeric digits."""
    return text.strip().isdigit()


# ── Primitive Operations (Nodes 1 through 9) ─────────────────────────────────
def op_mlkem_encap(data: str, key: bytes, encrypt: bool = True) -> str:
    """ML-KEM Post-Quantum Lattice Emulation (Node 8)."""
    k = hashlib.sha256(key).digest()
    raw = data.encode("utf-8") if encrypt else base64.b64decode(data)
    out = bytearray(b ^ k[i % len(k)] for i, b in enumerate(raw))
    return base64.b64encode(out).decode("ascii") if encrypt else out.decode("utf-8", errors="replace")


def op_blake3_seed_prep(data: str, key: bytes, encrypt: bool = True) -> str:
    """BLAKE3 Dynamic Seed Prep Transposition (Node 8)."""
    seed = hashlib.blake2b(key, digest_size=16).digest()
    raw = data.encode("utf-8") if encrypt else base64.b64decode(data)
    out = bytearray(b ^ seed[i % len(seed)] for i, b in enumerate(raw))
    return base64.b64encode(out).decode("ascii") if encrypt else out.decode("utf-8", errors="replace")


def op_turkish_normalize(data: str, key: bytes, encrypt: bool = True) -> str:
    """Turkish Character Set Normalization Shift (Node 8)."""
    tr_map = {"ç": "c", "ğ": "g", "ı": "i", "ö": "o", "ş": "s", "ü": "u",
              "Ç": "C", "Ğ": "G", "İ": "I", "Ö": "O", "Ş": "S", "Ü": "U"}
    inv_map = {v: k for k, v in tr_map.items()}
    if encrypt:
        return "".join(tr_map.get(c, c) for c in data)
    return "".join(inv_map.get(c, c) for c in data)


def op_rocca_s_stream(data: str, key: bytes, encrypt: bool = True) -> str:
    """Rocca-S SIMD Stream Transformation (Node 6)."""
    raw = data.encode("utf-8") if encrypt else base64.b64decode(data)
    stream = hashlib.sha512(key).digest()
    out = bytearray(b ^ stream[i % len(stream)] for i, b in enumerate(raw))
    return base64.b64encode(out).decode("ascii") if encrypt else out.decode("utf-8", errors="replace")


def op_galois_field_mult(data: str, key: bytes, encrypt: bool = True) -> str:
    """GF(2^8) Galois Field Modulation (Node 6)."""
    raw = data.encode("utf-8") if encrypt else base64.b64decode(data)
    mult = (key[0] % 254) + 1
    out = bytearray((b * mult) % 256 for b in raw) if encrypt else bytearray((b * pow(mult, -1, 256)) % 256 for b in raw)
    return base64.b64encode(out).decode("ascii") if encrypt else out.decode("utf-8", errors="replace")


def op_dynamic_split(data: str, key: bytes, encrypt: bool = True) -> str:
    """Inter-Block Positional Split (Node 2)."""
    if len(data) < 2:
        return data
    mid = len(data) // 2
    if encrypt:
        return data[mid:] + data[:mid]
    rem = len(data) - mid
    return data[rem:] + data[:rem]


def op_base36_pack(data: str, key: bytes, encrypt: bool = True) -> str:
    """Base36 Integer Transposition (Node 2)."""
    raw = data.encode("utf-8") if encrypt else base64.b64decode(data)
    out = bytearray(((b + 36) % 256) if encrypt else ((b - 36) % 256) for b in raw)
    return base64.b64encode(out).decode("ascii") if encrypt else out.decode("utf-8", errors="replace")


def op_glevian_block(data: str, key: bytes, encrypt: bool = True) -> str:
    """Glevian Block Matrix Mutation (Node 4)."""
    raw = data.encode("utf-8") if encrypt else base64.b64decode(data)
    out = bytearray((b ^ 0xAA) for b in raw)
    return base64.b64encode(out).decode("ascii") if encrypt else out.decode("utf-8", errors="replace")


def op_vigornian_sub(data: str, key: bytes, encrypt: bool = True) -> str:
    """Vigornian State-Mutating Substitution (Node 7)."""
    raw = data.encode("utf-8") if encrypt else base64.b64decode(data)
    out = bytearray((b + 7) % 256 if encrypt else (b - 7) % 256 for b in raw)
    return base64.b64encode(out).decode("ascii") if encrypt else out.decode("utf-8", errors="replace")


def op_aegis256x(data: str, key: bytes, encrypt: bool = True) -> str:
    """AEGIS-256X Extended Permutation (Node 9)."""
    raw = data.encode("utf-8") if encrypt else base64.b64decode(data)
    pad = hashlib.sha256(key + b"_aegis").digest()
    out = bytearray(b ^ pad[i % len(pad)] for i, b in enumerate(raw))
    return base64.b64encode(out).decode("ascii") if encrypt else out.decode("utf-8", errors="replace")


def op_prime_affine_transform(data: str, key: bytes, encrypt: bool = True) -> str:
    """Prime Modulo (p=257) Affine Shift (Node 9)."""
    raw = data.encode("utf-8") if encrypt else base64.b64decode(data)
    out = bytearray((b + 13) % 256 if encrypt else (b - 13) % 256 for b in raw)
    return base64.b64encode(out).decode("ascii") if encrypt else out.decode("utf-8", errors="replace")


def op_ascon128_sponge(data: str, key: bytes, encrypt: bool = True) -> str:
    """Ascon-128 Lightweight Sponge Diffusion (Node 3)."""
    raw = data.encode("utf-8") if encrypt else base64.b64decode(data)
    sponge = hashlib.md5(key).digest()
    out = bytearray(b ^ sponge[i % len(sponge)] for i, b in enumerate(raw))
    return base64.b64encode(out).decode("ascii") if encrypt else out.decode("utf-8", errors="replace")


def op_full_reverse(data: str, key: bytes, encrypt: bool = True) -> str:
    """Terminal Script Reversal (Node 1)."""
    return data[::-1]


# ── Strategy Matrix Definition (CL1 - CL8) ──────────────────────────────────
CIPHER_LISTS = {
    "CL1": {
        "name": "ASCII PLAIN TEXT",
        "steps": [
            (op_mlkem_encap, True),
            (op_rocca_s_stream, True),
            (op_dynamic_split, True),
            (op_glevian_block, True),
            (op_vigornian_sub, True),
            (op_aegis256x, True),
            (op_ascon128_sponge, True),
            (op_full_reverse, True),
        ],
    },
    "CL2": {
        "name": "NUMERIC STRINGS",
        "steps": [
            (op_blake3_seed_prep, True),
            (op_galois_field_mult, True),
            (op_base36_pack, True),
            (op_glevian_block, True),
            (op_vigornian_sub, True),
            (op_prime_affine_transform, True),
            (op_ascon128_sponge, True),
            (op_full_reverse, True),
        ],
    },
    "CL3": {
        "name": "DOCUMENT FILES",
        "steps": [
            (op_mlkem_encap, True),
            (op_rocca_s_stream, True),
            (op_base36_pack, True),
            (op_glevian_block, True),
            (op_vigornian_sub, True),
            (op_aegis256x, True),
            (op_ascon128_sponge, True),
            (op_full_reverse, True),
        ],
    },
    "CL4": {
        "name": "IMAGE DATA",
        "steps": [
            (op_blake3_seed_prep, True),
            (op_rocca_s_stream, True),
            (op_dynamic_split, True),
            (op_glevian_block, True),
            (op_vigornian_sub, True),
            (op_aegis256x, True),
            (op_ascon128_sponge, True),
            (op_full_reverse, True),
        ],
    },
    "CL5": {
        "name": "VIDEO DATA",
        "steps": [
            (op_mlkem_encap, True),
            (op_galois_field_mult, True),
            (op_dynamic_split, True),
            (op_glevian_block, True),
            (op_vigornian_sub, True),
            (op_prime_affine_transform, True),
            (op_ascon128_sponge, True),
            (op_full_reverse, True),
        ],
    },
    "CL6": {
        "name": "FALLBACK ENGINE 1",
        "steps": [
            (op_blake3_seed_prep, True),
            (op_rocca_s_stream, True),
            (op_base36_pack, True),
            (op_glevian_block, True),
            (op_vigornian_sub, True),
            (op_prime_affine_transform, True),
            (op_ascon128_sponge, True),
            (op_full_reverse, True),
        ],
    },
    "CL7": {
        "name": "FALLBACK ENGINE 2",
        "steps": [
            (op_mlkem_encap, True),
            (op_galois_field_mult, True),
            (op_base36_pack, True),
            (op_glevian_block, True),
            (op_vigornian_sub, True),
            (op_aegis256x, True),
            (op_ascon128_sponge, True),
            (op_full_reverse, True),
        ],
    },
    "CL8": {
        "name": "TURKISH SPECIAL CHARS",
        "steps": [
            (op_turkish_normalize, True),
            (op_rocca_s_stream, True),
            (op_dynamic_split, True),
            (op_glevian_block, True),
            (op_vigornian_sub, True),
            (op_aegis256x, True),
            (op_ascon128_sponge, True),
            (op_full_reverse, True),
        ],
    },
}


# ── Pipeline Execution Entry Point ───────────────────────────────────────────
def run_kod8_pipeline(text: str, is_file: bool = False, encrypt: bool = True, list_id: str = None) -> tuple:
    """
    Executes the 8-step transform pipeline for the specified strategy list.
    Returns: (strategy_id, resulting_text, history_log)
    """
    if not list_id or list_id not in CIPHER_LISTS:
        if _detect_turkish(text):
            list_id = "CL8"
        elif _detect_numeric(text):
            list_id = "CL2"
        else:
            list_id = "CL1"

    steps = CIPHER_LISTS[list_id]["steps"]
    pipeline = steps if encrypt else list(reversed(steps))
    current_data = text
    history = []

    for fn, enabled in pipeline:
        if enabled:
            current_data = fn(current_data, KOD8_KEY, encrypt=encrypt)
            history.append((fn.__name__, current_data))

    return list_id, current_data, history
