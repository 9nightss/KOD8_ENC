import base64
import math

# =============================================================================
# KOD 8 — CIPHER ENGINE v2.0
# =============================================================================
#
# Architecture:
#   • 6 CipherLists, one per input type (text, image, video, doc, numeric, exp)
#   • Each list defines exactly 8 steps in a fixed sequence
#   • Every step is fully reversible — decryption = same 8 steps in REVERSE
#     order, each called with encrypt=False
#   • KOD8 auto-detects which CipherList to use by analysing the input
#
# Chain Safety Rules (enforced in every CipherList):
#   R1. After op_hex    : output is pure uppercase hex  (chars: 0-9, A-F)
#   R2. After op_base64 : output is base64 alphabet     (A-Z, a-z, 0-9, +, /, =)
#   R3. op_vigenere_tr / op_atbash_tr only shift TURKISH_ALPHA chars; all
#       other chars pass through unchanged — they are safe anywhere in chain
#   R4. op_unicode_shift MUST NOT precede op_atbash_tr / op_vigenere_tr
#       in the same chain if Turkish-alphabet chars may be present, because
#       (+5 mod 256) on a Turkish char produces a non-Turkish codepoint that
#       the alphabet ops cannot then reverse correctly.
#       Safe positions: AFTER hex/base64 output (guaranteed non-Turkish) OR
#       as the final substitution before a pure-transposition outer shell.
#   R5. op_base64 decode expects valid base64; never place an op that produces
#       arbitrary bytes (rolling_xor, block_xor_cbc, sbox) BETWEEN a base64
#       encode and its corresponding decode in the reversed chain.
#   R6. .upper() is applied to all input before the first step so vigenere_tr
#       and atbash_tr always receive uppercase input and produce uppercase output.
#
# =============================================================================

KOD8_KEY      = "86247931"
TURKISH_ALPHA = "ABCÇDEFGĞHİIJKLMNOÖPRSŞTUÜVYZ"

# ── Deterministic S-box ──────────────────────────────────────────────────────
# Fisher-Yates shuffle seeded from KOD8_KEY, computed once at import time.
# _SBOX[i]    = encrypted byte value for input ordinal i   (bijective 0-255)
# _SBOX_INV   = precomputed inverse table used for decryption
_SBOX = list(range(256))
_seed = sum(int(c) * (i + 1) for i, c in enumerate(KOD8_KEY))
for _i in range(255, 0, -1):
    _seed = (_seed * 1103515245 + 12345) & 0x7FFFFFFF
    _j    = _seed % (_i + 1)
    _SBOX[_i], _SBOX[_j] = _SBOX[_j], _SBOX[_i]
_SBOX_INV = [0] * 256
for _i, _v in enumerate(_SBOX):
    _SBOX_INV[_v] = _i


# =============================================================================
# PRIMITIVE OPERATIONS
# =============================================================================
# Convention: every op signature is  op_xxx(text: str, encrypt: bool, **kwargs)
# All ops are self-contained, stateless, and fully invertible.
# =============================================================================

def op_hex(text: str, encrypt: bool, **_) -> str:
    """
    HEX ENCODE / DECODE
    -------------------
    Encrypt: converts every character to its UTF-8 hex representation.
        "Hi" → UTF-8 bytes [0x48, 0x69] → "4869" (uppercased)
    Decrypt: reads pairs of hex digits and decodes them back to UTF-8 text.

    Why it's here: normalises arbitrary unicode/binary input into a clean
    printable ASCII character set (0-9, A-F) so all downstream ops work
    safely without breaking on null bytes or control characters.
    Output guarantee (R1): pure uppercase hex — 0-9 and A-F only.
    """
    if encrypt:
        return text.encode("utf-8").hex().upper()
    try:
        return bytes.fromhex(text).decode("utf-8")
    except Exception:
        return text


def op_base64(text: str, encrypt: bool, **_) -> str:
    """
    BASE64 ENCODE / DECODE
    ----------------------
    Encrypt: encodes raw bytes (interpreted as latin-1) into a Base64 string.
        Binary data → safe ASCII:  A-Z, a-z, 0-9, +, /, =
    Decrypt: decodes Base64 string back to the original byte sequence.

    Why it's here: essential for image/video lists where the input is raw
    binary — Base64 makes any binary payload fully printable and ensures every
    subsequent op works on a uniform, well-defined character set (R2).
    Output guarantee (R2): base64 alphabet only — safe to feed into any op.
    """
    if encrypt:
        return base64.b64encode(text.encode("latin-1", errors="replace")).decode("ascii")
    try:
        return base64.b64decode(text + "=" * (-len(text) % 4)).decode("latin-1", errors="replace")
    except Exception:
        return text


def op_xor_key(text: str, encrypt: bool, **_) -> str:
    """
    XOR WITH KEY BYTE  (self-inverse)
    ----------------------------------
    Encrypt = Decrypt: XOR every character's ordinal with the integer value of
    the first key digit.  KOD8_KEY[0] = '8', so the mask byte is 8.

        chr(ord('A') ^ 8) = chr(65 ^ 8) = chr(73) = 'I'
        chr(ord('I') ^ 8) = chr(73 ^ 8) = chr(65) = 'A'  ← same op inverts it

    Because XOR is self-inverse, the encrypt and decrypt paths are identical
    — the engine just calls this with either flag and the result is the same.
    Does not change string length.  Safe at any chain position.
    """
    key_byte = int(KOD8_KEY[0])
    # Skip chars with ord > 255 — XOR result would be unrecoverable
    return "".join(
        chr(ord(c) ^ key_byte) if ord(c) <= 255 else c
        for c in text
    )


def op_rolling_xor(text: str, encrypt: bool, **_) -> str:
    """
    ROLLING XOR  (CBC byte-mode)
    ----------------------------
    Encrypt: XOR each character with the PREVIOUS OUTPUT character (chained).
        seed   = int(KOD8_KEY[0]) = 8              ← initialisation vector
        out[0] = chr(ord(in[0]) ^ seed)
        out[i] = chr(ord(in[i]) ^ ord(out[i-1]))   for i > 0

    Decrypt: undo the chain by XORing each ciphertext byte with the previous
    CIPHERTEXT byte (which is already known), so decryption can go forward:
        in[0] = chr(ord(out[0]) ^ seed)
        in[i] = chr(ord(out[i]) ^ ord(out[i-1]))

    Why it's here: DIFFUSION — a single changed character cascades through
    every subsequent output character.  Unlike plain XOR, identical input
    blocks produce different ciphertext blocks.  Safe anywhere in chain.
    """
    if not text:
        return text
    seed, result = int(KOD8_KEY[0]), []
    if encrypt:
        prev = seed
        for c in text:
            if ord(c) > 255:        # pass high-codepoint chars through
                result.append(c)
            else:
                enc = chr(ord(c) ^ prev)
                result.append(enc)
                prev = ord(enc)
    else:
        prev = seed
        for c in text:
            if ord(c) > 255:
                result.append(c)
            else:
                result.append(chr(ord(c) ^ prev))
                prev = ord(c)
    return "".join(result)


def op_keystream_xor(text: str, encrypt: bool, **_) -> str:
    """
    KEY STREAM XOR  (self-inverse)
    ------------------------------
    Encrypt = Decrypt: generates a pseudo-random byte stream from KOD8_KEY
    using a Linear Congruential Generator (LCG), then XORs each character
    with the next byte of the stream.

        seed  = int(KOD8_KEY)  = 86247931
        seed  = (seed × 1103515245 + 12345) mod 2^31   ← LCG step
        byte  = seed mod 256
        out_i = chr(ord(in_i) ^ byte_i)

    The PRNG is deterministic — same key always produces the same stream,
    so the XOR is self-inverse.

    Why it's here: every position gets a UNIQUE XOR byte, destroying long
    repeating patterns (e.g. video frame data).  Safe anywhere in chain.
    """
    seed, result = int(KOD8_KEY), []
    for c in text:
        seed = (seed * 1103515245 + 12345) & 0x7FFFFFFF
        if ord(c) > 255:   # skip high-codepoint chars unchanged
            result.append(c)
        else:
            result.append(chr(ord(c) ^ (seed % 256)))
    return "".join(result)


def op_vigenere_tr(text: str, encrypt: bool, **_) -> str:
    """
    VIGENERE CIPHER — TURKISH ALPHABET
    ------------------------------------
    Encrypt: for each character that belongs to TURKISH_ALPHA, shift it
    forward by the key digit at (key_pos mod 8), where key_pos only
    increments on Turkish-alpha characters.
        new_idx = (current_idx + shift) mod len(TURKISH_ALPHA)

    Decrypt: shift backward by the same amount.
        new_idx = (current_idx − shift) mod len(TURKISH_ALPHA)

    Non-TURKISH_ALPHA characters pass through UNCHANGED (R3).

    Why it's here: polyalphabetic substitution — shift amount varies by
    position, defeating frequency analysis on the Turkish alphabet.
    Prerequisite: input must be uppercase (R6) — only uppercase Turkish
    letters are in TURKISH_ALPHA.
    """
    result, key_pos = [], 0
    for c in text:
        if c in TURKISH_ALPHA:
            idx     = TURKISH_ALPHA.index(c)
            shift   = int(KOD8_KEY[key_pos % len(KOD8_KEY)])
            new_idx = (idx + shift if encrypt else idx - shift) % len(TURKISH_ALPHA)
            result.append(TURKISH_ALPHA[new_idx])
            key_pos += 1
        else:
            result.append(c)
    return "".join(result)


def op_atbash_tr(text: str, encrypt: bool, **_) -> str:
    """
    ATBASH — TURKISH ALPHABET MIRROR  (self-inverse)
    -------------------------------------------------
    Encrypt = Decrypt: maps each Turkish letter to its mirror position.
        index i  →  len(TURKISH_ALPHA) − 1 − i
        'A' (idx 0) ↔ 'Z' (last idx),  'B' ↔ 'Y',  etc.

    Applying it twice returns the original.
    Non-TURKISH_ALPHA characters pass through UNCHANGED (R3).

    Why it's here: zero-key substitution layer.  Without knowing the Turkish
    alphabet ordering (Ç, Ğ, İ, Ö, Ş, Ü positions), an attacker cannot
    reverse this step.  Prerequisite: input uppercase (R6).
    """
    result = []
    for c in text:
        if c in TURKISH_ALPHA:
            result.append(TURKISH_ALPHA[len(TURKISH_ALPHA) - 1 - TURKISH_ALPHA.index(c)])
        else:
            result.append(c)
    return "".join(result)


def op_unicode_shift(text: str, encrypt: bool, **_) -> str:
    """
    UNICODE CODEPOINT SHIFT  (+5 encrypt / −5 decrypt)
    ---------------------------------------------------
    Encrypt: add 5 to every character's Unicode codepoint, wrapping at 256.
        ord('0') = 48 → 53 = '5'
        ord('A') = 65 → 70 = 'F'
    Decrypt: subtract 5 (mod 256).

    Chain position constraint (R4): this op MUST NOT be placed BEFORE
    op_atbash_tr or op_vigenere_tr in the same chain when Turkish-alphabet
    characters may be present in the stream.  (+5 mod 256) on a Turkish char
    like 'Ğ' produces a codepoint not in TURKISH_ALPHA, which those ops then
    pass through unchanged — breaking the round-trip.

    Safe positions: immediately after op_hex or op_base64 (whose outputs are
    guaranteed non-Turkish), or as the final substitution when no Turkish-alpha
    ops follow.

    Why it's here: shifts hex digits (0-9, A-F) out of their recognisable
    range so the intermediate output no longer looks like hex encoding.

    Safety net: Turkish letters like 'İ' (U+0130=304) and 'Ğ' (U+011E=286)
    have codepoints > 255. Applying (+5 mod 256) to them is irreversible since
    (304+5)%256=53 but (53-5)=48 which is '0' not 'İ'. This op therefore SKIPS
    any character with ord(c) > 127. When placed after op_hex/op_base64 (pure
    7-bit ASCII) the skip never fires — it is a defensive guard only.
    """
    delta = 5 if encrypt else -5
    return "".join(
        chr((ord(c) + delta) % 256) if ord(c) <= 127 else c
        for c in text
    )


def op_sbox(text: str, encrypt: bool, **_) -> str:
    """
    S-BOX BYTE SUBSTITUTION
    -----------------------
    Encrypt: replace each character's ordinal with _SBOX[ordinal].
        'A' (65) → _SBOX[65]  (pseudo-random scrambled value)
    Decrypt: use the precomputed inverse _SBOX_INV.
        _SBOX_INV[_SBOX[65]] = 65  → 'A'

    The S-box is a fixed bijective permutation of 0–255, generated once from
    KOD8_KEY using Fisher-Yates at import time.  Every input byte maps to
    exactly one output byte — fully reversible.

    Why it's here: non-linear byte substitution.  The pseudo-random permutation
    destroys any algebraic relationship between input and output — the strongest
    single substitution primitive in KOD8.  Safe anywhere in chain.
    """
    # Skip chars with codepoint > 255 — their ord % 256 loses information
    # and the inverse cannot recover the original (e.g. İ=304, Ğ=286).
    table = _SBOX if encrypt else _SBOX_INV
    return "".join(
        chr(table[ord(c)]) if ord(c) <= 255 else c
        for c in text
    )


def op_rail_fence(text: str, encrypt: bool, rails: int = 3, **_) -> str:
    """
    RAIL FENCE TRANSPOSITION
    ------------------------
    Encrypt: write text in a zigzag across `rails` rails, read each rail
    left-to-right.

        "HELLOWORLD"  rails=3:
        Rail 0: H . . . O . . . L .   →  "HOL"
        Rail 1: . E . L . W . R . D   →  "ELWRD"
        Rail 2: . . L . . . O . . .   →  "LO"
        Cipher: "HOL" + "ELWRD" + "LO"  =  "HOLELWRDLO"

    Decrypt: reconstruct the zigzag pattern, slice ciphertext into per-rail
    segments by count, then re-interleave in zigzag order.

    Why it's here: positional transposition — characters keep their values
    but move to new positions.  Larger `rails` = more dispersed shuffle.
    Safe at any chain position — moves chars, does not change values.
    """
    n = len(text)
    if n == 0 or rails < 2:
        return text

    if encrypt:
        fence, rail, direction = [[] for _ in range(rails)], 0, 1
        for c in text:
            fence[rail].append(c)
            if rail == 0:             direction = 1
            elif rail == rails - 1:   direction = -1
            rail += direction
        return "".join("".join(r) for r in fence)

    # Decrypt: rebuild pattern then slice and re-interleave
    pattern, rail, direction = [], 0, 1
    for _ in range(n):
        pattern.append(rail)
        if rail == 0:             direction = 1
        elif rail == rails - 1:   direction = -1
        rail += direction

    counts   = [pattern.count(r) for r in range(rails)]
    segments, pos = [], 0
    for count in counts:
        segments.append(list(text[pos:pos + count]))
        pos += count

    indices, result = [0] * rails, []
    for r in pattern:
        result.append(segments[r][indices[r]])
        indices[r] += 1
    return "".join(result)


def op_block_rotate(text: str, encrypt: bool, n: int = 3, **_) -> str:
    """
    BLOCK ROTATION  (circular shift by N)
    --------------------------------------
    Encrypt: move the first N characters to the END.
        "ABCDEFGH"  n=3  →  "DEFGHABC"
    Decrypt: move the last N characters back to the FRONT.
        "DEFGHABC"  n=3  →  "ABCDEFGH"

    Why it's here: lightweight transposition — cheap to compute, ensures the
    first N plaintext chars never appear at the start of ciphertext.  `n` is
    fixed per CipherList.  Safe at any chain position.
    """
    if len(text) <= n:
        return text
    return (text[n:] + text[:n]) if encrypt else (text[-n:] + text[:-n])


def op_split_reverse(text: str, encrypt: bool, **_) -> str:
    """
    SPLIT + DOUBLE REVERSE  (self-inverse)
    ----------------------------------------
    Encrypt = Decrypt: split at midpoint, reverse each half, concatenate.

        "ABCDEFGH"  →  "ABCD" + "EFGH"  →  "DCBA" + "HGFE"  →  "DCBAHGFE"

    Applying twice restores original (self-inverse).

    Why it's here: positional scramble with no key dependency.  Harder to
    spot than a full reverse — both halves are independently inverted.
    Safe at any chain position — moves chars, does not change values.
    """
    mid = len(text) // 2
    return text[:mid][::-1] + text[mid:][::-1]


def op_full_reverse(text: str, encrypt: bool, **_) -> str:
    """
    FULL REVERSE  (self-inverse)
    ----------------------------
    Encrypt = Decrypt: reverse the entire string.
        "HELLO" → "OLLEH"  (same op applied again → "HELLO")

    Why it's here: cheap outer shell.  The first/last chars of plaintext
    become the last/first of ciphertext, defeating header/footer pattern
    recognition.  Safe at any chain position.
    """
    return text[::-1]


def op_columnar(text: str, encrypt: bool, cols: int = None, **_) -> str:
    """
    COLUMNAR TRANSPOSITION
    -----------------------
    Encrypt: write text row-by-row into a grid of `cols` columns, then
    read out column-by-column (left to right).

        "ATTACKATDAWN"  cols=4:
        Grid:  A T T A         Read cols:
               C K A T   →     "ACD" + "TKA" + "TAW" + "ATN"
               D A W N         =  "ACDTKATAWAT N"

    Decrypt: know `cols`, reconstruct column lengths, fill grid
    column-by-column with the ciphertext, read row-by-row.
    Padding (null bytes) fills the last row on encrypt and is stripped
    on decrypt.

    `cols` defaults to (sum of key digits mod 5) + 4  →  always 4–8.

    Why it's here: strong positional scramble for longer inputs — every
    character moves by its column index.  Destroys sequential structure
    (doc paragraphs, video frame headers).  Safe at any chain position.
    """
    if cols is None:
        cols = (sum(int(d) for d in KOD8_KEY) % 5) + 4   # 4–8 columns

    n = len(text)
    if n == 0:
        return text

    rows   = math.ceil(n / cols)
    padded = text + "\x00" * (rows * cols - n)

    if encrypt:
        grid = [padded[i * cols:(i + 1) * cols] for i in range(rows)]
        return "".join("".join(grid[r][c] for r in range(rows)) for c in range(cols))

    # Decrypt: determine per-column lengths, slice, re-read row-by-row
    full_cols   = n % cols or cols
    col_lengths = [rows if c < full_cols else rows - 1 for c in range(cols)]
    segments, pos = [], 0
    for length in col_lengths:
        segments.append(list(text[pos:pos + length]))
        pos += length

    result = []
    for r in range(rows):
        for c in range(cols):
            if r < len(segments[c]):
                ch = segments[c][r]
                if ch != "\x00":
                    result.append(ch)
    return "".join(result)


def op_block_shuffle(text: str, encrypt: bool, block_size: int = 8, **_) -> str:
    """
    BLOCK SHUFFLE  (key-derived permutation)
    -----------------------------------------
    Encrypt: divide the string into blocks of `block_size` chars, reorder
    blocks by a permutation derived from KOD8_KEY.

        Key digits "86247931" → raw positions [8,6,2,4,7,9,3,1].
        Reduce mod num_blocks, deduplicate (first-seen), fill remaining
        indices in ascending order to complete the permutation.

    Decrypt: compute the inverse permutation and reorder back.

    Last block null-padded to `block_size` if needed; padding stripped on
    decrypt.

    Why it's here: block-level transposition — moves entire 8-char chunks,
    destroying file-format structure that spans large byte ranges (JPEG
    headers, PDF cross-reference tables).  Safe at any chain position.
    """
    if not text:
        return text

    pad    = (-len(text)) % block_size
    padded = text + "\x00" * pad
    blocks = [padded[i:i + block_size] for i in range(0, len(padded), block_size)]
    n      = len(blocks)

    raw  = [int(d) % n for d in KOD8_KEY]
    seen, perm = set(), []
    for v in raw:
        if v not in seen:
            perm.append(v); seen.add(v)
    for i in range(n):
        if i not in seen:
            perm.append(i)

    if encrypt:
        result_blocks = [blocks[perm[i]] for i in range(n)]
    else:
        inv = [0] * n
        for i, p in enumerate(perm):
            inv[p] = i
        result_blocks = [blocks[inv[i]] for i in range(n)]

    result = "".join(result_blocks)
    return result.rstrip("\x00") if not encrypt else result


def op_block_xor_cbc(text: str, encrypt: bool, block_size: int = 8, **_) -> str:
    """
    BLOCK XOR CASCADE  (CBC-mode inspired)
    ----------------------------------------
    Encrypt: divide into blocks of `block_size` chars, XOR each block with
    the PREVIOUS ENCRYPTED block before storing.

        IV  = KOD8_KEY repeated/truncated to `block_size`  →  "86247931"
        B0' = XOR(B0, IV)
        B1' = XOR(B1, B0')   ← chain on previous CIPHERTEXT block
        B2' = XOR(B2, B1')  …

    Decrypt: XOR each ciphertext block with the previous ciphertext block
    (which is already known), going forward through the list:
        B0  = XOR(B0', IV)
        B1  = XOR(B1', B0')  …

    Why it's here: CBC-mode diffusion at block level.  A single changed
    character in block N corrupts all subsequent blocks — impossible to
    surgically modify one file section without corrupting the rest.
    Safe at any chain position — operates on ordinals only.
    """
    if not text:
        return text

    pad    = (-len(text)) % block_size
    padded = text + "\x00" * pad
    blocks = [padded[i:i + block_size] for i in range(0, len(padded), block_size)]
    iv     = (KOD8_KEY * ((block_size // len(KOD8_KEY)) + 1))[:block_size]

    def xor_str(a: str, b: str) -> str:
        return "".join(chr(ord(x) ^ ord(y)) for x, y in zip(a, b))

    result_blocks = []
    if encrypt:
        prev = iv
        for block in blocks:
            enc = xor_str(block, prev)
            result_blocks.append(enc)
            prev = enc
    else:
        prev = iv
        for block in blocks:
            result_blocks.append(xor_str(block, prev))
            prev = block           # chain on CIPHERTEXT block

    result = "".join(result_blocks)
    return result.rstrip("\x00") if not encrypt else result


def op_base36(text: str, encrypt: bool, **_) -> str:
    """
    BASE-36 DIGIT SUBSTITUTION
    ---------------------------
    Operates ONLY on digit characters (0-9); all other characters pass
    through UNCHANGED — the op is position-stable and fully reversible.

    Encrypt: map each digit to a base-36 symbol by adding the corresponding
    key digit and wrapping mod 36.
        BASE36 = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ"
        digit '7' at key_pos 0  →  shift = int('8') = 8
        new_val = (7 + 8) mod 36 = 15  →  BASE36[15] = 'F'

    Decrypt: for characters that are uppercase letters A-Z (produced by
    encrypt when new_val ≥ 10) — reverse the shift.  For characters that
    are still digits (new_val < 10) — also reverse the shift.
    key_pos increments only on transformed (digit) chars so the key schedule
    stays aligned between encrypt and decrypt.

    Why it's here: destroys decimal patterns FIRST.  JSON/CSV is full of
    numbers — making them unrecognisable before any other op defeats attempts
    to guess values from partial ciphertext.
    """
    # Encrypt: digits map to LOWERCASE base-36 symbols (0-9 then a-z).
    # Passthrough non-digits stay as-is (uppercase after R6 .upper()).
    # Decrypt: LOWERCASE chars are unambiguously former digits; uppercase = passthrough.
    BASE36 = "0123456789abcdefghijklmnopqrstuvwxyz"
    result, key_pos = [], 0

    if encrypt:
        for c in text:
            if c.isdigit():
                new_val = (int(c) + int(KOD8_KEY[key_pos % len(KOD8_KEY)])) % 36
                result.append(BASE36[new_val])   # lowercase output → unambiguous on decrypt
                key_pos += 1
            else:
                result.append(c)                 # non-digits pass through unchanged
    else:
        for c in text:
            if c.islower():
                # Lowercase letter = was a digit, transformed by encrypt
                orig = (BASE36.index(c) - int(KOD8_KEY[key_pos % len(KOD8_KEY)])) % 36
                result.append(str(orig) if orig < 10 else BASE36[orig])
                key_pos += 1
            elif c.isdigit():
                # Digit that stayed a digit after the modular shift
                orig = (int(c) - int(KOD8_KEY[key_pos % len(KOD8_KEY)])) % 36
                result.append(str(orig) if orig < 10 else BASE36[orig])
                key_pos += 1
            else:
                result.append(c)                 # non-digit, non-lowercase → passthrough
    return "".join(result)


# =============================================================================
# AUTO-DETECTION HELPERS
# =============================================================================

def _detect_image(t: str) -> bool:
    """Detect Base64-encoded image by magic-byte prefix."""
    return any(t.startswith(p) for p in (
        "iVBORw0KGgo", "/9j/", "UklGR", "R0lGOD", "Qk0"))

def _detect_video(t: str) -> bool:
    """Detect Base64-encoded video by magic-byte prefix."""
    return any(t.startswith(p) for p in ("AAAB", "GkXf", "AAAA"))

def _detect_document(t: str) -> bool:
    """PDF/DOCX Base64 prefix, or long prose."""
    if t.startswith("JVBERi0") or t.startswith("PK"):
        return True
    words = t.split()
    return len(words) > 20 and sum(c.isalpha() for c in t) / max(len(t), 1) > 0.5

def _detect_numeric(t: str) -> bool:
    """High ratio of digits/data-punctuation or JSON/CSV start token."""
    ratio = sum(c.isdigit() or c in ".,+-eE[]{}:" for c in t) / max(len(t), 1)
    return ratio > 0.45 or t.lstrip().startswith(("{", "["))

def _detect_text(t: str) -> bool:
    """Plain printable text that isn't mostly digits."""
    if not t:
        return False
    return (sum(c.isprintable() for c in t) / max(len(t), 1) > 0.85 and
            sum(c.isdigit()     for c in t) / max(len(t), 1) < 0.6)


def auto_detect(text: str) -> str:
    """
    AUTO-DETECT CIPHER LIST
    ------------------------
    Runs each detector in priority order; returns the first matching ID.
    Priority: image > video > document > numeric > plain text > experimental.

    The caller MUST store the returned cipher_id alongside the ciphertext —
    it is required for decryption and cannot be recovered from the ciphertext.
    """
    for cid, check in [
        ("CL2", _detect_image),
        ("CL3", _detect_video),
        ("CL4", _detect_document),
        ("CL5", _detect_numeric),
        ("CL1", _detect_text),
    ]:
        if check(text):
            return cid
    return "CL6"


# =============================================================================
# CIPHER LISTS
# =============================================================================
#
# Each "steps" list is the ENCRYPT order.
# Decryption = iterate steps in REVERSE order, call each with encrypt=False.
#
# Chain diagrams:  →  = encrypt direction
# Safety annotations reference R1-R6 from the header.
#
# =============================================================================

CIPHER_LISTS = {

    # ── CL-1 : Plain text ────────────────────────────────────────────────────
    # Substitution-heavy.  Turkish-aware ops (vigenere, atbash) come BEFORE
    # unicode_shift (R4).  unicode_shift is the penultimate step, applied after
    # all Turkish-alpha ops have run.
    #
    # Encrypt chain:
    #   hex → xor_key → vigenere_tr → rail_fence(3)
    #   → atbash_tr → block_rotate(3) → unicode_shift → full_reverse
    "CL1": {
        "name":    "Plain text — Turkish / Latin",
        "trigger": "text input",
        "detect":  _detect_text,
        "steps": [
            (op_hex,          {}),            # UTF-8 → hex  (R1: output = 0-9, A-F)
            (op_xor_key,      {}),            # XOR every char with key byte 8
            (op_vigenere_tr,  {}),            # polyalpha shift on TURKISH_ALPHA chars
            (op_rail_fence,   {"rails": 3}),  # 3-rail zigzag positional scatter
            (op_atbash_tr,    {}),            # mirror-invert TURKISH_ALPHA chars
            (op_block_rotate, {"n": 3}),      # circular 3-char shift
            (op_unicode_shift,{}),            # +5 codepoint shift (R4: after all TK ops)
            (op_full_reverse, {}),            # reverse entire string — outer shell
        ],
    },

    # ── CL-2 : Image files ───────────────────────────────────────────────────
    # Binary-safe ops first, then two layered encoding passes at the end.
    # No Turkish-alphabet ops — image binary never contains Turkish letters.
    #
    # Encrypt chain:
    #   base64 → sbox → rolling_xor → block_shuffle
    #   → xor_key → split_reverse → hex → unicode_shift
    "CL2": {
        "name":    "Image files — PNG, JPG, WebP",
        "trigger": "file input",
        "detect":  _detect_image,
        "steps": [
            (op_base64,       {}),            # binary → base64 ASCII  (R2)
            (op_sbox,         {}),            # non-linear bijective byte permutation
            (op_rolling_xor,  {}),            # CBC-byte diffusion
            (op_block_shuffle,{}),            # reorder 8-char blocks by key permutation
            (op_xor_key,      {}),            # symmetric XOR with key byte
            (op_split_reverse,{}),            # split-and-reverse both halves
            (op_hex,          {}),            # second encoding layer → hex  (R1)
            (op_unicode_shift,{}),            # +5 shift on hex chars  (R4: no TK ops after)
        ],
    },

    # ── CL-3 : Video files ───────────────────────────────────────────────────
    # Stream-XOR heavy — two XOR passes to handle long repeating frame patterns.
    # No Turkish-alphabet ops.  Block-XOR-CBC provides cross-block diffusion.
    #
    # Encrypt chain:
    #   base64 → keystream_xor → block_xor_cbc → block_shuffle
    #   → rolling_xor → rail_fence(4) → split_reverse → full_reverse
    "CL3": {
        "name":    "Video files — MP4, MKV, AVI",
        "trigger": "file input",
        "detect":  _detect_video,
        "steps": [
            (op_base64,        {}),           # binary → base64 ASCII  (R2)
            (op_keystream_xor, {}),           # LCG stream XOR — unique byte per position
            (op_block_xor_cbc, {}),           # CBC block diffusion
            (op_block_shuffle, {}),           # chunk reorder by key permutation
            (op_rolling_xor,   {}),           # CBC-byte diffusion second pass
            (op_rail_fence,    {"rails": 4}), # 4-rail zigzag scatter
            (op_split_reverse, {}),           # split-and-reverse both halves
            (op_full_reverse,  {}),           # full reversal outer shell
        ],
    },

    # ── CL-4 : Document files ────────────────────────────────────────────────
    # Structure-breaking ops first (columnar after hex).  Both Turkish-aware
    # subs (vigenere then atbash) run before any potential unicode_shift would
    # — but CL4 omits unicode_shift entirely to keep the chain clean.
    #
    # Encrypt chain:
    #   hex → columnar → vigenere_tr → rail_fence(5)
    #   → block_shuffle → xor_key → atbash_tr → split_reverse
    "CL4": {
        "name":    "Documents — PDF, DOCX, TXT",
        "trigger": "file input",
        "detect":  _detect_document,
        "steps": [
            (op_hex,          {}),            # UTF-8/binary → hex  (R1)
            (op_columnar,     {}),            # grid-column read destroys doc structure
            (op_vigenere_tr,  {}),            # polyalpha shift on A-F hex chars
            (op_rail_fence,   {"rails": 5}),  # 5-rail deep positional scatter
            (op_block_shuffle,{}),            # 8-char chunk reorder
            (op_xor_key,      {}),            # symmetric XOR
            (op_atbash_tr,    {}),            # mirror sub  (R4: no unicode_shift in CL4)
            (op_split_reverse,{}),            # split-and-reverse outer shell
        ],
    },

    # ── CL-5 : Numeric / data ────────────────────────────────────────────────
    # base36 FIRST to eliminate all recognisable digit patterns before any
    # other op.  Then hex to normalise, then substitution + XOR layers.
    # No atbash/vigenere after sbox (sbox output may include arbitrary chars
    # that don't belong to TURKISH_ALPHA — those just pass through, but
    # keeping the chain clean here avoids any ambiguity).
    #
    # Encrypt chain:
    #   base36 → hex → vigenere_tr → block_rotate(3)
    #   → sbox → keystream_xor → block_shuffle → full_reverse
    "CL5": {
        "name":    "Numeric / data — JSON, CSV, coords",
        "trigger": "text / file input",
        "detect":  _detect_numeric,
        "steps": [
            (op_base36,        {}),           # digit → base-36 symbol (destroys decimal)
            (op_hex,           {}),           # mixed alpha → pure hex  (R1)
            (op_vigenere_tr,   {}),           # polyalpha shift on A-F hex chars
            (op_block_rotate,  {"n": 3}),     # circular 3-char shift
            (op_sbox,          {}),           # non-linear byte permutation
            (op_keystream_xor, {}),           # LCG stream XOR
            (op_block_shuffle, {}),           # 8-char chunk reorder
            (op_full_reverse,  {}),           # full reversal outer shell
        ],
    },

    # ── CL-6 : Experimental ──────────────────────────────────────────────────
    # Maximum obfuscation.  All 8 ops are from distinct primitive families.
    # hex first (R1) normalises ANY input, then sbox (strongest sub) innermost,
    # then CBC diffusion, then structural scramble, then XOR, then Turkish mirror,
    # then full reverse outer.  No unicode_shift — sbox already covers that.
    #
    # Encrypt chain:
    #   hex → sbox → block_xor_cbc → columnar
    #   → block_shuffle → keystream_xor → atbash_tr → full_reverse
    "CL6": {
        "name":    "Experimental — unknown / mixed",
        "trigger": "experimental input",
        "detect":  lambda t: True,            # fallback — matches anything
        "steps": [
            (op_hex,           {}),           # normalise ANY input to hex  (R1)
            (op_sbox,          {}),           # non-linear byte permutation (innermost)
            (op_block_xor_cbc, {}),           # CBC-block diffusion
            (op_columnar,      {}),           # structural grid scramble
            (op_block_shuffle, {}),           # 8-char chunk reorder
            (op_keystream_xor, {}),           # LCG stream XOR
            (op_atbash_tr,     {}),           # mirror sub on any TK-alpha chars present
            (op_full_reverse,  {}),           # full reversal outer shell
        ],
    },
}


# =============================================================================
# KOD 8 ENGINE — PUBLIC API
# =============================================================================

class Kod8:
    def __init__(self, cipher_id: str = None):
        """
        cipher_id : one of "CL1"–"CL6", or None for auto-detection.
        When None the cipher is selected by analysing the input at encrypt
        time.  The chosen ID is returned with the ciphertext and MUST be
        supplied to decrypt().
        """
        self.cipher_id = cipher_id

    def encrypt(self, plaintext: str) -> tuple[str, str]:
        """
        Encrypt plaintext.  Returns (ciphertext, cipher_id_used).
        Store cipher_id_used — required for decryption.
        """
        cid    = self.cipher_id or auto_detect(plaintext)
        result = plaintext.upper()       # R6: normalise to uppercase
        for fn, kw in CIPHER_LISTS[cid]["steps"]:
            result = fn(result, encrypt=True, **kw)
        return result, cid

    def decrypt(self, ciphertext: str, cipher_id: str) -> str:
        """
        Decrypt ciphertext by running the CipherList in REVERSE ORDER,
        each step called with encrypt=False.
        cipher_id must match the one used during encryption.
        """
        result = ciphertext
        for fn, kw in reversed(CIPHER_LISTS[cipher_id]["steps"]):
            result = fn(result, encrypt=False, **kw)
        return result


# =============================================================================
# DEMO / SELF-TEST
# =============================================================================
if __name__ == "__main__":
    print("=" * 68)
    print("  KOD 8 ENGINE v2.0 — SELF-TEST")
    print("=" * 68)

    tests = [
        ("dream case",                                   "CL1"),
        ("Merhaba Dünya şifreleme testi",                "CL1"),
        ("HELLO WORLD TEST 123",                         "CL1"),
        ("37.8749 N, 32.4932 E",                         "CL5"),
        ("{\"user\": \"alice\", \"score\": 9823}",       "CL5"),
        ("1,2,3,4,5,6,7,8,9,0",                         "CL5"),
        ("This is a long document sentence. " * 3,       "CL4"),
        ("EXPERIMENTAL UNKNOWN DATA XYZ 999",            "CL6"),
        # auto-detect
        ("auto detect this sentence please",             None),
        ("99,88,77,66,55,44",                            None),
    ]

    all_pass = True
    for plaintext, force_cid in tests:
        engine    = Kod8(cipher_id=force_cid)
        enc, cid  = engine.encrypt(plaintext)
        dec       = engine.decrypt(enc, cid)
        expected  = plaintext.upper()
        match     = dec.strip("\x00") == expected.strip("\x00")
        if not match:
            all_pass = False
        tag = "✓" if match else "✗"
        print(f"\n  {tag} [{cid}] {CIPHER_LISTS[cid]['name']}")
        print(f"    Input     : {plaintext[:62]}")
        print(f"    Encrypted : {enc[:62]}{'…' if len(enc) > 62 else ''}")
        print(f"    Decrypted : {dec[:62]}")

    print("\n" + "=" * 68)
    print(f"  {'ALL TESTS PASSED ✓' if all_pass else 'SOME TESTS FAILED ✗'}")
    print("=" * 68)
