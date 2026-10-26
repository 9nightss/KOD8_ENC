# KOD8_ENC (v2.1)

KOD 8 is a multi-layered cryptographic obfuscation and pipeline engine designed for structured data protection. Unlike standard single-algorithm ciphers, KOD 8 utilizes a Strategic Chain Architecture, routing input through one of eight specialized CipherLists, each composing exactly eight reversible node transformations driven by a byte-level master key (`86247931`).

## Key Features

* **Strategic Auto-Detection:** Automatically inspects input headers and character sets to select the optimal cipher list (`CL1` through `CL8`).
* **8-Round Pipeline Logic:** Every payload passes through exactly 8 transformation nodes. Decryption is achieved by running the identical chain in precise reverse order.
* **Robust Turkish Special Character Support:** Features reversible character normalization (`op_turkish_normalize`) using an escape sequence architecture (`~`) to safely handle Turkish diacritics (`ç, ğ, ı, ö, ş, ü, Ç, Ğ, İ, Ö, Ş, Ü`).
* **Zero-Dependency GUI:** Built using Python's standard `tkinter` library with high-DPI scaling support.
* **Strict Validation & Error Handling:** Validates base64 encoding and UTF-8 integrity during decryption to fail loudly on wrong keys or malformed ciphertexts rather than returning silent garbage.

---

## Architecture & Cipher Strategies

The system consists of two primary modules:
1. `kod8_engine.py`: The cryptographic core containing byte-level stream/block operations, node wrappers, and the 8 defined CipherLists (`CL1`–`CL8`).
2. `kod8_ui.py`: The desktop control interface providing real-time step verification, binary file handling, and rounded UI components.

### The 8 Cipher Lists

| ID | Name | Targeted Data | Primary Focus |
| :--- | :--- | :--- | :--- |
| **CL1** | ASCII Plain Text | Standard prose / ASCII | ML-KEM/Rocca-S stream diffusion & block splitting |
| **CL2** | Numeric Strings | Numbers, GPS, counters | BLAKE3 prep, GF(2^8) field mod & base-36 pack |
| **CL3** | Document Files | PDF, DOCX, TXT | Stream-heavy cascade & base-36 transposition |
| **CL4** | Image Data | PNG, JPG, WebP | Dynamic block split & multi-stream XOR permutation |
| **CL5** | Video Data | MP4, MKV, AVI | Galois field multiplication & prime affine shifts |
| **CL6** | Fallback Engine 1 | Mixed / General binary | Combined BLAKE3, Rocca-S, and Affine transforms |
| **CL7** | Fallback Engine 2 | Alternate binary | ML-KEM encapsulation & Galois modulation |
| **CL8** | Turkish Special Chars | Turkish language text | Reversible escape-map normalization + stream diffusion |

---

## Pipeline Node Operations

KOD 8 utilizes 13 distinct modular transformation nodes across 6 functional families:

* **Key-Derived / Hashing Streams:** `op_mlkem_encap` (SHA-256), `op_blake3_seed_prep` (BLAKE2b/BLAKE3), `op_rocca_s_stream` (SHA-512), `op_aegis256x` (SHA-256 + salt), `op_ascon128_sponge` (MD5).
* **Mathematical & Field Modulation:** `op_galois_field_mult` (Mod-256 multiplication with odd inversion), `op_prime_affine_transform` (mod-256 affine shift).
* **Positional & Block Transposition:** `op_dynamic_split` (inter-block positional split), `op_full_reverse` (terminal script reversal).
* **Substitution & Shifting:** `op_base36_pack` (+36 shift), `op_vigornian_sub` (+7 shift), `op_glevian_block` (`\xAA` XOR matrix mutation).
* **Normalization:** `op_turkish_normalize` (escaped diacritic mapping).

---

## Getting Started & Usage

### Prerequisites
* Python 3.8 or higher (No external dependencies required).

### Running the UI
1. Place `kod8_engine.py` and `kod8_ui.py` in the same directory.
2. Execute the desktop interface:
   ```bash
   python kod8_ui.py
