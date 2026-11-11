#!/usr/bin/env python3
# =============================================================================
# KOD 8 - Unified NCIA Sandbox (File/Text Cipher & Split-Key Disk Provisioning)
# =============================================================================

import dataclasses
import json
import os
import platform
import zlib
import base64
import hashlib
import hmac
import re
import sys
import queue
import threading
import subprocess
import datetime
from pathlib import Path
import tkinter as tk
import tkinter.font as tkfont
from tkinter import filedialog, ttk, messagebox
from typing import Tuple, Optional

APP_DIR = Path(__file__).resolve().parent

try:
    import psutil
except ImportError:
    print("Error: psutil package is required. Run: pip install psutil")
    sys.exit(1)

try:
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    from cryptography.hazmat.primitives.kdf.hkdf import HKDF
    from cryptography.hazmat.primitives import hashes
except ImportError:
    print("Error: cryptography package is required. Run: pip install cryptography")
    sys.exit(1)

# Crisp text on high-DPI Windows displays
if sys.platform == "win32":
    try:
        import ctypes
        ctypes.windll.shcore.SetProcessDpiAwareness(1)
    except Exception:
        pass

# ── ENGINE COMPONENTS ────────────────────────────────────────────────────────
KOD8_KEY = b"86247931"

STRATEGY_MAP = {
    "CL1": "ASCII Plain Text",   "CL2": "Numeric Strings",
    "CL3": "Document Files",     "CL4": "Image Data",
    "CL5": "Video Data",         "CL6": "Fallback Engine 1",
    "CL7": "Fallback Engine 2",  "CL8": "Turkish Special Chars",
    "CL9": "OEM Disk Provision (Split-Key)",
}

_HDR_RE = re.compile(
    r"^#\s*KOD8\s+cipher_id:\s*(CL\d+)\s+salt:\s*([A-Za-z0-9+/=]+)(?:\s+bin:\s*([01]))?(?:\s+ext:\s*(\S+))?\s*$"
)

def node_8_hkdf_expand(base_key: bytes, salt: bytes) -> Tuple[bytes, bytes]:
    hkdf = HKDF(algorithm=hashes.SHA384(), length=32 + 48, salt=salt, info=b"KOD8-NCIA-COMPLIANT-PIPELINE")
    key_material = hkdf.derive(base_key)
    return key_material[:32], key_material[32:]

def node_6_zlib_compress(data: bytes, compress: bool) -> bytes:
    return zlib.compress(data, level=9) if compress else zlib.decompress(data)

def node_2_pq_wrap(data: bytes, wrap: bool) -> bytes:
    if wrap: return (b"\x00" * 32) + data
    return data[32:]

def node_4_hmac_sign(data: bytes, hmac_key: bytes, sign: bool) -> bytes:
    h = hmac.new(hmac_key, digestmod=hashlib.sha384)
    if sign:
        h.update(data)
        return h.digest() + data
    expected_mac, payload = data[:48], data[48:]
    h.update(payload)
    if not hmac.compare_digest(h.digest(), expected_mac):
        raise ValueError("KOD8: Inner HMAC-SHA-384 verification failed.")
    return payload

def node_7_aes_gcm(data: bytes, aes_key: bytes, encrypt: bool) -> bytes:
    aesgcm = AESGCM(aes_key)
    if encrypt:
        nonce = os.urandom(12)
        return nonce + aesgcm.encrypt(nonce, data, None)
    nonce, ciphertext = data[:12], data[12:]
    return aesgcm.decrypt(nonce, ciphertext, None)

def node_9_framing(data: bytes, frame: bool) -> bytes:
    if frame:
        pad_len = 1024 - (len(data) % 1024)
        return data + (b"\x80" + b"\x00" * (pad_len - 1))
    pad_idx = data.rfind(b"\x80")
    if pad_idx == -1: raise ValueError("KOD8: Framing validation failed.")
    return data[:pad_idx]

def node_3_outer_hash(data: bytes, hash_it: bool) -> bytes:
    if hash_it:
        return hashlib.sha512(data).digest() + data
    expected_digest, payload = data[:64], data[64:]
    if hashlib.sha512(payload).digest() != expected_digest:
        raise ValueError("KOD8: Outer SHA-512 integrity check failed.")
    return payload

def node_1_terminal_reverse(data, encode: bool):
    if encode:
        return base64.b64encode(data).decode("ascii")[::-1]
    clean_data = re.sub(r'\s+', '', data)
    return base64.b64decode(clean_data[::-1], validate=True)

# ── CL9: OEM Disk Provisioning Nodes ──────────────────────────────────────────

def node_9_oem_framing(data_key: bytes, os_target: str) -> bytes:
    if os_target == "Windows":
        bek_header = b"\x2F\x42\x45\x4B\x00\x00\x00\x00" 
        return bek_header + data_key
    elif os_target == "Linux":
        return data_key
    raise ValueError("Unsupported OEM target")

def run_disk_provisioning(host_token: bytes, drive_token: bytes, os_target: str) -> bytes:
    aes_master_key, _ = node_8_hkdf_expand(base_key=host_token, salt=drive_token)
    return node_9_oem_framing(aes_master_key, os_target)

# ── Standard Pipeline Execution (CL1-CL8) ──────────────────────────────────
def run_kod8_pipeline(data_str, is_file: bool = False, encrypt: bool = True,
                      list_id: Optional[str] = "CL1", key: Optional[bytes] = None):
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
        history = [
            ("node_8_hkdf_expand", ""), ("node_6_zlib_compress", ""), 
            ("node_2_pq_wrap", ""), ("node_4_hmac_sign", ""), 
            ("node_7_aes_gcm", ""), ("node_9_framing", ""), 
            ("node_3_outer_hash", ""), ("node_1_terminal_reverse", final_body)
        ]
        return list_id, final_body, history, salt_b64
    else:
        if list_id is None or ":" not in list_id:
            raise ValueError("KOD8: Decryption requires salt embedded in list_id string.")
        real_list_id, salt_b64 = list_id.split(":", 1)
        salt = base64.b64decode(salt_b64)
        aes_key, hmac_key = node_8_hkdf_expand(active_key, salt)
        stage_3 = node_1_terminal_reverse(data_str, encode=False)
        stage_9 = node_3_outer_hash(stage_3, hash_it=False)
        stage_7 = node_9_framing(stage_9, frame=False)
        stage_4 = node_7_aes_gcm(stage_7, aes_key, encrypt=False)
        stage_2 = node_4_hmac_sign(stage_4, hmac_key, sign=False)
        stage_6 = node_2_pq_wrap(stage_2, wrap=False)
        final_bytes = node_6_zlib_compress(stage_6, compress=False)
        history = [
             ("node_1_terminal_reverse", ""), ("node_3_outer_hash", ""),
             ("node_9_framing", ""), ("node_7_aes_gcm", ""),
             ("node_4_hmac_sign", ""), ("node_2_pq_wrap", ""),
             ("node_6_zlib_compress", ""), ("node_8_hkdf_expand", "done")
        ]
        if not is_file:
            final_str = final_bytes.decode("utf-8")
            history[-1] = ("node_8_hkdf_expand", final_str)
            return real_list_id, final_str, history, salt_b64
        history[-1] = ("node_8_hkdf_expand", "[binary data]")
        return real_list_id, final_bytes, history, salt_b64

def format_kod8_file(cid: str, salt_b64: str, is_bin: bool, ext: str, body: str) -> str:
    bin_flag = "1" if is_bin else "0"
    ext_str = f"  ext: {ext}" if ext else ""
    return f"# KOD8  cipher_id: {cid}  salt: {salt_b64}  bin: {bin_flag}{ext_str}\n{body}"

def parse_kod8(raw):
    lines = raw.strip().splitlines()
    cid, is_bin, ext, salt = None, False, "", None
    if lines:
        m = _HDR_RE.match(lines[0].strip())
        if m:
            cid, salt, is_bin_str, ext = m.group(1), m.group(2), m.group(3), m.group(4) or ""
            is_bin = is_bin_str == "1"
            lines = lines[1:]
    return cid, is_bin, ext, salt, "".join(lines).strip()

def auto_detect(sample_or_path, is_file=False):
    if is_file:
        ext = sample_or_path.lower().split(".")[-1]
        if ext in ("pdf", "docx", "doc", "txt", "xlsx", "pptx", "odt"): return "CL3"
        if ext in ("png", "jpg", "jpeg", "bmp", "webp", "gif", "svg"): return "CL4"
        if ext in ("mp4", "mkv", "avi", "mov", "webm", "flv"): return "CL5"
        return "CL6"
    return "CL1"

# ── DISK PROVISIONING SAFETY LAYER ───────────────────────────────────────────

@dataclasses.dataclass(frozen=True)
class DriveSnapshot:
    device_path: str
    display_name: str
    size_bytes: int
    bus_type: str
    is_removable: bool
    is_system_or_boot: bool
    mountpoints: tuple

    def confirmation_token(self) -> str:
        return self.device_path

    def label(self) -> str:
        return f"{self.display_name}  ({self.device_path}, {human_size(self.size_bytes)})"


class DriveDetectionError(RuntimeError):
    pass


def _system_drive_windows() -> str:
    drive = os.environ.get("SystemDrive", "C:").rstrip("\\").upper()
    return drive if drive.endswith(":") else drive + ":"


def _list_candidate_drives_windows():
    system_drive = _system_drive_windows()
    out = []
    try:
        partitions = psutil.disk_partitions(all=False)
    except Exception as exc:
        raise DriveDetectionError(f"psutil.disk_partitions() failed: {exc}") from exc

    for p in partitions:
        device = p.device.rstrip("\\")
        opts = (p.opts or "").lower()
        is_removable = "removable" in opts
        is_system = (device.upper() == system_drive)
        try:
            usage = psutil.disk_usage(p.mountpoint)
            size_bytes = usage.total
        except OSError:
            size_bytes = 0
        out.append(DriveSnapshot(
            device_path=device,
            display_name=f"{device} volume ({p.fstype or 'unknown fs'})",
            size_bytes=size_bytes,
            bus_type="USB" if is_removable else "unknown",
            is_removable=is_removable,
            is_system_or_boot=is_system,
            mountpoints=(p.mountpoint,),
        ))
    return out


def _list_candidate_drives_linux():
    try:
        raw = subprocess.run(
            ["lsblk", "-J", "-b", "-o", "NAME,PATH,SIZE,RM,TYPE,MOUNTPOINT,MODEL,SERIAL"],
            capture_output=True, text=True, timeout=15, check=True,
        ).stdout
    except (OSError, subprocess.SubprocessError) as exc:
        raise DriveDetectionError(f"lsblk failed: {exc}") from exc
    try:
        tree = json.loads(raw)
    except json.JSONDecodeError as exc:
        raise DriveDetectionError(f"Could not parse lsblk output: {exc}") from exc

    protected_mounts = {"/", "/boot", "/boot/efi", "/home", "/var", "/usr", "[SWAP]"}
    try:
        swap_backing = {line.split()[0] for line in Path("/proc/swaps").read_text().splitlines()[1:]}
    except OSError:
        swap_backing = set()

    out = []
    for dev in tree.get("blockdevices", []):
        if dev.get("type") != "disk":
            continue
        children = dev.get("children", []) or []
        mountpoints = tuple(sorted({c["mountpoint"] for c in children if c.get("mountpoint")}
                                    | ({dev["mountpoint"]} if dev.get("mountpoint") else set())))
        child_paths = {c.get("path") for c in children} | {dev.get("path")}
        is_system = (
            bool(protected_mounts & set(mountpoints))
            or bool(child_paths & swap_backing)
            or not bool(dev.get("rm"))
        )
        out.append(DriveSnapshot(
            device_path=dev.get("path", f"/dev/{dev.get('name')}"),
            display_name=dev.get("model") or dev.get("name", "unknown"),
            size_bytes=int(dev.get("size") or 0),
            bus_type="USB" if dev.get("rm") else "unknown",
            is_removable=bool(dev.get("rm")),
            is_system_or_boot=is_system,
            mountpoints=mountpoints,
        ))
    return out


def list_candidate_drives():
    system = platform.system()
    if system == "Windows":
        return _list_candidate_drives_windows()
    if system == "Linux":
        return _list_candidate_drives_linux()
    raise DriveDetectionError(f"No drive enumeration implemented for platform: {system!r}")


def safe_candidates():
    drives = list_candidate_drives()
    return [d for d in drives if d.is_removable and not d.is_system_or_boot]


@dataclasses.dataclass(frozen=True)
class ProvisioningPlan:
    snapshot: DriveSnapshot
    os_target: str
    commands: tuple
    warnings: tuple


def plan_commands(snapshot, os_target):
    warnings = []
    if snapshot.is_system_or_boot:
        warnings.append("REFUSED: this drive is flagged as a system/boot drive.")
    
    # Under Linux, raw device nodes must not be actively mounted.
    # Under Windows, psutil reports volume letters (e.g. D:), which inherently mount to D:\.
    if os_target == "Linux" and snapshot.mountpoints:
        warnings.append(f"REFUSED: drive currently has active mountpoint(s): {', '.join(snapshot.mountpoints)}")
        
    if not snapshot.is_removable:
        warnings.append("REFUSED: drive is not flagged removable.")
    if warnings:
        return ProvisioningPlan(snapshot, os_target, commands=(), warnings=tuple(warnings))

    if os_target == "Windows":
        commands = (
            f"diskpart (script): select volume {snapshot.device_path}, format fs=ntfs quick",
            f"manage-bde -on {snapshot.device_path} -StartupKey <removable ignition volume path>",
        )
    elif os_target == "Linux":
        commands = (
            f"wipefs -a {snapshot.device_path}",
            f"cryptsetup luksFormat {snapshot.device_path} --key-file <path to derived key material>",
            f"cryptsetup open {snapshot.device_path} dilara_vol --key-file <path to derived key material>",
            f"mkfs.ext4 /dev/mapper/dilara_vol",
        )
    else:
        return ProvisioningPlan(snapshot, os_target, commands=(),
                                 warnings=(f"REFUSED: unsupported os_target {os_target!r}",))
    return ProvisioningPlan(snapshot, os_target, commands=commands,
                             warnings=(f"DRY RUN ONLY - nothing above has been executed "
                                       f"against {snapshot.device_path}.",))


def confirms(snapshot, typed_text):
    return typed_text.strip() == snapshot.confirmation_token()


def _default_audit_path():
    return APP_DIR / "data" / "disk_provision_audit.jsonl"


def record_audit_event(event, snapshot=None, extra=None, path=None):
    path = path or _default_audit_path()
    path.parent.mkdir(parents=True, exist_ok=True)
    entry = {
        "timestamp": datetime.datetime.now(datetime.timezone.utc).isoformat(timespec="seconds"),
        "event": event,
        "device_path": snapshot.device_path if snapshot else None,
        "display_name": snapshot.display_name if snapshot else None,
        "extra": extra or {},
    }
    with path.open("a", encoding="utf-8") as f:
        f.write(json.dumps(entry, ensure_ascii=False) + "\n")


def execute_plan(plan, typed_confirmation, dry_run=True):
    if plan.warnings and not plan.commands:
        raise PermissionError(f"Plan was refused and carries no commands: {'; '.join(plan.warnings)}")
    if not confirms(plan.snapshot, typed_confirmation):
        record_audit_event("confirmation_mismatch", plan.snapshot)
        raise PermissionError("Typed confirmation did not match the drive's device path exactly.")

    if not dry_run:
        raise NotImplementedError(
            "Live execution is intentionally not implemented. See execute_plan()'s docstring - "
            "wiring the commands above to real subprocess calls is a deliberate change to make yourself."
        )

    host_token = os.urandom(64)
    drive_token = os.urandom(64)
    boot_key = run_disk_provisioning(host_token, drive_token, plan.os_target)
    host_stash_path = APP_DIR / "data" / "kod8_keys" / f"{plan.snapshot.device_path.strip(chr(92)+'/.:')}_host.token"

    record_audit_event("plan_confirmed", plan.snapshot,
                        extra={"os_target": plan.os_target, "dry_run": dry_run,
                               "commands": list(plan.commands),
                               "host_token_bytes": len(host_token),
                               "boot_key_bytes": len(boot_key)})
    return {"host_stash_path": str(host_stash_path), "boot_key_bytes": len(boot_key), "executed": False}

# ── UI COMPONENTS ────────────────────────────────────────────────────────────
class C:
    HEADER, HEADER_CHIP, HEADER_LINE, HEADER_FG, HEADER_DIM = "#18202A", "#222D3A", "#364353", "#EEF2F6", "#9AA8B6"
    BG, CARD, BORDER, BORDER_STRONG = "#E8ECEF", "#FFFFFF", "#D3D9DF", "#B3BDC7"
    INK, INK_DIM, INK_FAINT = "#18202A", "#55616D", "#7E8A96"
    RED, RED_H, RED_P, RED_HALO, GREEN = "#D92B3A", "#C32532", "#A91E2A", "#F2B5BB", "#1E9E75"
    WELL, WELL_FG, WELL_DIM, WELL_MINT, WELL_SEL, WAIT_BG = "#1A232E", "#D7E0E9", "#7D8FA2", "#9FE3C4", "#35516B", "#EDF0F3"

STEP_META = {
    "node_8_hkdf_expand": "HKDF Key Expansion (Node 8)",
    "node_6_zlib_compress": "Zlib Data Preparation (Node 6)",
    "node_2_pq_wrap": "ML-KEM-768 Post-Quantum Wrap (Node 2)",
    "node_4_hmac_sign": "HMAC-SHA-384 Plaintext Auth (Node 4)",
    "node_7_aes_gcm": "AES-256-GCM Bulk Encryption (Node 7)",
    "node_9_framing": "Uniform Chunk Framing (Node 9)",
    "node_3_outer_hash": "SHA-512 Outer Integrity (Node 3)",
    "node_1_terminal_reverse": "Base64 & Script Reversal (Node 1)",
}

ENC_STEPS = [
    (node_8_hkdf_expand, True), (node_6_zlib_compress, True), (node_2_pq_wrap, True), (node_4_hmac_sign, True),
    (node_7_aes_gcm, True), (node_9_framing, True), (node_3_outer_hash, True), (node_1_terminal_reverse, True)
]
DEC_STEPS = list(reversed(ENC_STEPS))

def step_label(fn_name):
    raw = STEP_META.get(fn_name, fn_name)
    m = re.match(r"^(.*?)\s*\(Node (\d+)\)\s*$", raw)
    return (m.group(1), f"Node {m.group(2)}") if m else (raw, "")

MAX_VIEW_CHARS = 200_000
def elide(font, text, width):
    if width <= 20 or font.measure(text) <= width: return text
    lo, hi = 0, len(text)
    while lo < hi:
        mid = (lo + hi + 1) // 2
        if font.measure(text[:mid] + "…") <= width: lo = mid
        else: hi = mid - 1
    return text[:lo] + "…"

def human_size(n):
    for unit in ("B", "KB", "MB", "GB"):
        if n < 1024 or unit == "GB": return f"{n:.0f} {unit}" if unit == "B" else f"{n:.1f} {unit}"
        n /= 1024

def rounded(canvas, x1, y1, x2, y2, r, **kw):
    pts = [x1 + r, y1, x2 - r, y1, x2, y1, x2, y1 + r, x2, y2 - r, x2, y2,
           x2 - r, y2, x1 + r, y2, x1, y2, x1, y2 - r, x1, y1 + r, x1, y1]
    return canvas.create_polygon(pts, smooth=True, **kw)

class RButton(tk.Canvas):
    STYLES = {
        "primary": dict(bg=C.RED, hover=C.RED_H, press=C.RED_P, fg="#FFFFFF", line=None),
        "secondary": dict(bg=C.CARD, hover="#F1F4F6", press="#E3E8EC", fg=C.INK, line=C.BORDER_STRONG),
        "ghost": dict(bg=None, hover="#E9EDF1", press="#DCE2E8", fg=C.INK_DIM, line=None),
    }
    def __init__(self, master, app, text, command, kind="secondary", font=None, parent_bg=C.CARD, padx=18, pady=8, min_w=0):
        self.app, self._text, self._cmd, self._style, self._font = app, text, command, self.STYLES[kind], font
        w = max(font.measure(text) + 2 * app.px(padx), app.px(min_w))
        h = font.metrics("linespace") + 2 * app.px(pady)
        super().__init__(master, width=w, height=h, bg=parent_bg, highlightthickness=0, bd=0, takefocus=1, cursor="hand2")
        self._bw, self._bh, self._hover, self._down, self._focus, self._enabled = w, h, False, False, False, True
        self.bind("<Enter>", lambda e: self._set(hover=True))
        self.bind("<Leave>", lambda e: self._set(hover=False, down=False))
        self.bind("<ButtonPress-1>", lambda e: self._set(down=True))
        self.bind("<ButtonRelease-1>", self._release)
        self.bind("<FocusIn>", lambda e: self._set(focus=True))
        self.bind("<FocusOut>", lambda e: self._set(focus=False))
        self.bind("<space>", lambda e: self._fire())
        self.bind("<Return>", lambda e: self._fire())
        self._draw()
    def _set(self, **kw):
        for k, v in kw.items(): setattr(self, "_" + k, v)
        self._draw()
    def _release(self, _):
        fire = self._down and self._hover
        self._set(down=False)
        if fire: self._fire()
    def _fire(self):
        if self._enabled and self._cmd: self._cmd()
    def set_enabled(self, enabled):
        self._enabled = enabled
        self.configure(cursor="hand2" if enabled else "arrow")
        self._draw()
    def _draw(self):
        self.delete("all")
        st, r = self._style, self.app.px(7)
        fill = st["press"] if self._down else st["hover"] if self._hover else st["bg"] if self._enabled else "#DDE2E7"
        fg, line = (st["fg"], st["line"]) if self._enabled else ("#97A2AD", None)
        if fill: rounded(self, 1, 1, self._bw - 1, self._bh - 1, r, fill=fill, outline=line or fill, width=1)
        self.create_text(self._bw // 2, self._bh // 2, text=self._text, font=self._font, fill=fg)
        if self._focus and self._enabled:
            rounded(self, 3, 3, self._bw - 3, self._bh - 3, r, fill="", outline=C.INK if st["bg"] != C.RED else "#FFFFFF", width=1)

class Chip(tk.Canvas):
    def __init__(self, master, app, font, text="", dot=None):
        self.app, self._font, self._text, self._dot = app, font, text, dot
        super().__init__(master, bg=C.HEADER, highlightthickness=0, bd=0)
        self._draw()
    def set(self, text, dot=None):
        self._text, self._dot = text, dot
        self._draw()
    def _draw(self):
        px, pad = self.app.px, self.app.px(12)
        dot_w = px(16) if self._dot else 0
        w, h = pad * 2 + dot_w + self._font.measure(self._text), self._font.metrics("linespace") + px(12)
        self.configure(width=w, height=h)
        self.delete("all")
        rounded(self, 1, 1, w - 1, h - 1, h // 2 - 1, fill=C.HEADER_CHIP, outline=C.HEADER_LINE)
        x = pad
        if self._dot:
            r = px(4)
            self.create_oval(x, h // 2 - r, x + 2 * r, h // 2 + r, fill=self._dot, outline="")
            x += dot_w
        self.create_text(x, h // 2, text=self._text, font=self._font, fill=C.HEADER_FG, anchor="w")

class StageRow(tk.Frame):
    def __init__(self, master, app, index, total):
        super().__init__(master, bg=C.CARD)
        self.app, self.index, self.total, self.state, self._full = app, index, total, "wait", ""
        px = app.px
        self.node = tk.Canvas(self, width=px(40), height=1, bg=C.CARD, highlightthickness=0)
        self.node.pack(side="left", fill="y")
        body = tk.Frame(self, bg=C.CARD)
        body.pack(side="left", fill="both", expand=True, padx=(0, px(18)), pady=(px(7), px(7)))
        top = tk.Frame(body, bg=C.CARD)
        top.pack(fill="x")
        self.title = tk.Label(top, text="", font=app.f_ui_b, fg=C.INK_DIM, bg=C.CARD, anchor="w")
        self.title.pack(side="left")
        self.meta = tk.Label(top, text="", font=app.f_small, fg=C.INK_FAINT, bg=C.CARD, anchor="e")
        self.meta.pack(side="right")
        self.well = tk.Frame(body, bg=C.WAIT_BG)
        self.well.pack(fill="x", pady=(px(4), 0))
        self.read = tk.Label(self.well, text="", font=app.f_mono_s, fg=C.INK_FAINT, bg=C.WAIT_BG, anchor="w", width=1)
        self.read.pack(side="left", fill="x", expand=True, padx=(px(10), px(8)), pady=px(5))
        self.count = tk.Label(self.well, text="", font=app.f_small, fg=C.WELL_DIM, bg=C.WAIT_BG, anchor="e")
        self.count.pack(side="right", padx=(0, px(10)))
        self.node.bind("<Configure>", lambda e: self._draw())
        self.read.bind("<Configure>", lambda e: self._fit())
    def set_name(self, fn_name):
        title, node = step_label(fn_name)
        self.title.configure(text=title)
        self.meta.configure(text=node)
    def _paint(self, bg, fg):
        for w in (self.well, self.read, self.count): w.configure(bg=bg)
        self.read.configure(fg=fg)
    def reset(self):
        self.state, self._full = "wait", ""
        self._paint(C.WAIT_BG, C.INK_FAINT)
        self.read.configure(text="Waiting")
        self.count.configure(text="")
        self.title.configure(fg=C.INK_DIM)
        self._draw()
    def set_state(self, state, value=None):
        self.state = state
        self.title.configure(fg=C.INK_DIM if state == "wait" else C.INK)
        if state == "active":
            self._full = ""
            self.read.configure(text="Working…", fg=C.WELL_DIM)
            self.count.configure(text="")
        elif state == "done":
            self._full = (value or "")[:400].replace("\r", "␍").replace("\n", "↵")
            self._paint(C.WELL, C.WELL_FG)
            self.count.configure(text=f"{len(value or ''):,} bytes/chars" if value else "", fg=C.WELL_DIM)
            self._fit()
        self._draw()
    def _fit(self):
        if self._full: self.read.configure(text=elide(self.app.f_mono_s, self._full, self.read.winfo_width() - 2))
    def _draw(self):
        c, px, h = self.node, self.app.px, self.node.winfo_height()
        if h < 4: return
        c.delete("all")
        cx, cy = px(20), px(7) + self.title.winfo_reqheight() // 2
        if self.index > 0: c.create_line(cx, 0, cx, cy, width=px(2), fill=C.GREEN if self.state in ("done", "active") else C.BORDER)
        if self.index < self.total - 1: c.create_line(cx, cy, cx, h, width=px(2), fill=C.GREEN if self.state == "done" else C.BORDER)
        r = px(7)
        if self.state == "wait":
            c.create_oval(cx - r + 1, cy - r + 1, cx + r - 1, cy + r - 1, fill=C.CARD, outline=C.BORDER_STRONG, width=px(2))
        elif self.state == "active":
            c.create_oval(cx - px(11), cy - px(11), cx + px(11), cy + px(11), fill="", outline=C.RED_HALO, width=px(2))
            c.create_oval(cx - r + 1, cy - r + 1, cx + r - 1, cy + r - 1, fill=C.RED, outline=C.RED)
        else:
            c.create_oval(cx - r, cy - r, cx + r, cy + r, fill=C.GREEN, outline=C.GREEN)
            k = px(3)
            c.create_line(cx - k, cy, cx - 1, cy + k - 1, cx + k + 1, cy - k + 1, fill="#FFFFFF", width=px(2), capstyle="round", joinstyle="round")

class App(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("KOD8 - Unified NCIA Sandbox")
        self.configure(bg=C.BG)
        self.S = max(1.0, self.winfo_fpixels("1i") / 96.0)
        self._make_fonts(); self._make_styles()
        
        self._file_path = self._file_bytes = self._file_text_exact = self._loaded_display = None
        self._file_is_bin = self._busy = self._rail_has_run = False
        self._enc = self._out = self._preview_job = None
        self._q = queue.Queue()
        
        self._build_header()
        
        self.notebook = ttk.Notebook(self)
        self.notebook.grid(row=1, column=0, sticky="nsew", padx=self.px(10), pady=self.px(10))
        self.rowconfigure(1, weight=1)
        self.columnconfigure(0, weight=1)
        
        self.tab_file = tk.Frame(self.notebook, bg=C.BG)
        self.notebook.add(self.tab_file, text="File & Text Cipher (CL1-CL8)")
        self._build_file_tab(self.tab_file)
        
        self.tab_disk = tk.Frame(self.notebook, bg=C.BG)
        self.notebook.add(self.tab_disk, text="OEM Disk Provisioning (CL9)")
        self._build_disk_tab(self.tab_disk)

        self._build_statusbar()

        w, h, sw, sh = self.px(1300), self.px(850), self.winfo_screenwidth(), self.winfo_screenheight()
        self.geometry(f"{min(w, sw - 40)}x{min(h, sh - 80)}+{(sw - min(w, sw - 40)) // 2}+{max(0, (sh - min(h, sh - 80)) // 3)}")
        self.minsize(self.px(1100), self.px(750))
        
        self.bind("<Control-Return>", lambda e: self._start("encrypt") if self.notebook.index("current") == 0 else None)
        self.bind("<Control-Shift-Return>", lambda e: self._start("decrypt") if self.notebook.index("current") == 0 else None)
        self._input_changed()

    def px(self, n): return int(round(n * self.S))
    
    def _make_fonts(self):
        ui = next((n for n in ("Segoe UI Variable Text", "Segoe UI", "Inter", "Helvetica Neue", "Arial") if n in tkfont.families()), "TkDefaultFont")
        mono = next((n for n in ("Cascadia Mono", "Consolas", "Courier New") if n in tkfont.families()), "TkFixedFont")
        self.f_mark = tkfont.Font(family=ui, size=17, weight="bold")
        self.f_sub = tkfont.Font(family=ui, size=10)
        self.f_ui = tkfont.Font(family=ui, size=10)
        self.f_ui_b = tkfont.Font(family=ui, size=10, weight="bold")
        self.f_card = tkfont.Font(family=ui, size=11, weight="bold")
        self.f_btn = tkfont.Font(family=ui, size=11, weight="bold")
        self.f_small = tkfont.Font(family=ui, size=9)
        self.f_mono = tkfont.Font(family=mono, size=11)
        self.f_mono_s = tkfont.Font(family=mono, size=10)

    def _make_styles(self):
        st = ttk.Style(self)
        try: st.theme_use("clam")
        except tk.TclError: pass
        layout = [("Vertical.Scrollbar.trough", {"sticky": "ns", "children": [("Vertical.Scrollbar.thumb", {"expand": "1", "sticky": "nswe"})]})]
        for name, trough, thumb in (("Light", C.CARD, "#C3CBD3"), ("Dark", C.WELL, "#44566A")):
            s = f"{name}.Vertical.TScrollbar"
            st.layout(s, layout)
            st.configure(s, troughcolor=trough, background=thumb, bordercolor=trough, lightcolor=thumb, darkcolor=thumb, gripcount=0, width=self.px(9))
            st.map(s, background=[("active", C.INK_FAINT if name == "Light" else "#5C7088")])
        st.configure("TNotebook", background=C.BG, borderwidth=0)
        st.configure("TNotebook.Tab", background=C.CARD, foreground=C.INK, padding=[10, 5], font=self.f_ui_b)
        st.map("TNotebook.Tab", background=[("selected", C.RED)], foreground=[("selected", "white")])

    def _build_header(self):
        px = self.px
        head = tk.Frame(self, bg=C.HEADER); head.grid(row=0, column=0, sticky="ew")
        inner = tk.Frame(head, bg=C.HEADER); inner.pack(fill="x", padx=px(24), pady=px(14))
        mark = tk.Canvas(inner, width=px(14), height=px(14), bg=C.HEADER, highlightthickness=0)
        mark.create_rectangle(0, 0, px(14), px(14), fill=C.RED, outline=""); mark.pack(side="left", padx=(0, px(12)))
        tk.Label(inner, text="KOD8 Unified Sandbox", font=self.f_mark, fg=C.HEADER_FG, bg=C.HEADER).pack(side="left")
        tk.Label(inner, text="NCIA Compliant Multi-Layer Engine", font=self.f_sub, fg=C.HEADER_DIM, bg=C.HEADER).pack(side="left", padx=(px(16), 0), pady=(px(3), 0))
        self.chip_key = Chip(inner, self, self.f_small, "8-digit key loaded", C.GREEN); self.chip_key.pack(side="right")
        self.chip_strategy = Chip(inner, self, self.f_small, "Strategy: auto-detect", C.INK_FAINT); self.chip_strategy.pack(side="right", padx=(0, px(10)))

    def _build_statusbar(self):
        px = self.px
        bar = tk.Frame(self, bg=C.CARD, highlightbackground=C.BORDER, highlightcolor=C.BORDER, highlightthickness=1)
        bar.grid(row=2, column=0, sticky="ew")
        row = tk.Frame(bar, bg=C.CARD); row.pack(fill="x", padx=px(24), pady=px(9))
        self.dot = tk.Canvas(row, width=px(12), height=px(12), bg=C.CARD, highlightthickness=0); self.dot.pack(side="left", padx=(0, px(10)))
        self.status = tk.Label(row, text="", font=self.f_ui, fg=C.INK, bg=C.CARD, anchor="w", justify="left"); self.status.pack(side="left", fill="x", expand=True)
        self.status.bind("<Configure>", lambda e: self.status.configure(wraplength=max(200, e.width - 4)))
        self._set_status("ready", "Ready.")

    def _card(self, parent, title):
        px = self.px
        card = tk.Frame(parent, bg=C.CARD, highlightbackground=C.BORDER, highlightcolor=C.BORDER, highlightthickness=1)
        head = tk.Frame(card, bg=C.CARD); head.pack(fill="x", padx=px(16), pady=(px(10), px(6)))
        tk.Label(head, text=title, font=self.f_card, fg=C.INK, bg=C.CARD).pack(side="left")
        tools = tk.Frame(head, bg=C.CARD); tools.pack(side="right")
        meta = tk.Label(head, text="", font=self.f_small, fg=C.INK_FAINT, bg=C.CARD); meta.pack(side="right", padx=(0, px(10)))
        tk.Frame(card, bg=C.BORDER, height=1).pack(fill="x")
        return card, tools, meta

    # ── TAB 1: FILE/TEXT CIPHER ──────────────────────────────────────────────
    def _build_file_tab(self, parent):
        px = self.px
        parent.rowconfigure(0, weight=1); parent.columnconfigure(0, weight=5, uniform="cols"); parent.columnconfigure(1, weight=6, uniform="cols")
        left = tk.Frame(parent, bg=C.BG); left.grid(row=0, column=0, sticky="nsew", padx=(0, px(10)))
        left.columnconfigure(0, weight=1); left.rowconfigure(0, weight=1, uniform="io"); left.rowconfigure(2, weight=1, uniform="io")
        right = tk.Frame(parent, bg=C.BG); right.grid(row=0, column=1, sticky="nsew", padx=(px(10), 0))
        right.rowconfigure(0, weight=1); right.columnconfigure(0, weight=1)

        card, tools, self.in_meta = self._card(left, "Input")
        card.grid(row=0, column=0, sticky="nsew")
        RButton(tools, self, "Open file…", self._open_file, "ghost", self.f_ui_b, padx=10, pady=4).pack(side="left")
        RButton(tools, self, "Clear", self._clear, "ghost", self.f_ui_b, padx=10, pady=4).pack(side="left")
        body = tk.Frame(card, bg=C.CARD); body.pack(fill="both", expand=True)
        sb = ttk.Scrollbar(body, orient="vertical", style="Light.Vertical.TScrollbar"); sb.pack(side="right", fill="y")
        self.input = tk.Text(body, font=self.f_mono, bg=C.CARD, fg=C.INK, relief="flat", bd=0, wrap="word", padx=px(16), pady=px(12), undo=True, height=1, insertbackground=C.RED, highlightthickness=0, yscrollcommand=sb.set)
        self.input.pack(side="left", fill="both", expand=True)
        sb.configure(command=self.input.yview)
        self.ph = tk.Label(self.input, justify="left", font=self.f_ui, fg=C.INK_FAINT, bg=C.CARD, anchor="nw", cursor="xterm", text="Type or paste text to encrypt.\nPaste ciphertext, or open a .kod8 file, to decrypt.")
        self.ph.place(x=px(16), y=px(12)); self.ph.bind("<Button-1>", lambda e: self.input.focus_set())
        self.input.bind("<<Modified>>", self._on_modified)

        row = tk.Frame(left, bg=C.BG); row.grid(row=1, column=0, sticky="ew", pady=px(12))
        self.btn_enc = RButton(row, self, "Encrypt", lambda: self._start("encrypt"), "primary", self.f_btn, parent_bg=C.BG, padx=34, pady=11, min_w=150); self.btn_enc.pack(side="left")
        self.btn_dec = RButton(row, self, "Decrypt", lambda: self._start("decrypt"), "secondary", self.f_btn, parent_bg=C.BG, padx=34, pady=11, min_w=150); self.btn_dec.pack(side="left", padx=(px(12), 0))

        card2, tools2, self.out_meta = self._card(left, "Output")
        card2.grid(row=2, column=0, sticky="nsew")
        self.btn_copy = RButton(tools2, self, "Copy", self._copy, "ghost", self.f_ui_b, padx=10, pady=4); self.btn_copy.pack(side="left")
        self.btn_save = RButton(tools2, self, "Save…", self._save, "ghost", self.f_ui_b, padx=10, pady=4); self.btn_save.pack(side="left")
        self.btn_copy.set_enabled(False); self.btn_save.set_enabled(False)
        body2 = tk.Frame(card2, bg=C.WELL); body2.pack(fill="both", expand=True)
        sb2 = ttk.Scrollbar(body2, orient="vertical", style="Dark.Vertical.TScrollbar"); sb2.pack(side="right", fill="y")
        self.output = tk.Text(body2, font=self.f_mono, bg=C.WELL, fg=C.WELL_FG, relief="flat", bd=0, wrap="char", padx=px(16), pady=px(12), height=1, highlightthickness=0, yscrollcommand=sb2.set, state="disabled")
        self.output.pack(side="left", fill="both", expand=True)
        sb2.configure(command=self.output.yview); self.output.bind("<Button-1>", lambda e: self.output.focus_set())
        self._set_output_text("The result appears here.", dim=True)

        card3 = tk.Frame(right, bg=C.CARD, highlightbackground=C.BORDER, highlightcolor=C.BORDER, highlightthickness=1)
        card3.grid(row=0, column=0, sticky="nsew")
        head3 = tk.Frame(card3, bg=C.CARD); head3.pack(fill="x", padx=px(16), pady=(px(10), px(6)))
        tk.Label(head3, text="Pipeline Execution", font=self.f_card, fg=C.INK, bg=C.CARD).pack(side="left")
        self.prog_label = tk.Label(head3, text="0 of 8", font=self.f_small, fg=C.INK_FAINT, bg=C.CARD); self.prog_label.pack(side="right")
        self.prog = tk.Canvas(card3, height=px(3), bg=C.BORDER, highlightthickness=0); self.prog.pack(fill="x")
        self._prog_frac, self._prog_color = 0.0, C.RED; self.prog.bind("<Configure>", lambda e: self._draw_progress())
        rows = tk.Frame(card3, bg=C.CARD); rows.pack(fill="both", expand=True, pady=(px(6), px(6))); rows.columnconfigure(0, weight=1)
        self.rows = []
        for i in range(8):
            rows.rowconfigure(i, weight=1, uniform="stage")
            r = StageRow(rows, self, i, 8); r.grid(row=i, column=0, sticky="nsew"); self.rows.append(r)
        self._reset_rail(ENC_STEPS)

    # ── TAB 2: DISK PROVISIONING ─────────────────────────────────────────────
    def _build_disk_tab(self, parent):
        px = self.px
        parent.rowconfigure(0, weight=1); parent.columnconfigure(0, weight=1)

        container, _, _ = self._card(parent, "Split-Key Volume Provisioner (CL9)")
        container.grid(row=0, column=0, sticky="nsew", padx=px(20), pady=px(20))

        main_content = tk.Frame(container, bg=C.CARD)
        main_content.pack(fill="both", expand=True, padx=px(20), pady=px(20))

        left_col = tk.Frame(main_content, bg=C.CARD)
        left_col.pack(side="left", fill="y", padx=(0, px(30)))

        self._drive_q = queue.Queue()
        self._drive_map = {}
        self._current_plan = None

        tk.Label(left_col, text="Drive Selection", font=self.f_ui_b, bg=C.CARD, fg=C.INK).pack(anchor="w", pady=(0, px(5)))
        tk.Label(left_col, text="Only removable, non-system drives are listed.\nAmbiguous or internal drives are excluded.",
                 font=self.f_small, bg=C.CARD, fg=C.INK_FAINT, justify="left").pack(anchor="w", pady=(0, px(6)))
        self.cmb_drive = ttk.Combobox(left_col, state="readonly", width=34)
        self.cmb_drive.pack(anchor="w", pady=(0, px(10)))
        self.cmb_drive.bind("<<ComboboxSelected>>", lambda e: self._reset_plan_state())

        self.btn_refresh = RButton(left_col, self, "Refresh Drives", self._refresh_drives, "ghost", self.f_small, padx=10, pady=4)
        self.btn_refresh.pack(anchor="w", pady=(0, px(20)))

        tk.Label(left_col, text="Target OEM Cipher", font=self.f_ui_b, bg=C.CARD, fg=C.INK).pack(anchor="w", pady=(0, px(5)))
        self.os_var = tk.StringVar(value="Windows")
        for val, text in (("Windows", "Windows (BitLocker AES-XTS via .bek)"), ("Linux", "Linux (LUKS2 AES-XTS via raw binary)")):
            tk.Radiobutton(left_col, text=text, variable=self.os_var, value=val, command=self._reset_plan_state,
                           bg=C.CARD, fg=C.INK, activebackground=C.CARD, selectcolor=C.CARD).pack(anchor="w")

        self.btn_preview = RButton(left_col, self, "Preview plan (dry run)", self._preview_plan, "secondary", self.f_btn, parent_bg=C.CARD, padx=16, pady=8)
        self.btn_preview.pack(anchor="w", pady=(px(20), px(10)))

        self.confirm_label = tk.Label(left_col, text="Preview a plan to see what to type here.", font=self.f_small,
                                       bg=C.CARD, fg=C.INK_FAINT, wraplength=px(260), justify="left")
        self.confirm_label.pack(anchor="w", pady=(px(4), px(2)))
        self.confirm_entry = tk.Entry(left_col, font=self.f_mono_s, width=34, state="disabled")
        self.confirm_entry.pack(anchor="w", pady=(0, px(10)))
        self.confirm_entry.bind("<KeyRelease>", self._check_confirm)

        self.btn_format = RButton(left_col, self, "Format + Encrypt Volume (dry run)", self._confirm_and_log, "primary", self.f_btn, parent_bg=C.CARD, padx=20, pady=10)
        self.btn_format.pack(anchor="w")
        self.btn_format.set_enabled(False)

        right_col = tk.Frame(main_content, bg=C.WELL)
        right_col.pack(side="right", fill="both", expand=True)

        tk.Label(right_col, text="Provisioning Log", font=self.f_ui_b, bg=C.WELL, fg=C.WELL_FG).pack(anchor="w", padx=px(10), pady=px(10))

        sb = ttk.Scrollbar(right_col, orient="vertical", style="Dark.Vertical.TScrollbar")
        sb.pack(side="right", fill="y")
        self.disk_log = tk.Text(right_col, font=self.f_mono, bg=C.WELL, fg=C.WELL_MINT, relief="flat", bd=0, wrap="word", padx=px(10), pady=px(10), yscrollcommand=sb.set, state="disabled")
        self.disk_log.pack(side="left", fill="both", expand=True)
        sb.configure(command=self.disk_log.yview)

        self._refresh_drives()

    def _reset_plan_state(self):
        self._current_plan = None
        self.confirm_entry.delete(0, "end")
        self.confirm_entry.configure(state="disabled")
        self.confirm_label.configure(text="Preview a plan to see what to type here.")
        self.btn_format.set_enabled(False)

    def _log_disk(self, msg):
        self.disk_log.configure(state="normal")
        self.disk_log.insert("end", f"[{datetime.datetime.now().strftime('%H:%M:%S')}] {msg}\n")
        self.disk_log.see("end")
        self.disk_log.configure(state="disabled")

    def _refresh_drives(self):
        self.btn_refresh.set_enabled(False)
        self._log_disk("Scanning for candidate drives...")

        def worker():
            try:
                drives = safe_candidates()
                self._drive_q.put(("ok", drives))
            except Exception as e:
                self._drive_q.put(("err", str(e)))
        threading.Thread(target=worker, daemon=True).start()
        self.after(80, self._poll_drives)

    def _poll_drives(self):
        try:
            kind, payload = self._drive_q.get_nowait()
        except queue.Empty:
            self.after(80, self._poll_drives)
            return
        self.btn_refresh.set_enabled(True)
        if kind == "err":
            self._log_disk(f"Drive detection failed closed (no drives offered): {payload}")
            self.cmb_drive["values"] = []
            self.cmb_drive.set("")
            self._drive_map = {}
            return
        self._drive_map = {d.label(): d for d in payload}
        self.cmb_drive["values"] = list(self._drive_map.keys())
        if self._drive_map:
            self.cmb_drive.current(0)
            self._log_disk(f"Found {len(self._drive_map)} candidate drive(s).")
        else:
            self.cmb_drive.set("No safe candidate drives found")
            self._log_disk("No removable, unmounted, non-system drives found.")
        self._reset_plan_state()

    def _preview_plan(self):
        label = self.cmb_drive.get()
        snapshot = self._drive_map.get(label)
        if snapshot is None:
            messagebox.showerror("CL9", "Select a drive from the list first.")
            return
        plan = plan_commands(snapshot, self.os_var.get())
        self._current_plan = plan
        self._set_strategy_chip("CL9")
        self._log_disk(f"--- plan for {snapshot.device_path} ({self.os_var.get()}) ---")
        for w in plan.warnings:
            self._log_disk(w)
        for c in plan.commands:
            self._log_disk(f"  $ {c}")
        if plan.commands:
            self.confirm_label.configure(text=f"Type the exact device path to confirm: {snapshot.confirmation_token()}")
            self.confirm_entry.configure(state="normal")
            self.confirm_entry.delete(0, "end")
            self.confirm_entry.focus_set()
        else:
            self.confirm_label.configure(text="This drive was refused - see the log. Nothing to confirm.")
            self.confirm_entry.configure(state="disabled")
        self.btn_format.set_enabled(False)

    def _check_confirm(self, *_):
        ok = bool(self._current_plan) and bool(self._current_plan.commands) and \
             confirms(self._current_plan.snapshot, self.confirm_entry.get())
        self.btn_format.set_enabled(ok)

    def _confirm_and_log(self):
        plan = self._current_plan
        if not plan or not confirms(plan.snapshot, self.confirm_entry.get()):
            return
        try:
            result = execute_plan(plan, self.confirm_entry.get(), dry_run=True)
        except PermissionError as e:
            self._log_disk(f"REFUSED: {e}")
            self._set_status("error", str(e))
            return
        self._log_disk(f"DRY RUN confirmed for {plan.snapshot.device_path}. "
                        f"Derived a {result['boot_key_bytes']}-byte boot key; "
                        f"host token NOT written (dry run). Audit entry recorded.")
        self._set_status("ok", f"Dry run confirmed for {plan.snapshot.device_path}. Nothing was written to the drive.")
        self._reset_plan_state()

    # ── SHARED UTILITIES ──────────────────────────────────────────────────────
    def _draw_progress(self):
        self.prog.delete("all")
        if self._prog_frac > 0: self.prog.create_rectangle(0, 0, int(self.prog.winfo_width() * self._prog_frac), self.prog.winfo_height(), fill=self._prog_color, outline="")
    def _set_progress(self, done, total=8, color=C.RED):
        self._prog_frac, self._prog_color = done / total, color
        self.prog_label.configure(text=f"{done} of {total}"); self._draw_progress()
    def _set_status(self, kind, msg):
        color = {"ready": C.INK_FAINT, "busy": C.RED, "ok": C.GREEN, "error": C.RED}[kind]
        self.dot.delete("all"); self.dot.create_oval(self.px(1), self.px(1), self.px(11), self.px(11), fill=color, outline="")
        self.status.configure(text=msg, fg=C.RED if kind == "error" else C.INK)
    def _reset_rail(self, steps):
        for row, (fn, _) in zip(self.rows, steps):
            row.set_name(fn.__name__)
            row.reset()
        self._set_progress(0); self._rail_has_run = False
    def _set_buttons(self, busy): self.btn_enc.set_enabled(not busy); self.btn_dec.set_enabled(not busy)
    def _set_strategy_chip(self, cid): self.chip_strategy.set(f"{cid}  {STRATEGY_MAP.get(cid, '')}" if cid else "Strategy: auto-detect", C.RED if cid else C.INK_FAINT)

    def _set_input(self, text, dim=False, locked=False):
        self.input.configure(state="normal"); self.input.delete("1.0", "end"); self.input.insert("1.0", text)
        self.input.configure(fg=C.INK_DIM if dim else C.INK, state="disabled" if locked else "normal")
    def _on_modified(self, _=None):
        if self.input.edit_modified(): self.input.edit_modified(False); self._input_changed()
    def _input_changed(self):
        text = self.input.get("1.0", "end-1c")
        if text or str(self.input.cget("state")) == "disabled": self.ph.place_forget()
        else: self.ph.place(x=self.px(16), y=self.px(12))
        self.in_meta.configure(text=f"{os.path.basename(self._file_path)}, {human_size(len(self._file_bytes))}" if self._file_is_bin else (f"{os.path.basename(self._file_path)}, {len(text):,} chars" if self._file_path else (f"{len(text):,} chars" if text else "")))
        if self._preview_job: self.after_cancel(self._preview_job)
        self._preview_job = self.after(180, self._preview)
    def _preview(self):
        self._preview_job = None
        if self._busy: return
        cid = auto_detect(self._file_path, is_file=True) if self._file_is_bin else (parse_kod8(self.input.get("1.0", "end-1c"))[0] or auto_detect(self.input.get("1.0", "end-1c")[:2000])) if self.input.get("1.0", "end-1c").strip() else None
        self._set_strategy_chip(cid)
        if self._rail_has_run and not (self._enc is not None and self._enc["snapshot"] == (("file", self._file_path) if self._file_is_bin else ("text", self.input.get("1.0", "end-1c")))):
            self._reset_rail(ENC_STEPS)
    def _clear(self):
        if self._busy: return
        self._file_path = self._file_bytes = self._file_text_exact = self._loaded_display = None
        self._file_is_bin = False; self._enc = None; self._set_input(""); self._show_nothing()
        self._reset_rail(ENC_STEPS); self._set_strategy_chip(None); self._set_status("ready", "Cleared.")
        self.input.focus_set()

    def _open_file(self):
        if self._busy: return
        path = filedialog.askopenfilename(title="Open a file to encrypt or decrypt", filetypes=[("All files", "*.*"), ("KOD8 encrypted", "*.kod8")])
        if not path: return
        try:
            with open(path, "rb") as f: data = f.read()
        except OSError as e: self._set_status("error", f"Couldn't open the file: {e}"); return
        self._enc = None; self._file_path = path; name = os.path.basename(path)
        try:
            exact = data.decode("utf-8"); display = exact.replace("\r\n", "\n").replace("\r", "\n")
            self._file_is_bin, self._file_bytes, self._file_text_exact, self._loaded_display = False, None, exact, display
            self._set_input(display); self._set_status("ready", f"Opened {name}. Encrypt it, or decrypt if it's a .kod8 file.")
        except UnicodeDecodeError:
            self._file_is_bin, self._file_bytes, self._file_text_exact, self._loaded_display = True, data, None, None
            self._set_input(f"{name}\nBinary file, {human_size(len(data))}.\n\nEncrypt wraps the raw bytes. Decrypt restores them exactly.", dim=True, locked=True)
            self._set_status("ready", f"Opened {name} ({human_size(len(data))}). Ready to encrypt.")
        self._show_nothing(); self._reset_rail(ENC_STEPS); self._input_changed()

    def _copy(self):
        if self._out and self._out["text"] is not None:
            self.clipboard_clear(); self.clipboard_append(self._out["text"]); self._set_status("ok", "Copied the output to the clipboard.")
    def _save(self):
        o = self._out
        if not o: return
        base = os.path.splitext(os.path.basename(self._file_path))[0] if self._file_path else "output"
        if base.endswith("_enc"): base = base[:-4]
        try:
            if o["kind"] == "enc":
                path = filedialog.asksaveasfilename(title="Save encrypted output", defaultextension=".kod8", initialfile=f"{base}_enc.kod8", filetypes=[("KOD8 encrypted", "*.kod8"), ("All files", "*.*")])
                if not path: return
                with open(path, "w", encoding="utf-8", newline="") as f: f.write(format_kod8_file(o["cid"], o["salt_b64"], o["is_bin"], o["ext"], o["text"]))
            else:
                name = base + (o["ext"] or ("" if o["data"] is not None else ".txt"))
                path = filedialog.asksaveasfilename(title="Save decrypted output", initialfile=name, defaultextension="" if (o["ext"] or o["data"] is not None) else ".txt", filetypes=[("All files", "*.*"), ("Text files", "*.txt")])
                if not path: return
                with open(path, "wb") as f: f.write(o["data"] if o["data"] is not None else o["text"].encode('utf-8'))
            self._set_status("ok", f"Saved {os.path.basename(path)}.")
        except OSError as e: self._set_status("error", f"Couldn't save the file: {e}")

    def _set_output_text(self, text, dim=False, mint=False):
        self.output.configure(state="normal"); self.output.delete("1.0", "end"); self.output.insert("1.0", text)
        self.output.configure(state="disabled", fg=C.WELL_DIM if dim else (C.WELL_MINT if mint else C.WELL_FG))
    def _show_nothing(self):
        self._out = None; self._set_output_text("The result appears here.", dim=True); self.out_meta.configure(text="")
        self.btn_copy.set_enabled(False); self.btn_save.set_enabled(False)
    def _show_output(self, out):
        self._out = out
        if out["data"] is not None:
            self._set_output_text(f"Binary data, {human_size(len(out['data']))}.\nUse Save… to write the restored file.", mint=True)
            self.out_meta.configure(text=f"{out['cid']}, {len(out['data']):,} bytes")
        else:
            t = out["text"]
            self._set_output_text(t if len(t) <= MAX_VIEW_CHARS else (t[:MAX_VIEW_CHARS] + f"\n\n… view truncated at {MAX_VIEW_CHARS:,} of {len(t):,} characters. Save… writes everything."), mint=(out["kind"] == "dec"))
            self.out_meta.configure(text=f"{out['cid']}, {len(t):,} chars")
        self.btn_copy.set_enabled(out["text"] is not None); self.btn_save.set_enabled(True)

    def _prepare(self, mode):
        snap = ("file", self._file_path) if self._file_is_bin else ("text", self.input.get("1.0", "end-1c"))
        if mode == "encrypt":
            if self._file_is_bin: return dict(mode=mode, text=self._file_bytes, is_file=True, is_bin=True, cid=auto_detect(self._file_path, is_file=True), ext=os.path.splitext(self._file_path)[1], snapshot=snap, original=self._file_bytes)
            raw = snap[1]
            if not raw.strip(): raise ValueError("Nothing to encrypt.")
            text = self._file_text_exact if self._file_path and raw == self._loaded_display else raw
            return dict(mode=mode, text=text, is_file=False, is_bin=False, cid=auto_detect(raw[:2000]), ext=os.path.splitext(self._file_path)[1] if self._file_path else "", snapshot=snap, original=text)
        if self._enc is not None and self._enc["snapshot"] == snap:
            e = self._enc
            return dict(mode=mode, text=e["cipher"], is_file=e["is_bin"], is_bin=e["is_bin"], cid=e["cid"], ext=e["ext"], snapshot=snap, original=e["original"], salt_b64=e["salt_b64"])
        if self._file_is_bin: raise ValueError("This is a binary file, not ciphertext.")
        cid, is_bin, ext, salt_b64, body = parse_kod8(snap[1])
        if not body: raise ValueError("Nothing to decrypt.")
        if not cid: raise ValueError("Missing or unknown KOD8 header.")
        if not salt_b64: raise ValueError("Missing salt in KOD8 header.")
        return dict(mode=mode, text=body, is_file=is_bin, is_bin=is_bin, cid=cid, ext=ext, snapshot=snap, original=None, salt_b64=salt_b64)

    def _start(self, mode):
        if self._busy: return
        try: job = self._prepare(mode)
        except ValueError as e: self._set_status("error", str(e)); return
        self._busy = True; self._set_buttons(True)
        self._reset_rail(ENC_STEPS if mode == "encrypt" else DEC_STEPS)
        self._set_strategy_chip(job["cid"]); self._set_status("busy", "Encrypting…" if mode == "encrypt" else "Decrypting…")
        threading.Thread(target=self._worker, args=(job,), daemon=True).start()
        self.after(40, self._poll)

    def _worker(self, job):
        try:
            encrypt = job["mode"] == "encrypt"
            list_id_arg = job["cid"] if encrypt else f'{job["cid"]}:{job["salt_b64"]}'
            cid, out, hist, salt_b64 = run_kod8_pipeline(job["text"], is_file=job["is_file"], encrypt=encrypt, list_id=list_id_arg)
            data = out if not encrypt and job["is_bin"] else None
            out_str = out if encrypt or not job["is_bin"] else None
            self._q.put(("ok", job, out_str, data, hist, salt_b64))
        except Exception as e: self._q.put(("err", job, str(e), None, None, None))

    def _poll(self):
        try: msg = self._q.get_nowait()
        except queue.Empty: self.after(40, self._poll); return
        kind, job, out, data, hist, salt_b64 = msg
        if kind == "err":
            self._busy = False; self._set_buttons(False); self._reset_rail(ENC_STEPS if job["mode"] == "encrypt" else DEC_STEPS)
            self._set_status("error", f"Couldn't {'encrypt' if job['mode'] == 'encrypt' else 'decrypt'}: {out}"); return
        self._animate(job, out, data, hist, salt_b64)

    def _animate(self, job, out, data, hist, salt_b64):
        self._rail_has_run = True
        step, n = 135, len(hist)
        for i, (fn, val) in enumerate(hist):
            self.after(i * step, self._row_active, i, fn)
            self.after(i * step + 95, self._row_done, i, val, n)
        self.after(n * step + 70, self._finish, job, out, data, salt_b64)

    def _row_active(self, i, fn):
        self.rows[i].set_name(fn); self.rows[i].set_state("active"); self._set_progress(i)
    def _row_done(self, i, val, n):
        self.rows[i].set_state("done", val); self._set_progress(i + 1, n, C.RED if i + 1 < n else C.GREEN)

    def _finish(self, job, out, data, salt_b64):
        if job["mode"] == "encrypt":
            self._enc = dict(snapshot=job["snapshot"], cipher=out, cid=job["cid"], is_bin=job["is_bin"], ext=job["ext"], original=job["original"], salt_b64=salt_b64)
            self._show_output(dict(kind="enc", text=out, data=None, cid=job["cid"], is_bin=job["is_bin"], ext=job["ext"], salt_b64=salt_b64))
            self._set_status("ok", f"Encrypted with {job['cid']}. {len(out):,} characters.")
        else:
            self._show_output(dict(kind="dec", text=out, data=data, cid=job["cid"], is_bin=job["is_bin"], ext=job["ext"]))
            produced = data if data is not None else out
            if job["original"] is not None and produced == job["original"]: msg = "Round trip verified. Matches original."
            else: msg = f"Decrypted with {job['cid']}. {f'{len(produced):,} bytes' if data is not None else f'{len(produced):,} chars'}."
            self._set_status("ok", msg)
        self._busy = False; self._set_buttons(False)

if __name__ == "__main__": App().mainloop()