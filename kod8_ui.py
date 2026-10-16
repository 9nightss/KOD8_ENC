#!/usr/bin/env python3

# =============================================================================
# KOD 8
# =============================================================================

import tkinter as tk
from tkinter import filedialog, messagebox
import threading
import os
import sys
import base64
import time

# ── engine ───────────────────────────────────────────────────────────────────
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from kod8_engine import run_kod8_pipeline, CIPHER_LISTS, KOD8_KEY, _detect_turkish, _detect_numeric

# ═════════════════════════════════════════════════════════════════════════════
# PALETTE
# ═════════════════════════════════════════════════════════════════════════════
BG_WINDOW     = "#1e2128"
BG_PANEL      = "#2b2f38"
BG_INPUT      = "#23272e"
BG_HEADER     = "#23272e"
BTN_UPLOAD    = "#3d7ebf"
BTN_UPLOAD_H  = "#4a8ecf"
BTN_ENC       = "#2e7d32"
BTN_ENC_H     = "#388e3c"
BTN_DEC       = "#1a4fa0"
BTN_DEC_H     = "#1e5bb5"
FG_WHITE      = "#e8eaf0"
FG_DIM        = "#6a7080"
FG_GREEN      = "#4caf50"
FG_CYAN       = "#4db6ff"
FG_YELLOW     = "#f0c060"
FG_RED        = "#ef5350"
FG_SELECTED   = "#4db6ff"
SEPARATOR     = "#33373f"

FONT_MONO     = ("Consolas", 11)
FONT_MONO_B   = ("Consolas", 11, "bold")
FONT_MONO_SM  = ("Consolas", 10)
FONT_TITLE    = ("Consolas", 16, "bold")
FONT_PROG_NUM = ("Consolas", 24, "bold")
FONT_PROG_LBL = ("Consolas", 11, "bold")
FONT_BTN      = ("Consolas", 12, "bold")
FONT_STEP     = ("Consolas", 11)

CL_STRATEGY = {
    "CL1": "STRATEGY\nASCII PLAIN TEXT",
    "CL2": "STRATEGY\nNUMERIC STRINGS",
    "CL3": "STRATEGY\nDOCUMENT FILES",
    "CL4": "STRATEGY\nIMAGE DATA",
    "CL5": "STRATEGY\nVIDEO DATA",
    "CL6": "STRATEGY\nFALLBACK ENGINE 1",
    "CL7": "STRATEGY\nFALLBACK ENGINE 2",
    "CL8": "STRATEGY\nTURKISH SPECIAL CHARS",
}

STEP_META = {
    "op_mlkem_encap":          "ML-KEM Post-Quantum Lattice (Node 8)",
    "op_blake3_seed_prep":     "BLAKE3 Dynamic Seed Prep (Node 8)",
    "op_turkish_normalize":    "Turkish Character Set Normalize (Node 8)",
    "op_rocca_s_stream":       "Rocca-S SIMD Stream Transformation (Node 6)",
    "op_galois_field_mult":    "GF(2^8) Galois Field Modulation (Node 6)",
    "op_dynamic_split":        "Inter-Block Positional Split (Node 2)",
    "op_base36_pack":          "Base36 Integer Transposition (Node 2)",
    "op_glevian_block":        "Glevian Block Matrix Mutation (Node 4)",
    "op_vigornian_sub":        "Vigornian State-Mutating Sub (Node 7)",
    "op_aegis256x":            "AEGIS-256X Extended Permutation (Node 9)",
    "op_prime_affine_transform":"Prime Modulo (p=257) Affine Shift (Node 9)",
    "op_ascon128_sponge":      "Ascon-128 Lightweight Sponge Diffusion (Node 3)",
    "op_full_reverse":         "Terminal Script Reversal (Node 1)",
}


def auto_detect(sample_or_path: str, is_file: bool = False) -> str:
    """Helper dispatcher for strategy UI previews."""
    if is_file:
        ext = sample_or_path.lower().split(".")[-1]
        if ext in ["pdf", "docx", "doc", "txt", "xlsx", "pptx", "odt"]:
            return "CL3"
        elif ext in ["png", "jpg", "jpeg", "bmp", "webp", "gif", "svg"]:
            return "CL4"
        elif ext in ["mp4", "mkv", "avi", "mov", "webm", "flv"]:
            return "CL5"
        return "CL6"
    else:
        if _detect_turkish(sample_or_path):
            return "CL8"
        elif _detect_numeric(sample_or_path):
            return "CL2"
        return "CL1"


# ═════════════════════════════════════════════════════════════════════════════
# HOVER BUTTON
# ═════════════════════════════════════════════════════════════════════════════

class HoverButton(tk.Button):
    def __init__(self, master, bg_normal, bg_hover, **kw):
        super().__init__(master, bg=bg_normal,
                         activebackground=bg_hover,
                         activeforeground=kw.get("fg", FG_WHITE),
                         **kw)
        self.bind("<Enter>", lambda _: self.configure(bg=bg_hover))
        self.bind("<Leave>", lambda _: self.configure(bg=bg_normal))


# ═════════════════════════════════════════════════════════════════════════════
# APPLICATION
# ═════════════════════════════════════════════════════════════════════════════

class Kod8enc(tk.Tk):

    def __init__(self):
        super().__init__()
        self.title("KOD 8 - Multi Layer Based Cipher Engine")
        self.configure(bg=BG_WINDOW)
        self.geometry("1120x960")
        self.minsize(860, 780)

        self._file_path   = None
        self._file_bytes  = None
        self._file_is_bin = False
        self._enc_result  = None
        self._enc_cid     = None
        self._busy        = False

        self._build()

    # ─────────────────────────────────────────────────────────────────────
    # UI BUILD
    # ─────────────────────────────────────────────────────────────────────

    def _build(self):

        # ── 1. Upload / Browse bar ────────────────────────────────────────
        top_bar = tk.Frame(self, bg=BG_HEADER, pady=10)
        top_bar.pack(fill="x")

        HoverButton(
            top_bar, BTN_UPLOAD, BTN_UPLOAD_H,
            text="UPLOAD / BROWSE",
            font=FONT_BTN, fg=FG_WHITE,
            relief="flat", bd=0,
            padx=18, pady=8, cursor="hand2",
            command=self._browse,
        ).pack(side="left", padx=(16, 14))

        self._selected_var = tk.StringVar(value="No file selected.")
        tk.Label(
            top_bar,
            textvariable=self._selected_var,
            font=FONT_MONO_SM, fg=FG_SELECTED,
            bg=BG_HEADER, anchor="w",
        ).pack(side="left", fill="x", expand=True, padx=(0, 16))

        # ── 2. Data display / text input ──────────────────────────────────
        data_frame = tk.Frame(self, bg=BG_INPUT)
        data_frame.pack(fill="both", expand=True, padx=16, pady=(8, 8))

        self._data_text = tk.Text(
            data_frame,
            bg=BG_INPUT, fg=FG_WHITE,
            font=FONT_MONO, relief="flat", bd=0,
            wrap="word", padx=10, pady=10,
            insertbackground=FG_CYAN,
            selectbackground=BG_PANEL,
            height=8,
        )
        self._data_text.pack(side="left", fill="both", expand=True)

        sb = tk.Scrollbar(data_frame, orient="vertical",
                          command=self._data_text.yview,
                          bg=BG_PANEL, troughcolor=BG_WINDOW,
                          relief="flat", bd=0, width=10)
        sb.pack(side="right", fill="y")
        self._data_text.configure(yscrollcommand=sb.set)

        self._placeholder_active = True
        self._set_data_text("[NO FILE LOADED]", FG_DIM)
        self._data_text.bind("<FocusIn>", self._data_focus_in)

        # ── 3. Strategy / Progress row ──────────────────────────────────
        sp = tk.Frame(self, bg=BG_WINDOW)
        sp.pack(fill="x", padx=16, pady=(0, 8))
        sp.columnconfigure(0, weight=1, uniform="half")
        sp.columnconfigure(1, weight=1, uniform="half")

        strat_card = tk.Frame(sp, bg=BG_PANEL)
        strat_card.grid(row=0, column=0, sticky="nsew", padx=(0, 6), ipady=16)
        self._strategy_var = tk.StringVar(value="STRATEGY\nAUTO DETECT")
        tk.Label(
            strat_card,
            textvariable=self._strategy_var,
            font=FONT_TITLE, fg=FG_WHITE,
            bg=BG_PANEL, justify="center",
        ).pack(expand=True)

        prog_card = tk.Frame(sp, bg=BG_PANEL)
        prog_card.grid(row=0, column=1, sticky="nsew", padx=(6, 0), ipady=16)
        tk.Label(prog_card, text="PROGRESS",
                 font=FONT_PROG_LBL, fg=FG_WHITE,
                 bg=BG_PANEL).pack()
        self._progress_var = tk.StringVar(value="0 / 8")
        tk.Label(prog_card,
                 textvariable=self._progress_var,
                 font=FONT_PROG_NUM, fg=FG_WHITE,
                 bg=BG_PANEL).pack()

        # ── 4. Step-by-step verification ──────────────────────────────────
        verif = tk.Frame(self, bg=BG_PANEL)
        verif.pack(fill="both", expand=True, padx=16, pady=(0, 10))

        hdr = tk.Frame(verif, bg=SEPARATOR)
        hdr.pack(fill="x")
        tk.Label(hdr, text="Process Cycle",
                 font=FONT_MONO_B, fg=FG_WHITE,
                 bg=SEPARATOR, pady=8).pack()

        # canvas + scrollbar for the 8 step rows
        list_wrap = tk.Frame(verif, bg=BG_PANEL)
        list_wrap.pack(fill="both", expand=True)

        self._canvas = tk.Canvas(list_wrap, bg=BG_PANEL,
                                  highlightthickness=0, bd=0)
        self._canvas.pack(side="left", fill="both", expand=True)

        vsb = tk.Scrollbar(list_wrap, orient="vertical",
                           command=self._canvas.yview,
                           bg=BG_PANEL, troughcolor=BG_WINDOW,
                           relief="flat", bd=0, width=10)
        vsb.pack(side="right", fill="y")
        self._canvas.configure(yscrollcommand=vsb.set)

        self._steps_frame = tk.Frame(self._canvas, bg=BG_PANEL)
        self._steps_win = self._canvas.create_window(
            (0, 0), window=self._steps_frame, anchor="nw")

        self._steps_frame.bind(
            "<Configure>",
            lambda e: self._canvas.configure(
                scrollregion=self._canvas.bbox("all")))
        self._canvas.bind(
            "<Configure>",
            lambda e: self._canvas.itemconfig(
                self._steps_win, width=e.width))
        self._canvas.bind_all(
            "<MouseWheel>",
            lambda e: self._canvas.yview_scroll(
                int(-1*(e.delta/120)), "units"))

        self._step_widgets = []   # (StringVar, Label) per row
        self._build_step_rows()

        # ── 5. Bottom buttons ─────────────────────────────────────────────
        btn_bar = tk.Frame(self, bg=BG_WINDOW)
        btn_bar.pack(pady=(0, 22))

        self._enc_btn = HoverButton(
            btn_bar, BTN_ENC, BTN_ENC_H,
            text="ENCRYPT",
            font=FONT_BTN, fg=FG_WHITE,
            relief="flat", bd=0,
            padx=44, pady=10, cursor="hand2",
            command=self._do_encrypt,
        )
        self._enc_btn.pack(side="left", padx=(0, 16))

        self._dec_btn = HoverButton(
            btn_bar, BTN_DEC, BTN_DEC_H,
            text="DECRYPT",
            font=FONT_BTN, fg=FG_WHITE,
            relief="flat", bd=0,
            padx=44, pady=10, cursor="hand2",
            command=self._do_decrypt,
        )
        self._dec_btn.pack(side="left")

    # ─────────────────────────────────────────────────────────────────────
    # STEP ROWS
    # ─────────────────────────────────────────────────────────────────────

    def _build_step_rows(self):
        for w in self._steps_frame.winfo_children():
            w.destroy()
        self._step_widgets = []

        for i in range(8):
            var = tk.StringVar(value="Waiting...")
            lbl = tk.Label(
                self._steps_frame,
                textvariable=var,
                font=FONT_STEP, fg=FG_DIM,
                bg=BG_PANEL, anchor="w",
                padx=20, pady=8,
            )
            lbl.pack(fill="x")
            tk.Frame(self._steps_frame, bg=SEPARATOR, height=1).pack(fill="x")
            self._step_widgets.append((var, lbl))

    def _reset_steps(self):
        for var, lbl in self._step_widgets:
            var.set("Waiting...")
            lbl.configure(fg=FG_DIM)
        self._progress_var.set("0 / 8")

    def _set_step(self, idx, text, color):
        if 0 <= idx < len(self._step_widgets):
            var, lbl = self._step_widgets[idx]
            var.set(text)
            lbl.configure(fg=color)

    # ─────────────────────────────────────────────────────────────────────
    # DATA AREA
    # ─────────────────────────────────────────────────────────────────────

    def _set_data_text(self, content, color=FG_WHITE):
        self._data_text.configure(state="normal")
        self._data_text.delete("1.0", "end")
        self._data_text.insert("1.0", content)
        self._data_text.configure(fg=color)

    def _data_focus_in(self, _=None):
        if self._placeholder_active:
            self._set_data_text("", FG_WHITE)
            self._placeholder_active = False

    def _get_data(self):
        raw = self._data_text.get("1.0", "end-1c").strip()
        if not raw or raw in ("[NO FILE LOADED]", "[COMPLIED BINARY DATA]"):
            return None
        return raw

    # ─────────────────────────────────────────────────────────────────────
    # BROWSE
    # ─────────────────────────────────────────────────────────────────────

    def _browse(self):
        path = filedialog.askopenfilename(
            title="Select file to encrypt / decrypt",
            filetypes=[
                ("All files",       "*.*"),
                ("KOD8 encrypted",  "*.kod8"),
                ("Text files",      "*.txt *.md *.csv *.json"),
                ("Images",          "*.png *.jpg *.jpeg *.webp *.gif *.bmp *.svg"),
                ("Video",           "*.mp4 *.mkv *.avi *.mov *.webm *.flv"),
                ("Documents",       "*.pdf *.docx *.doc *.xlsx *.pptx *.odt"),
            ],
        )
        if not path:
            return

        self._file_path = path
        self._enc_result = None
        fname = os.path.basename(path)
        self._selected_var.set(f"Selected: {fname}")

        try:
            try:
                with open(path, "r", encoding="utf-8") as f:
                    content = f.read()
                self._file_bytes  = content.encode("utf-8")
                self._file_is_bin = False
                self._placeholder_active = False
                self._set_data_text(content, FG_WHITE)
            except UnicodeDecodeError:
                with open(path, "rb") as f:
                    raw = f.read()
                self._file_bytes  = raw
                self._file_is_bin = True
                self._placeholder_active = False
                self._set_data_text("[COMPLIED BINARY DATA]", FG_DIM)

            # preview strategy
            cid = auto_detect(path if self._file_is_bin else content[:500], is_file=self._file_is_bin)
            self._strategy_var.set(CL_STRATEGY.get(cid, "STRATEGY\nAUTO DETECT"))
            self._reset_steps()

        except Exception as e:
            messagebox.showerror("File Error", str(e))

    # ─────────────────────────────────────────────────────────────────────
    # ENCRYPT
    # ─────────────────────────────────────────────────────────────────────

    def _do_encrypt(self):
        if self._busy:
            return

        if self._file_bytes is not None:
            text = (base64.b64encode(self._file_bytes).decode("ascii")
                    if self._file_is_bin
                    else self._file_bytes.decode("utf-8", errors="replace"))
        else:
            text = self._get_data()
            if not text:
                messagebox.showwarning(
                    "No Input",
                    "Upload a file or type text in the input area first.")
                return

        cid = auto_detect(self._file_path if (self._file_bytes and self._file_is_bin) else text[:500], is_file=self._file_is_bin)
        self._strategy_var.set(CL_STRATEGY.get(cid, "STRATEGY\nAUTO DETECT"))
        self._reset_steps()
        self._set_buttons("disabled")
        self._busy = True

        steps_names = [STEP_META.get(fn.__name__, fn.__name__)
                       for fn, _ in CIPHER_LISTS[cid]["steps"]]

        def _worker():
            try:
                used_cid, enc, history = run_kod8_pipeline(text, is_file=self._file_is_bin, encrypt=True, list_id=cid)
                n = len(steps_names)
                for i, name in enumerate(steps_names):
                    self.after(0, self._set_step, i,
                               f"Step {i+1}: {name}  [", FG_DIM)
                    time.sleep(0.10)
                    self.after(0, self._set_step, i,
                               f"Step {i+1}: {name}  [\u2714]", FG_GREEN)
                    self.after(0, self._progress_var.set, f"{i+1} / {n}")
                self._enc_result = enc
                self._enc_cid    = used_cid
                self.after(0, self._finish_encrypt, enc, used_cid)
            except Exception as e:
                self.after(0, self._on_error, str(e))

        threading.Thread(target=_worker, daemon=True).start()

    def _finish_encrypt(self, enc, cid):
        self._busy = False
        self._set_buttons("normal")
        self._strategy_var.set(CL_STRATEGY.get(cid, "STRATEGY\nAUTO DETECT"))
        self._set_data_text(enc, FG_CYAN)
        fname = (os.path.splitext(os.path.basename(self._file_path))[0]
                 if self._file_path else "output")
        self._selected_var.set(
            f"Encrypted  [{cid}]  —  {len(enc):,} chars   |   "
            f"suggested filename: {fname}_enc.kod8")

        if messagebox.askyesno(
                "Save Encrypted Output",
                f"Encryption complete  [{cid}].\n\nSave to a .kod8 file?"):
            default = fname + "_enc.kod8"
            path = filedialog.asksaveasfilename(
                defaultextension=".kod8",
                initialfile=default,
                filetypes=[("KOD8 encrypted", "*.kod8"),
                           ("All files", "*.*")])
            if path:
                with open(path, "w", encoding="utf-8") as f:
                    f.write(f"# KOD8  cipher_id: {cid}\n{enc}")
                self._selected_var.set(f"Saved: {os.path.basename(path)}")

    # ─────────────────────────────────────────────────────────────────────
    # DECRYPT
    # ─────────────────────────────────────────────────────────────────────

    def _do_decrypt(self):
        if self._busy:
            return

        # use last encrypt result if available
        if self._enc_result:
            cipher_text = self._enc_result
            cid         = self._enc_cid
        else:
            raw = self._get_data()
            if not raw:
                messagebox.showwarning(
                    "No Input",
                    "Load a .kod8 file or encrypt something first.")
                return
            lines = raw.splitlines()
            cid   = None
            body_lines = []
            for line in lines:
                if line.startswith("# KOD8  cipher_id:"):
                    cid = line.split(":")[1].strip()
                else:
                    body_lines.append(line)
            cipher_text = "\n".join(body_lines).strip()
            if not cid:
                cid = self._ask_cipher_id()
                if not cid:
                    return

        self._strategy_var.set(CL_STRATEGY.get(cid, "STRATEGY\nAUTO DETECT"))
        self._reset_steps()
        self._set_buttons("disabled")
        self._busy = True

        steps_names = [STEP_META.get(fn.__name__, fn.__name__)
                       for fn, _ in CIPHER_LISTS[cid]["steps"]]

        def _worker():
            try:
                n = len(steps_names)
                for i, name in enumerate(steps_names):
                    self.after(0, self._set_step, i,
                               f"Step {i+1}: {name}  [", FG_DIM)
                    time.sleep(0.09)
                    self.after(0, self._set_step, i,
                               f"Step {i+1}: {name}  [\u2714]", FG_GREEN)
                    self.after(0, self._progress_var.set, f"{i+1} / {n}")
                
                _, dec, history = run_kod8_pipeline(cipher_text, is_file=False, encrypt=False, list_id=cid)
                
                # Check if payload was Base64 binary
                if self._file_is_bin:
                    try:
                        dec = base64.b64decode(dec).decode("latin1")
                    except Exception:
                        pass
                
                self.after(0, self._finish_decrypt, dec, cid)
            except Exception as e:
                self.after(0, self._on_error, str(e))

        threading.Thread(target=_worker, daemon=True).start()

    def _finish_decrypt(self, dec, cid):
        self._busy = False
        self._set_buttons("normal")
        self._set_data_text(dec, FG_GREEN)
        self._selected_var.set(
            f"Decrypted  [{cid}]  —  {len(dec):,} chars")
        self._enc_result = None
        self._prompt_save_decrypted(dec, cid)

    def _prompt_save_decrypted(self, dec, cid):
        if not messagebox.askyesno(
                "Save Decrypted File",
                f"Decryption complete  [{cid}].\n\nSave the decrypted output to a file?"):
            return

        if self._file_path:
            base = os.path.basename(self._file_path)
            for suffix in ("_enc.kod8", ".kod8", "_enc"):
                if base.endswith(suffix):
                    base = base[: -len(suffix)]
                    break
            default_name = base if base else "decrypted_output"
        else:
            default_name = "decrypted_output"

        path = filedialog.asksaveasfilename(
            title="Save decrypted file",
            initialfile=default_name,
            filetypes=[
                ("Text files",   "*.txt"),
                ("All files",    "*.*"),
                ("JSON",         "*.json"),
                ("CSV",          "*.csv"),
            ],
            defaultextension=".txt",
        )
        if not path:
            return

        try:
            mode = "wb" if isinstance(dec, bytes) else "w"
            encoding = None if isinstance(dec, bytes) else "utf-8"
            with open(path, mode, encoding=encoding) as f:
                f.write(dec)
            self._selected_var.set(f"Saved: {os.path.basename(path)}")
        except Exception as e:
            messagebox.showerror("Save Error", str(e))

    # ─────────────────────────────────────────────────────────────────────
    # CIPHER ID DIALOG
    # ─────────────────────────────────────────────────────────────────────

    def _ask_cipher_id(self):
        dlg = tk.Toplevel(self)
        dlg.title("Select Cipher ID")
        dlg.configure(bg=BG_WINDOW)
        dlg.resizable(False, False)
        dlg.grab_set()

        tk.Label(dlg,
                 text="Which cipher list was used to encrypt this file?",
                 font=FONT_MONO_SM, fg=FG_WHITE,
                 bg=BG_WINDOW, padx=16).pack(anchor="w", pady=(14, 6))

        var = tk.StringVar(value="CL1")
        for cid in ["CL1", "CL2", "CL3", "CL4", "CL5", "CL6", "CL7", "CL8"]:
            name = CIPHER_LISTS[cid]["name"]
            tk.Radiobutton(
                dlg,
                text=f"  {cid}  —  {name}",
                variable=var, value=cid,
                font=FONT_MONO_SM, fg=FG_WHITE,
                bg=BG_PANEL, selectcolor=BG_WINDOW,
                activebackground=BG_PANEL,
                relief="flat", anchor="w",
                padx=16, pady=5,
            ).pack(fill="x", padx=12, pady=1)

        result = [None]

        def _ok():
            result[0] = var.get()
            dlg.destroy()

        row = tk.Frame(dlg, bg=BG_WINDOW)
        row.pack(pady=14)
        HoverButton(row, BTN_DEC, BTN_DEC_H,
                    text="Confirm", font=FONT_BTN,
                    fg=FG_WHITE, relief="flat", bd=0,
                    padx=22, pady=6, cursor="hand2",
                    command=_ok).pack(side="left", padx=6)
        HoverButton(row, BG_PANEL, SEPARATOR,
                    text="Cancel", font=FONT_BTN,
                    fg=FG_DIM, relief="flat", bd=0,
                    padx=22, pady=6, cursor="hand2",
                    command=dlg.destroy).pack(side="left", padx=6)

        dlg.wait_window()
        return result[0]

    # ─────────────────────────────────────────────────────────────────────
    # HELPERS
    # ─────────────────────────────────────────────────────────────────────

    def _set_buttons(self, state):
        self._enc_btn.configure(state=state)
        self._dec_btn.configure(state=state)

    def _on_error(self, msg):
        self._busy = False
        self._set_buttons("normal")
        messagebox.showerror("KOD8 Error", msg)


# ═════════════════════════════════════════════════════════════════════════════
# ENTRY POINT
# ═════════════════════════════════════════════════════════════════════════════

if __name__ == "__main__":
    app = Kod8enc()
    app.mainloop()
