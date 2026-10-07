#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
middleware_gui.py — GUI холодного кошелька Monero на ESP32-S3.

Протокол 2 (mwlink): COBS+CRC32 поверх serial или HID, команды
PING/INFO/PUT/GET/STATUS/CLEAR/REQ. Транспорт и обмен файлами целиком
делегированы модулю mwlink.py, который должен лежать рядом.

Что делает GUI:
  • Переключатель транспорта: Авто / Serial / HID.
  • Список exchange/ показывает имя, тип, размер, время. Свежие сверху.
  • Отправка outputs  → получение keyImages.
  • Отправка unsigned → подпись на устройстве → сохранение
    <prefix><ts>_signed_monero_tx (формат Feather) + sidecar .json.
  • Кнопка «Отправить в сеть»: если в sidecar есть raw_tx_hex — RPC,
    иначе диалог с подсказкой импортировать Feather-файл вручную.
  • «Получить view key» / «Получить адрес» через CMD_REQ (REQ_VIEWONLY /
    REQ_ADDRESS); результат приходит в outbox как wallet_export (JSON).
  • История кошелька: всё, что проходило через устройство.
  • Журнал: события устройства (P/E/I/D) и хоста.

Зависимости: pyserial, requests, hidapi (опционально для HID).
Рядом должен лежать mwlink.py (протокол 2).
"""

import os
import sys
import json
import time
import zlib
import queue
import threading
import traceback
import datetime as _dt
import tkinter as tk
from tkinter import ttk, messagebox, font as tkfont

# --- зависимость: mwlink ----------------------------------------------------
try:
    import mwlink
except ImportError:
    print("Рядом должен лежать mwlink.py (протокол 2).")
    sys.exit(1)

try:
    import serial.tools.list_ports  # noqa: F401
except ImportError:
    pass

try:
    import requests
except ImportError:
    requests = None


# ============================================================================
# Пути и константы
# ============================================================================
def _app_dir():
    if getattr(sys, "frozen", False):
        return os.path.dirname(os.path.abspath(sys.executable))
    return os.path.dirname(os.path.abspath(__file__))


APP_DIR      = _app_dir()
EXCHANGE_DIR = os.path.join(APP_DIR, "exchange")
CONFIG_PATH  = os.path.join(APP_DIR, "config.json")
HISTORY_PATH = os.path.join(EXCHANGE_DIR, "wallet_history.json")
HISTORY_MAX  = 500

SIDECAR_SUFFIX = ".json"

TRANSPORT_LABELS = {"auto": "Авто", "serial": "Serial", "hid": "HID"}
TRANSPORT_KEYS   = {v: k for k, v in TRANSPORT_LABELS.items()}

DEFAULT_CONFIG = {
    "transport":     "auto",
    "serial_port":   "",
    "rpc_url":       "http://127.0.0.1:18081",
    "rpc_user":      "",
    "rpc_password":  "",
}


# ============================================================================
# Тема
# ============================================================================
class C:
    bg          = "#0d1016"
    bg_card     = "#181d27"
    bg_elev     = "#222836"
    bg_input    = "#262d3d"
    bg_hover    = "#2f3747"
    bg_active   = "#3b4459"
    bg_log      = "#0b0e13"

    border      = "#2c3342"
    border_hi   = "#3d4657"

    text        = "#f7f9fc"
    text_dim    = "#b6bece"
    text_mute   = "#7d8698"

    accent      = "#ff8a3d"
    accent_hi   = "#ffa55e"
    accent_lo   = "#c96a1c"
    accent_glow = "#4a2c12"

    warm_bg     = "#3a2410"
    warm_bg_hi  = "#56371b"
    warm_bg_off = "#1c1410"
    warm_fg     = "#ffb87a"
    warm_fg_off = "#5c4a3c"

    success     = "#3ddc84"
    error       = "#ff5c5c"
    warning     = "#ffb74d"
    info        = "#7cb8ff"


FONT_UI    = "TkDefaultFont"
FONT_MONO  = "TkFixedFont"

SZ_BASE    = 11
SZ_SMALL   = 10
SZ_TINY    = 9
SZ_MONO    = 11
SZ_MONO_SM = 10
SZ_TITLE   = 16
SZ_CARD    = 13


def detect_fonts():
    global FONT_UI, FONT_MONO
    try:
        families = set(tkfont.families())
    except Exception:
        families = set()
    ui_candidates = [
        "Inter", "SF Pro Display", "Segoe UI Variable", "Segoe UI",
        "SF Pro Text", "Ubuntu", "Cantarell", "Noto Sans",
        "Helvetica Neue", "Helvetica", "Arial",
    ]
    mono_candidates = [
        "JetBrains Mono", "Cascadia Code", "SF Mono", "Fira Code",
        "Consolas", "Menlo", "DejaVu Sans Mono", "Courier New", "Courier",
    ]
    ui = next((f for f in ui_candidates if f in families), None)
    mono = next((f for f in mono_candidates if f in families), None)
    if ui is None:
        ui = tkfont.nametofont("TkDefaultFont").actual("family")
    if mono is None:
        mono = tkfont.nametofont("TkFixedFont").actual("family")
    FONT_UI = ui
    FONT_MONO = mono


def enable_dark_title_bar(root: tk.Tk):
    if sys.platform != "win32":
        return
    try:
        import ctypes
        root.update_idletasks()
        hwnd = ctypes.windll.user32.GetParent(root.winfo_id()) or root.winfo_id()
        value = ctypes.c_int(1)
        for attr in (20, 19):
            if ctypes.windll.dwmapi.DwmSetWindowAttribute(
                    hwnd, attr, ctypes.byref(value), ctypes.sizeof(value)) == 0:
                break
        root.withdraw()
        root.after(10, root.deiconify)
    except Exception:
        pass


def setup_theme(root):
    style = ttk.Style(root)
    try:
        style.theme_use("clam")
    except Exception:
        pass
    root.configure(bg=C.bg)

    style.configure(".", background=C.bg, foreground=C.text,
                    font=(FONT_UI, SZ_BASE), borderwidth=0, focuscolor=C.accent)
    style.configure("TFrame", background=C.bg)
    style.configure("TLabel", background=C.bg, foreground=C.text,
                    font=(FONT_UI, SZ_BASE))

    style.configure("TEntry",
                    fieldbackground=C.bg_input, background=C.bg_input,
                    foreground=C.text, insertcolor=C.accent,
                    bordercolor=C.border,
                    lightcolor=C.bg_input, darkcolor=C.bg_input,
                    borderwidth=1, relief="flat",
                    padding=(12, 10), font=(FONT_UI, SZ_BASE))
    style.map("TEntry",
              bordercolor=[("focus", C.accent)],
              lightcolor=[("focus", C.bg_input)],
              darkcolor=[("focus", C.bg_input)])

    style.configure("TCombobox",
                    fieldbackground=C.bg_input, background=C.bg_input,
                    foreground=C.text, arrowcolor=C.text_dim,
                    bordercolor=C.border,
                    lightcolor=C.bg_input, darkcolor=C.bg_input,
                    borderwidth=1, relief="flat",
                    padding=(12, 8), font=(FONT_UI, SZ_BASE))
    style.map("TCombobox",
              fieldbackground=[("readonly", C.bg_input), ("focus", C.bg_input)],
              bordercolor=[("focus", C.accent)],
              arrowcolor=[("active", C.accent)])

    style.configure("Files.Treeview",
                    background=C.bg_card, fieldbackground=C.bg_card,
                    foreground=C.text, borderwidth=0, relief="flat",
                    rowheight=40, font=(FONT_UI, SZ_BASE))
    style.map("Files.Treeview",
              background=[("selected", C.bg_active)],
              foreground=[("selected", C.accent_hi)])
    style.configure("Files.Treeview.Heading",
                    background=C.bg_card, foreground=C.text_mute,
                    font=(FONT_UI, SZ_TINY, "bold"),
                    borderwidth=0, relief="flat", padding=(12, 10))
    style.map("Files.Treeview.Heading",
              background=[("active", C.bg_card)],
              foreground=[("active", C.text)])
    style.layout("Files.Treeview", [("Treeview.treearea", {"sticky": "nswe"})])

    style.configure("Vertical.TScrollbar",
                    background=C.bg_elev, troughcolor=C.bg_card,
                    bordercolor=C.bg_card, arrowcolor=C.text_mute,
                    borderwidth=0, width=12, arrowsize=14)
    style.map("Vertical.TScrollbar", background=[("active", C.bg_hover)])


# ============================================================================
# CopyField
# ============================================================================
class CopyField(tk.Frame):
    def __init__(self, parent, value, *, mono=True, size=SZ_MONO_SM,
                 bg=C.bg_elev, fg=None, height=1, wrap="none"):
        super().__init__(parent, bg=bg, highlightthickness=0, bd=0)
        fg = fg if fg is not None else C.text

        self._txt = tk.Text(
            self, height=height, wrap=wrap,
            bg=bg, fg=fg,
            font=(FONT_MONO if mono else FONT_UI, size),
            insertbackground=C.accent,
            selectbackground=C.accent_glow,
            selectforeground=C.text,
            relief="flat", borderwidth=0,
            padx=0, pady=0, highlightthickness=0, cursor="xterm",
        )
        self._txt.insert("1.0", value if value is not None else "")
        self._txt.configure(state="disabled")
        self._txt.pack(fill="both", expand=True)

        self._menu = tk.Menu(self._txt, tearoff=0,
                             bg=C.bg_elev, fg=C.text,
                             activebackground=C.accent, activeforeground="#fff",
                             borderwidth=0)
        self._menu.add_command(label="Копировать", command=self._copy_sel)
        self._menu.add_command(label="Копировать всё", command=self._copy_all)
        self._txt.bind("<Button-3>", self._popup)
        self._txt.bind("<Control-c>", lambda e: (self._copy_sel(), "break")[1])
        self._txt.bind("<Control-C>", lambda e: (self._copy_sel(), "break")[1])
        self._txt.bind("<Control-a>", lambda e: (self._select_all(), "break")[1])
        self._txt.bind("<Control-A>", lambda e: (self._select_all(), "break")[1])

    def _select_all(self):
        self._txt.tag_add("sel", "1.0", "end-1c")

    def _copy_sel(self):
        try:
            s = self._txt.get("sel.first", "sel.last")
        except tk.TclError:
            return
        self.clipboard_clear()
        self.clipboard_append(s)

    def _copy_all(self):
        s = self._txt.get("1.0", "end-1c")
        self.clipboard_clear()
        self.clipboard_append(s)

    def _popup(self, e):
        try:
            self._menu.tk_popup(e.x_root, e.y_root)
        finally:
            self._menu.grab_release()


# ============================================================================
# ModernButton
# ============================================================================
class ModernButton(tk.Canvas):
    VARIANTS = {
        "primary": {"bg": C.accent, "bg_hi": C.accent_hi, "bg_off": C.accent_lo,
                    "fg": "#ffffff", "fg_off": "#6b3a14"},
        "ghost":   {"bg": C.warm_bg, "bg_hi": C.warm_bg_hi, "bg_off": C.warm_bg_off,
                    "fg": C.warm_fg, "fg_off": C.warm_fg_off},
        "danger":  {"bg": C.error, "bg_hi": "#ff7d7d", "bg_off": "#5c1a1a",
                    "fg": "#ffffff", "fg_off": "#7a3030"},
    }

    def __init__(self, parent, text="", command=None,
                 variant="ghost", icon="", width=None, height=42,
                 bg=None, font_size=SZ_BASE, bold=True):
        if bg is None:
            try:
                bg = parent.cget("bg")
            except Exception:
                bg = C.bg_card
        if width is None:
            width = 24 + 10 * (len(text) + (2 if icon else 0))
        super().__init__(parent, width=width, height=height,
                         bg=bg, highlightthickness=0, bd=0)
        self._text = text
        self._icon = icon
        self._command = command
        self._variant = variant
        self._cw = width
        self._ch = height
        self._font_size = font_size
        self._bold = bold
        self._enabled = True
        self._state = "normal"
        self.bind("<Enter>",           self._on_enter)
        self.bind("<Leave>",           self._on_leave)
        self.bind("<Button-1>",        self._on_press)
        self.bind("<ButtonRelease-1>", self._on_release)
        self._draw()

    def _palette(self):
        v = self.VARIANTS[self._variant]
        if not self._enabled:
            return v["bg_off"], v["fg_off"]
        if self._state in ("hover", "press"):
            return v["bg_hi"], v["fg"]
        return v["bg"], v["fg"]

    def _rounded_rect(self, x1, y1, x2, y2, r, **kw):
        pts = [x1 + r, y1, x2 - r, y1, x2, y1,
               x2, y1 + r, x2, y2 - r, x2, y2,
               x2 - r, y2, x1 + r, y2, x1, y2,
               x1, y2 - r, x1, y1 + r, x1, y1]
        return self.create_polygon(pts, smooth=True, **kw)

    def _draw(self):
        self.delete("all")
        bg, fg = self._palette()
        outline = C.warm_bg_hi if (self._variant == "ghost" and self._enabled) else ""
        self._rounded_rect(1, 1, self._cw - 1, self._ch - 1, 12,
                           fill=bg, outline=outline,
                           width=1 if outline else 0)
        label = f"{self._icon}  {self._text}".strip() if self._icon else self._text
        weight = "bold" if self._bold else "normal"
        self.create_text(self._cw // 2, self._ch // 2, text=label, fill=fg,
                         font=(FONT_UI, self._font_size, weight))

    def _on_enter(self, _):
        if not self._enabled:
            return
        self._state = "hover"
        self.configure(cursor="hand2")
        self._draw()

    def _on_leave(self, _):
        self._state = "normal"
        self.configure(cursor="")
        self._draw()

    def _on_press(self, _):
        if not self._enabled:
            return
        self._state = "press"
        self._draw()

    def _on_release(self, _):
        if not self._enabled:
            return
        self._state = "hover"
        self._draw()
        if self._command:
            self._command()

    def set_enabled(self, enabled):
        self._enabled = bool(enabled)
        self.configure(cursor="hand2" if enabled else "")
        self._draw()

    def set_text(self, text):
        self._text = text
        self._draw()


# ============================================================================
# StatusPill
# ============================================================================
class StatusPill(tk.Canvas):
    def __init__(self, parent, bg=C.bg):
        super().__init__(parent, width=280, height=42,
                         bg=bg, highlightthickness=0, bd=0)
        self._color = C.text_mute
        self._label = "ESP32 отключено"
        self.bind("<Configure>", lambda e: self._draw(e.width))
        self._draw(280)

    def set(self, label, color):
        self._label = label
        self._color = color
        self._draw(self.winfo_width() or 280)

    def _rounded_rect(self, x1, y1, x2, y2, r, **kw):
        pts = [x1 + r, y1, x2 - r, y1, x2, y1,
               x2, y1 + r, x2, y2 - r, x2, y2,
               x2 - r, y2, x1 + r, y2, x1, y2,
               x1, y2 - r, x1, y1 + r, x1, y1]
        return self.create_polygon(pts, smooth=True, **kw)

    def _draw(self, w):
        self.delete("all")
        h = 42
        w = max(w, 80)
        r = h // 2
        self._rounded_rect(0, 0, w, h, r, fill=C.bg_elev, outline="")
        cx, cy = 22, h // 2
        self.create_oval(cx - 6, cy - 6, cx + 6, cy + 6, fill=self._color, outline="")
        self.create_text(42, h // 2, anchor="w", text=self._label,
                         fill=C.text, font=(FONT_UI, SZ_BASE, "bold"))


# ============================================================================
# Card
# ============================================================================
class Card(tk.Frame):
    def __init__(self, parent, title="", subtitle="", pad=16, bg=C.bg_card):
        super().__init__(parent, bg=C.bg, highlightthickness=0)
        outer = tk.Frame(self, bg=bg, highlightthickness=0)
        outer.pack(fill="both", expand=True)

        head = tk.Frame(outer, bg=bg, highlightthickness=0)
        head.pack(fill="x", padx=pad, pady=(pad, 0))

        title_wrap = tk.Frame(head, bg=bg)
        title_wrap.pack(side="left", anchor="w")
        tk.Label(title_wrap, text=title, bg=bg, fg=C.text,
                 font=(FONT_UI, SZ_CARD, "bold")).pack(anchor="w")
        self._subtitle = tk.Label(title_wrap, text=subtitle, bg=bg,
                                  fg=C.text_mute, font=(FONT_UI, SZ_SMALL))
        if subtitle:
            self._subtitle.pack(anchor="w", pady=(2, 0))
        else:
            self._subtitle.pack_forget()

        self.actions = tk.Frame(head, bg=bg)
        self.actions.pack(side="right", anchor="e")

        tk.Frame(outer, bg=C.border, height=1)\
            .pack(fill="x", padx=pad, pady=(10, 0))

        self.body = tk.Frame(outer, bg=bg)
        self.body.pack(fill="both", expand=True, padx=pad, pady=(10, pad))


# ============================================================================
# Конфиг
# ============================================================================
def load_config():
    cfg = dict(DEFAULT_CONFIG)
    if os.path.exists(CONFIG_PATH):
        try:
            with open(CONFIG_PATH, "r", encoding="utf-8") as f:
                cfg.update(json.load(f))
        except Exception:
            pass
    return cfg


def save_config(cfg):
    try:
        with open(CONFIG_PATH, "w", encoding="utf-8") as f:
            json.dump(cfg, f, indent=2, ensure_ascii=False)
    except Exception:
        pass


# ============================================================================
# Утилиты
# ============================================================================
def human_size(n):
    if n < 1024:
        return f"{n} B"
    if n < 1024 * 1024:
        return f"{n / 1024:.1f} KB"
    return f"{n / (1024 * 1024):.2f} MB"


def format_mtime(ts):
    dt = time.localtime(ts)
    now = time.localtime()
    if dt.tm_year == now.tm_year:
        return time.strftime("%d.%m %H:%M:%S", dt)
    return time.strftime("%d.%m.%Y", dt)


def sidecar_path(path):
    return path + SIDECAR_SUFFIX


def load_sidecar(path):
    p = sidecar_path(path)
    if not os.path.isfile(p):
        return None
    try:
        with open(p, "r", encoding="utf-8") as f:
            return json.load(f)
    except Exception:
        return None


def save_sidecar(path, obj):
    try:
        with open(sidecar_path(path), "w", encoding="utf-8") as f:
            json.dump(obj, f, indent=2, ensure_ascii=False)
        return True
    except Exception:
        return False


def kind_label(kind_int):
    try:
        return mwlink.KINDS[kind_int]
    except Exception:
        return "?"


def detect_kind_label(path):
    try:
        with open(path, "rb") as f:
            head = f.read(64)
    except Exception:
        return "?"
    k = mwlink.detect_kind(head)
    if k is None:
        return "?"
    return kind_label(k)


# ============================================================================
# История
# ============================================================================
def load_history():
    if not os.path.isfile(HISTORY_PATH):
        return []
    try:
        with open(HISTORY_PATH, "r", encoding="utf-8") as f:
            return json.load(f) or []
    except Exception:
        return []


def append_history(entry):
    hist = load_history()
    hist.append(entry)
    if len(hist) > HISTORY_MAX:
        hist = hist[-HISTORY_MAX:]
    try:
        with open(HISTORY_PATH, "w", encoding="utf-8") as f:
            json.dump(hist, f, indent=2, ensure_ascii=False)
    except Exception:
        pass


# ============================================================================
# Monero RPC
# ============================================================================
def rpc_call(cfg, method, params=None, timeout=30):
    if requests is None:
        raise RuntimeError("Установите requests")
    url = cfg["rpc_url"].rstrip("/") + "/json_rpc"
    body = {"jsonrpc": "2.0", "id": "0", "method": method}
    if params is not None:
        body["params"] = params
    auth = (cfg["rpc_user"], cfg.get("rpc_password", "")) if cfg.get("rpc_user") else None
    resp = requests.post(url, json=body, auth=auth, timeout=timeout)
    resp.raise_for_status()
    return resp.json()


def rpc_send_raw_tx(cfg, tx_hex):
    if requests is None:
        raise RuntimeError("Установите requests")
    url = cfg["rpc_url"].rstrip("/")
    if url.endswith("/json_rpc"):
        endpoint = url
        body = {"jsonrpc": "2.0", "id": "0",
                "method": "send_raw_transaction",
                "params": {"tx_as_hex": tx_hex}}
    else:
        endpoint = url + "/send_raw_transaction"
        body = {"tx_as_hex": tx_hex}
    auth = (cfg["rpc_user"], cfg.get("rpc_password", "")) if cfg.get("rpc_user") else None
    resp = requests.post(endpoint, json=body, auth=auth, timeout=120)
    resp.raise_for_status()
    return resp.json()


# ============================================================================
# FileInfoDialog
# ============================================================================
class FileInfoDialog(tk.Toplevel):
    def __init__(self, parent, path, kind_label_str):
        super().__init__(parent)
        self.title(f"Детали: {os.path.basename(path)}")
        self.transient(parent)
        self.grab_set()
        self.configure(bg=C.bg)
        self.geometry("960x680")

        try:
            size = os.path.getsize(path)
            mtime = os.path.getmtime(path)
            with open(path, "rb") as f:
                data = f.read()
        except Exception as e:
            messagebox.showerror("Ошибка", str(e))
            self.destroy()
            return

        root = tk.Frame(self, bg=C.bg)
        root.pack(fill="both", expand=True, padx=16, pady=16)
        card = Card(root, title=os.path.basename(path),
                    subtitle=f"{kind_label_str} · {human_size(size)}", pad=18)
        card.pack(fill="both", expand=True)

        # прокрутка
        wrap = tk.Frame(card.body, bg=C.bg_card)
        wrap.pack(fill="both", expand=True)
        canvas = tk.Canvas(wrap, bg=C.bg_card, highlightthickness=0)
        vs = ttk.Scrollbar(wrap, orient="vertical", command=canvas.yview)
        canvas.configure(yscrollcommand=vs.set)
        vs.pack(side="right", fill="y")
        canvas.pack(side="left", fill="both", expand=True)
        inner = tk.Frame(canvas, bg=C.bg_card)
        win_id = canvas.create_window((0, 0), window=inner, anchor="nw")
        inner.bind("<Configure>", lambda e: canvas.configure(scrollregion=canvas.bbox("all")))
        canvas.bind("<Configure>", lambda e: canvas.itemconfigure(win_id, width=e.width))

        self._kv(inner, "Тип", kind_label_str)
        self._kv(inner, "Файл", os.path.basename(path))
        self._kv(inner, "Путь", path)
        self._kv(inner, "Размер", f"{size} байт")
        self._kv(inner, "Изменён",
                 time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(mtime)))
        self._kv(inner, "CRC32 файла", f"{zlib.crc32(data) & 0xFFFFFFFF:08x}", mono=True)

        # Разбор контейнера (магия / версия / iv) — без расшифровки
        magic = None
        for m in (b"Monero signed tx set", b"Monero key image export",
                  b"Monero output export", b"Monero unsigned tx set"):
            if data.startswith(m):
                magic = m
                break
        if magic is not None:
            self._section(inner, "Контейнер")
            self._kv(inner, "Magic", magic.decode("ascii", "replace"))
            self._kv(inner, "Длина magic", f"{len(magic)} байт")
            if len(data) > len(magic):
                self._kv(inner, "Version", f"{data[len(magic)]:#04x}")
            if len(data) >= len(magic) + 8:
                self._kv(inner, "IV (8 байт)",
                         data[len(magic):len(magic) + 8].hex(), mono=True)
            if len(data) > len(magic) + 8 + 64:
                self._kv(inner, "Размер шифротекста",
                         f"{len(data) - len(magic) - 8 - 64} байт")
            self._kv(inner, "Подпись",
                     data[-64:].hex() if len(data) >= 64 else "", mono=True)

        side = load_sidecar(path)
        if side:
            self._section(inner, "Sidecar JSON")
            for key in sorted(side.keys()):
                self._kv(inner, key, str(side[key]), mono=True)

        self._section(inner, "Первые 256 байт (hex)")
        self._hexdump(inner, data[:256])

        foot = tk.Frame(card.body, bg=C.bg_card)
        foot.pack(fill="x", pady=(14, 0))
        ModernButton(foot, text="Закрыть", variant="ghost",
                     command=self.destroy, width=160, height=44).pack(side="right")

    def _kv(self, parent, key, val, mono=False):
        row = tk.Frame(parent, bg=C.bg_elev)
        row.pack(fill="x", pady=2)
        tk.Label(row, text=key, bg=C.bg_elev, fg=C.text_mute,
                 font=(FONT_UI, SZ_TINY), anchor="w", width=22)\
            .pack(side="left", anchor="n")
        CopyField(row, val, mono=mono,
                  size=SZ_MONO_SM if mono else SZ_BASE,
                  bg=C.bg_elev, fg=C.text,
                  wrap="word" if mono and len(str(val)) > 80 else "none",
                  height=2 if mono and len(str(val)) > 80 else 1)\
            .pack(side="left", fill="x", expand=True)

    def _section(self, parent, text):
        tk.Label(parent, text=text.upper(), bg=C.bg_card, fg=C.text_mute,
                 font=(FONT_UI, SZ_TINY, "bold"), anchor="w")\
            .pack(fill="x", pady=(16, 6))
        tk.Frame(parent, bg=C.border, height=1).pack(fill="x", pady=(0, 8))

    def _hexdump(self, parent, data):
        for off in range(0, len(data), 32):
            chunk = data[off:off + 32]
            hexs = " ".join(f"{b:02x}" for b in chunk)
            row = tk.Frame(parent, bg=C.bg_input)
            row.pack(fill="x", pady=1)
            CopyField(row, f"{off:04x}  {hexs}", mono=True, size=SZ_MONO_SM,
                      bg=C.bg_input, fg=C.text, height=1)\
                .pack(fill="x", padx=12, pady=6)


# ============================================================================
# HistoryDialog
# ============================================================================
KIND_COLORS = {
    "keyimages":      C.info,
    "signed_tx":      C.success,
    "signed_tx_sent": C.success,
    "viewonly":       C.warning,
    "address":        C.warning,
    "outputs":        C.accent,
    "unsigned_tx":    C.text_dim,
}


class HistoryDialog(tk.Toplevel):
    def __init__(self, parent, entries):
        super().__init__(parent)
        self.title("История кошелька")
        self.transient(parent)
        self.grab_set()
        self.configure(bg=C.bg)
        self.geometry("1200x760")
        self.entries = entries

        root = tk.Frame(self, bg=C.bg)
        root.pack(fill="both", expand=True, padx=16, pady=16)
        card = Card(root, title="История кошелька",
                    subtitle=f"Записей: {len(entries)} · свежие сверху · "
                             f"двойной клик = детали",
                    pad=18)
        card.pack(fill="both", expand=True)

        wrap = tk.Frame(card.body, bg=C.bg_card)
        wrap.pack(fill="both", expand=True)
        canvas = tk.Canvas(wrap, bg=C.bg_card, highlightthickness=0)
        vs = ttk.Scrollbar(wrap, orient="vertical", command=canvas.yview)
        canvas.configure(yscrollcommand=vs.set)
        vs.pack(side="right", fill="y")
        canvas.pack(side="left", fill="both", expand=True)
        inner = tk.Frame(canvas, bg=C.bg_card)
        win_id = canvas.create_window((0, 0), window=inner, anchor="nw")
        inner.bind("<Configure>", lambda e: canvas.configure(scrollregion=canvas.bbox("all")))
        canvas.bind("<Configure>", lambda e: canvas.itemconfigure(win_id, width=e.width))

        if not entries:
            tk.Label(inner, text="Пока ничего не проходило через кошелёк",
                     bg=C.bg_card, fg=C.text_mute,
                     font=(FONT_UI, SZ_BASE)).pack(pady=30)
        else:
            for e in sorted(entries, key=lambda x: x.get("time", ""), reverse=True):
                self._build_entry(inner, e)

        foot = tk.Frame(card.body, bg=C.bg_card)
        foot.pack(fill="x", pady=(14, 0))
        ModernButton(foot, text="Очистить историю", variant="ghost",
                     command=self._clear, width=200, height=44).pack(side="left")
        ModernButton(foot, text="Закрыть", variant="ghost",
                     command=self.destroy, width=160, height=44).pack(side="right")

    def _clear(self):
        if not messagebox.askyesno("Очистить историю",
                                   "Удалить все записи истории?"):
            return
        try:
            with open(HISTORY_PATH, "w", encoding="utf-8") as f:
                json.dump([], f)
        except Exception as e:
            messagebox.showerror("Ошибка", str(e))
            return
        self.destroy()

    def _build_entry(self, parent, e):
        kind = e.get("kind", "?")
        color = KIND_COLORS.get(kind, C.text_dim)

        box = tk.Frame(parent, bg=C.bg_elev)
        box.pack(fill="x", pady=5)
        tk.Frame(box, bg=color, width=4).pack(side="left", fill="y")
        body = tk.Frame(box, bg=C.bg_elev)
        body.pack(fill="x", padx=16, pady=12)

        head = tk.Frame(body, bg=C.bg_elev)
        head.pack(fill="x")
        tk.Label(head, text=e.get("time", "?"), bg=C.bg_elev, fg=C.text_mute,
                 font=(FONT_UI, SZ_SMALL)).pack(side="left")
        tk.Label(head, text=kind, bg=C.bg_elev, fg=color,
                 font=(FONT_UI, SZ_TINY, "bold")).pack(side="left", padx=(12, 0))
        tk.Label(head, text=human_size(e.get("size", 0)),
                 bg=C.bg_elev, fg=C.text_dim,
                 font=(FONT_UI, SZ_SMALL)).pack(side="right")

        file_row = tk.Frame(body, bg=C.bg_elev)
        file_row.pack(fill="x", pady=(4, 0))
        tk.Label(file_row, text="Файл:", bg=C.bg_elev, fg=C.text_mute,
                 font=(FONT_UI, SZ_TINY), width=6, anchor="w").pack(side="left")
        CopyField(file_row, e.get("file", "?"), mono=True, size=SZ_MONO_SM,
                  bg=C.bg_elev, fg=C.text, height=1)\
            .pack(side="left", fill="x", expand=True)

        if e.get("txid"):
            tx_row = tk.Frame(body, bg=C.bg_elev)
            tx_row.pack(fill="x", pady=(2, 0))
            tk.Label(tx_row, text="TxID:", bg=C.bg_elev, fg=C.text_mute,
                     font=(FONT_UI, SZ_TINY), width=6, anchor="w").pack(side="left")
            CopyField(tx_row, e["txid"], mono=True, size=SZ_MONO_SM,
                      bg=C.bg_elev, fg=C.text_dim, height=1)\
                .pack(side="left", fill="x", expand=True)

        if e.get("note"):
            tk.Label(body, text=e["note"], bg=C.bg_elev, fg=C.text_dim,
                     font=(FONT_UI, SZ_TINY), anchor="w")\
                .pack(fill="x", pady=(2, 0))

        for w in (box, body, head, file_row):
            w.bind("<Double-1>", lambda ev, ent=e: self._open_detail(ent))

    def _open_detail(self, entry):
        dlg = tk.Toplevel(self)
        dlg.title("Детали записи")
        dlg.transient(self)
        dlg.grab_set()
        dlg.configure(bg=C.bg)
        dlg.geometry("960x620")
        root = tk.Frame(dlg, bg=C.bg)
        root.pack(fill="both", expand=True, padx=16, pady=16)
        card = Card(root, title=entry.get("kind", "?"),
                    subtitle=entry.get("time", "?"), pad=18)
        card.pack(fill="both", expand=True)

        # кнопка «открыть файл», если он ещё на диске
        fname = entry.get("file", "")
        fpath = os.path.join(EXCHANGE_DIR, fname) if fname else ""
        if fpath and os.path.isfile(fpath):
            ModernButton(card.body, text="Показать детали файла", icon="ⓘ",
                         variant="primary",
                         command=lambda p=fpath, k=entry.get("kind", "?"):
                             FileInfoDialog(dlg, p, k),
                         width=260, height=44).pack(anchor="w", pady=(0, 10))

        for key in ("kind", "file", "size", "sha3_256", "crc32", "magic",
                    "version", "iv", "txid", "note"):
            if key in entry and entry[key] not in (None, ""):
                row = tk.Frame(card.body, bg=C.bg_card)
                row.pack(fill="x", pady=2)
                tk.Label(row, text=key, bg=C.bg_card, fg=C.text_mute,
                         font=(FONT_UI, SZ_TINY), anchor="w", width=14)\
                    .pack(side="left", anchor="n")
                CopyField(row, str(entry[key]), mono=True, size=SZ_MONO_SM,
                          bg=C.bg_card, fg=C.text, wrap="word", height=2)\
                    .pack(side="left", fill="x", expand=True)

        foot = tk.Frame(card.body, bg=C.bg_card)
        foot.pack(fill="x", pady=(14, 0))
        ModernButton(foot, text="Закрыть", variant="ghost",
                     command=dlg.destroy, width=160, height=44).pack(side="right")


# ============================================================================
# App
# ============================================================================
class App:
    def __init__(self, root: tk.Tk):
        self.root = root
        self.cfg = load_config()
        self.wallet = None
        self.transport = None
        self.exchange = None
        self.event_q = queue.Queue()
        self.busy = False
        self.file_info = {}
        self._pending_req = None

        root.title("Monero Cold Wallet")
        root.minsize(1100, 660)
        root.configure(bg=C.bg)

        detect_fonts()
        setup_theme(root)
        enable_dark_title_bar(root)

        self._build_ui()
        self._refresh_files()
        self._autosize_window()

        self.root.protocol("WM_DELETE_WINDOW", self._on_close)
        self.root.after(80, self._poll_events)
        self.root.after(200, self._poll_device)

    def _autosize_window(self):
        self.root.update_idletasks()
        req_w = self.root.winfo_reqwidth()
        req_h = self.root.winfo_reqheight()
        sw = self.root.winfo_screenwidth()
        sh = self.root.winfo_screenheight()
        max_w = min(int(sw * 0.95), 1560)
        max_h = sh - 120
        w = max(1100, min(req_w, max_w))
        h = max(660, min(req_h, max_h))
        self.root.geometry(f"{w}x{h}")
        self.root.update_idletasks()
        px = max(0, (sw - w) // 2)
        py = max(0, (sh - h) // 2 - 20)
        self.root.geometry(f"+{px}+{py}")

    # ------------------------------------------------------------------ UI
    def _build_ui(self):
        header = tk.Frame(self.root, bg=C.bg)
        header.pack(fill="x", padx=24, pady=(16, 0))
        brand = tk.Frame(header, bg=C.bg)
        brand.pack(side="left")
        logo = tk.Canvas(brand, width=48, height=48, bg=C.bg, highlightthickness=0)
        logo.pack(side="left")
        logo.create_oval(2, 2, 46, 46, fill=C.accent_glow, outline="")
        logo.create_text(24, 24, text="◈", fill=C.accent, font=(FONT_UI, 22, "bold"))
        text = tk.Frame(brand, bg=C.bg)
        text.pack(side="left", padx=(14, 0))
        tk.Label(text, text="Monero Cold Wallet", bg=C.bg, fg=C.text,
                 font=(FONT_UI, SZ_TITLE, "bold")).pack(anchor="w")
        tk.Label(text, text="ESP32-S3 · protocol 2 (mwlink)",
                 bg=C.bg, fg=C.text_mute,
                 font=(FONT_UI, SZ_BASE)).pack(anchor="w", pady=(2, 0))
        self.status_pill = StatusPill(header, bg=C.bg)
        self.status_pill.pack(side="right")

        tk.Frame(self.root, bg=C.bg, height=12).pack(fill="x")

        # CONNECTION
        conn = Card(self.root, title="Подключение",
                    subtitle="ESP32 и узел Monero", pad=16)
        conn.pack(fill="x", padx=24)
        grid = tk.Frame(conn.body, bg=C.bg_card)
        grid.pack(fill="x")

        self._label(grid, "Транспорт", 0, 0)
        self.transport_var = tk.StringVar(
            value=TRANSPORT_LABELS.get(self.cfg.get("transport", "auto"), "Авто"))
        self.transport_cb = ttk.Combobox(
            grid, textvariable=self.transport_var, width=10,
            values=list(TRANSPORT_LABELS.values()), state="readonly")
        self.transport_cb.grid(row=1, column=0, sticky="w", padx=(0, 12), pady=(4, 0))
        self.transport_cb.bind("<<ComboboxSelected>>",
                               lambda e: self._on_transport_changed())

        self._label(grid, "Порт ESP32", 0, 1)
        self.port_var = tk.StringVar(value=self.cfg["serial_port"])
        self.port_cb = ttk.Combobox(grid, textvariable=self.port_var, width=20)
        self.port_cb.grid(row=1, column=1, sticky="w", padx=(0, 8), pady=(4, 0))
        self.scan_btn = ModernButton(grid, text="", icon="⟳", variant="ghost",
                                     command=self._scan_ports, width=44, height=40,
                                     font_size=15)
        self.scan_btn.grid(row=1, column=2, sticky="w", padx=(0, 16), pady=(4, 0))

        self.connect_btn = ModernButton(grid, text="Подключиться",
                                        variant="primary",
                                        command=self._on_connect,
                                        width=180, height=40, font_size=SZ_BASE)
        self.connect_btn.grid(row=1, column=3, sticky="w", pady=(4, 0))

        self._label(grid, "Monero RPC", 2, 0, top=14)
        self.rpc_url_var = tk.StringVar(value=self.cfg["rpc_url"])
        ttk.Entry(grid, textvariable=self.rpc_url_var)\
            .grid(row=3, column=0, columnspan=2, sticky="we", padx=(0, 16), pady=(4, 0))
        self._label(grid, "User", 2, 2, top=14)
        self.rpc_user_var = tk.StringVar(value=self.cfg["rpc_user"])
        ttk.Entry(grid, textvariable=self.rpc_user_var, width=12)\
            .grid(row=3, column=2, sticky="w", pady=(4, 0))
        self.rpc_pass_var = tk.StringVar(value=self.cfg["rpc_password"])
        ttk.Entry(grid, textvariable=self.rpc_pass_var, width=14, show="•")\
            .grid(row=3, column=3, sticky="w", padx=(10, 0), pady=(4, 0))
        ModernButton(grid, text="Проверить", variant="ghost",
                     command=self._on_test_rpc, width=140, height=40,
                     font_size=SZ_BASE)\
            .grid(row=3, column=4, sticky="w", padx=(16, 0), pady=(4, 0))
        grid.columnconfigure(0, weight=1)
        grid.columnconfigure(2, weight=1)

        # EXCHANGE
        exch = Card(self.root, title="Exchange", subtitle=EXCHANGE_DIR, pad=16)
        exch.pack(fill="both", expand=True, padx=24, pady=(12, 0))
        ModernButton(exch.actions, text="Обновить", icon="⟳", variant="ghost",
                     command=self._refresh_files, width=150, height=36,
                     font_size=SZ_SMALL).pack(side="left", padx=(0, 8))
        ModernButton(exch.actions, text="Открыть папку", icon="⌘", variant="ghost",
                     command=self._open_exchange_folder, width=190, height=36,
                     font_size=SZ_SMALL).pack(side="left", padx=(0, 8))
        ModernButton(exch.actions, text="История", icon="⏱", variant="ghost",
                     command=self._on_show_history, width=140, height=36,
                     font_size=SZ_SMALL).pack(side="left")

        list_wrap = tk.Frame(exch.body, bg=C.bg_card)
        list_wrap.pack(fill="both", expand=True)

        cols = ("name", "type", "size", "time")
        self.tree = ttk.Treeview(list_wrap, columns=cols, show="headings",
                                 height=6, style="Files.Treeview")
        self.tree.heading("name", text="ФАЙЛ",    anchor="w")
        self.tree.heading("type", text="ТИП",     anchor="w")
        self.tree.heading("size", text="РАЗМЕР",  anchor="e")
        self.tree.heading("time", text="ИЗМЕНЁН", anchor="e")
        self.tree.column("name", width=460, anchor="w")
        self.tree.column("type", width=200, anchor="w")
        self.tree.column("size", width=160, anchor="e")
        self.tree.column("time", width=200, anchor="e")

        vsb = ttk.Scrollbar(list_wrap, orient="vertical", command=self.tree.yview)
        self.tree.configure(yscrollcommand=vsb.set)
        self.tree.pack(side="left", fill="both", expand=True)
        vsb.pack(side="right", fill="y")
        self.tree.bind("<Double-1>", self._on_file_double_click)
        self.tree.bind("<<TreeviewSelect>>", self._on_file_select)

        # WALLET TOOLS
        tools = tk.Frame(self.root, bg=C.bg)
        tools.pack(fill="x", padx=24, pady=(12, 0))
        self.view_key_btn = ModernButton(
            tools, text="Получить view key", icon="👁", variant="ghost",
            command=self._action_get_view_key, width=240, height=44,
            font_size=SZ_BASE)
        self.view_key_btn.pack(side="left")
        self.address_btn = ModernButton(
            tools, text="Получить адрес", icon="◈", variant="ghost",
            command=self._action_get_address, width=220, height=44,
            font_size=SZ_BASE)
        self.address_btn.pack(side="left", padx=(10, 0))
        self.view_key_btn.set_enabled(False)
        self.address_btn.set_enabled(False)

        # ACTION BAR
        actions = tk.Frame(self.root, bg=C.bg)
        actions.pack(fill="x", padx=24, pady=(12, 0))
        self.keyimages_btn = ModernButton(
            actions, text="Получить key images", icon="🔑", variant="primary",
            command=self._action_get_keyimages, width=260, height=48,
            font_size=SZ_BASE)
        self.keyimages_btn.pack(side="left")
        self.sign_btn = ModernButton(
            actions, text="Подписать транзакцию", icon="✎", variant="primary",
            command=self._action_sign_tx_clicked, width=260, height=48,
            font_size=SZ_BASE)
        self.sign_btn.pack(side="left", padx=(10, 0))
        self.send_btn = ModernButton(
            actions, text="Отправить в сеть", icon="↑", variant="primary",
            command=self._on_send_network, width=230, height=48,
            font_size=SZ_BASE)
        self.send_btn.pack(side="left", padx=(10, 0))
        self.details_btn = ModernButton(
            actions, text="Показать детали", icon="ⓘ", variant="ghost",
            command=self._on_show_details, width=220, height=48,
            font_size=SZ_BASE)
        self.details_btn.pack(side="left", padx=(10, 0))
        for b in (self.keyimages_btn, self.sign_btn,
                  self.send_btn, self.details_btn):
            b.set_enabled(False)

        # LOG
        logc = Card(self.root, title="Журнал",
                    subtitle="События устройства и хоста", pad=16)
        logc.pack(fill="both", expand=True, padx=24, pady=(12, 16))
        log_wrap = tk.Frame(logc.body, bg=C.bg_log)
        log_wrap.pack(fill="both", expand=True)
        self.log_area = tk.Text(log_wrap, height=6, wrap="word",
                                font=(FONT_MONO, SZ_MONO_SM), state="disabled",
                                bg=C.bg_log, fg=C.text_dim,
                                insertbackground=C.accent,
                                selectbackground=C.accent_glow,
                                selectforeground=C.text,
                                borderwidth=0, highlightthickness=0,
                                padx=16, pady=10)
        log_vs = ttk.Scrollbar(log_wrap, orient="vertical",
                               command=self.log_area.yview)
        self.log_area.configure(yscrollcommand=log_vs.set)
        self.log_area.pack(side="left", fill="both", expand=True)
        log_vs.pack(side="right", fill="y")
        self.log_area.tag_configure("ts",   foreground=C.text_mute)
        self.log_area.tag_configure("info", foreground=C.text)
        self.log_area.tag_configure("ok",   foreground=C.success)
        self.log_area.tag_configure("warn", foreground=C.warning)
        self.log_area.tag_configure("err",  foreground=C.error)
        self.log_area.tag_configure("esp",  foreground=C.info)

    def _label(self, parent, text, row, col, top=0):
        tk.Label(parent, text=text.upper(), bg=C.bg_card, fg=C.text_mute,
                 font=(FONT_UI, SZ_TINY, "bold"), anchor="w")\
            .grid(row=row, column=col, sticky="w", pady=(top, 0))

    def log(self, msg, tag=None):
        self.log_area.configure(state="normal")
        try:
            at_bottom = self.log_area.yview()[1] >= 0.999
        except Exception:
            at_bottom = True
        self.log_area.insert("end", time.strftime("%H:%M:%S "), ("ts",))
        if tag is None:
            low = msg.lower()
            if low.startswith("✅") or " ok" in low:
                tag = "ok"
            elif low.startswith("❌") or "error" in low or "ошибка" in low:
                tag = "err"
            elif "warn" in low or "⚠" in msg:
                tag = "warn"
            elif low.startswith("[esp]") or low.startswith("[p]") \
                    or low.startswith("[i]") or low.startswith("[d]") \
                    or low.startswith("[e]"):
                tag = "esp"
            else:
                tag = "info"
        self.log_area.insert("end", msg + "\n", (tag,))
        if at_bottom:
            self.log_area.see("end")
        self.log_area.configure(state="disabled")

    def _on_transport_changed(self):
        kind = TRANSPORT_KEYS.get(self.transport_var.get(), "auto")
        hid = (kind == "hid")
        state = "disabled" if hid else "normal"
        self.port_cb.configure(state=state)
        self.scan_btn.set_enabled(not hid)
        self.cfg["transport"] = kind
        save_config(self.cfg)

    def _selected(self):
        sel = self.tree.selection()
        return self.file_info.get(sel[0]) if sel else None

    # --------------------------------------------------------- device polling
    def _poll_device(self):
        if self.wallet is not None:
            try:
                self.wallet.pump(0.05)
                if self.exchange is not None:
                    events = self.exchange.step()
                    for ev in events:
                        self.log(f"[esp] {ev}", "esp")
                    for path in self.exchange.take_saved():
                        self._on_device_saved(path)
            except mwlink.LinkDisconnected as e:
                self.log(f"❌ Связь потеряна: {e}", "err")
                self._disconnect_device()
            except mwlink.LinkError as e:
                self.log(f"[esp] {e}", "warn")
            except Exception as e:
                self.log(f"[esp] {e}", "warn")
        self.root.after(200, self._poll_device)

    def _device_log(self, level, text):
        prefix = mwlink.LOG_LEVELS.get(level, "?")
        tag = "esp"
        if prefix == "E":
            tag = "err"
        elif prefix == "P":
            tag = "info"
        self.log(f"[{prefix}] {text}", tag)

    def _on_device_saved(self, path):
        self.log(f"✅ Сохранён результат: {os.path.basename(path)}", "ok")
        base = os.path.basename(path)

        # view key / адрес — JSON от устройства
        if self._pending_req and base.endswith(".json"):
            try:
                with open(path, "r", encoding="utf-8") as f:
                    obj = json.load(f)
                self._handle_request_result(self._pending_req, obj)
                self._write_sidecar_for_result(path, kind=self._pending_req)
            except Exception as e:
                self.log(f"WARN: не смог разобрать {base}: {e}", "warn")
            finally:
                self._pending_req = None
            self._refresh_files()
            return

        # keyImages / signed_monero_tx
        if base.endswith("_keyImages") or "_keyImages." in base:
            self._write_sidecar_for_result(path, kind="keyimages")
        elif "_signed_monero_tx" in base:
            self._write_sidecar_for_result(path, kind="signed_tx")

        self._refresh_files()

    def _handle_request_result(self, what, obj):
        if what == "viewonly":
            vk = obj.get("view_key") or obj.get("private_view_key") or ""
            self.log(f"✅ view key: {vk}", "ok")
            self._show_secret_dialog(
                title="Приватный view-ключ",
                subtitle="Секрет. Даёт обзор входящих, но НЕ позволяет тратить.",
                fields=[("Приватный view key (hex)", vk),
                        ("Приватный view key (0x…)", "0x" + vk if vk else "")])
        elif what == "address":
            addr = obj.get("address") or obj.get("addr") or ""
            self.log(f"✅ адрес: {addr}", "ok")
            self._show_secret_dialog(
                title="Основной адрес кошелька",
                subtitle="Адрес для получения средств.",
                fields=[("Адрес (mainnet)", addr)])

    def _write_sidecar_for_result(self, path, kind):
        """Sidecar-JSON рядом с результатом + запись в историю.

        Без view key кладём только то, что видно снаружи контейнера.
        Если raw_tx_hex когда-нибудь появится в sidecar вручную — он
        включит RPC-режим в «Отправить в сеть».
        """
        side = load_sidecar(path) or {}
        side["kind"] = kind
        side.setdefault("saved_time",
                        _dt.datetime.now().strftime("%Y-%m-%d %H:%M:%S"))
        side.setdefault("size", os.path.getsize(path))
        side.setdefault("file", os.path.basename(path))

        try:
            with open(path, "rb") as f:
                data = f.read()
            side.setdefault("crc32", f"{zlib.crc32(data) & 0xFFFFFFFF:08x}")
            for magic in (b"Monero signed tx set", b"Monero key image export",
                          b"Monero output export", b"Monero unsigned tx set"):
                if data.startswith(magic):
                    side.setdefault("magic", magic.decode("ascii", "replace"))
                    if len(data) > len(magic):
                        side.setdefault("version", f"{data[len(magic)]:#04x}")
                    if len(data) >= len(magic) + 8:
                        side.setdefault("iv",
                                        data[len(magic):len(magic) + 8].hex())
                    break
        except Exception:
            pass

        save_sidecar(path, side)

        entry = {
            "time": side["saved_time"],
            "kind": kind,
            "file": side["file"],
            "size": side["size"],
            "crc32": side.get("crc32", ""),
            "magic": side.get("magic", ""),
            "version": side.get("version", ""),
            "iv": side.get("iv", ""),
            "txid": side.get("txid", ""),
            "note": side.get("note", ""),
        }
        append_history(entry)

    # --------------------------------------------------------- connect
    def _scan_ports(self):
        try:
            ports = [p.device for p in serial.tools.list_ports.comports()]
        except Exception:
            ports = []
        self.port_cb["values"] = ports
        if ports and not self.port_var.get():
            self.port_var.set(ports[0])

    def _open_exchange_folder(self):
        if not os.path.isdir(EXCHANGE_DIR):
            os.makedirs(EXCHANGE_DIR, exist_ok=True)
        try:
            if sys.platform.startswith("win"):
                os.startfile(EXCHANGE_DIR)
            elif sys.platform == "darwin":
                os.system(f'open "{EXCHANGE_DIR}"')
            else:
                os.system(f'xdg-open "{EXCHANGE_DIR}"')
        except Exception as e:
            messagebox.showerror("Ошибка", str(e))

    def _pull_config_from_ui(self):
        self.cfg["transport"] = TRANSPORT_KEYS.get(self.transport_var.get(), "auto")
        self.cfg["serial_port"] = self.port_var.get()
        self.cfg["rpc_url"] = self.rpc_url_var.get()
        self.cfg["rpc_user"] = self.rpc_user_var.get()
        self.cfg["rpc_password"] = self.rpc_pass_var.get()
        save_config(self.cfg)

    def _on_connect(self):
        if self.wallet is not None:
            self._disconnect_device()
            return
        self._pull_config_from_ui()
        kind = self.cfg["transport"]
        port = self.port_var.get().strip() or None
        try:
            self.transport = mwlink.open_transport(kind, port, timeout=10.0)
            self.log(f"Транспорт: {self.transport.describe()}", "ok")
            self.wallet = mwlink.Wallet(self.transport, on_log=self._device_log)
            self.exchange = mwlink.Exchange(self.wallet, EXCHANGE_DIR, watch=False)
            self.connect_btn.set_text("Отключиться")
            self.status_pill.set(f"ESP32 · {self.transport.describe()}", C.success)
            self.view_key_btn.set_enabled(True)
            self.address_btn.set_enabled(True)
            self.root.after(1500, self._do_ping)
        except mwlink.LinkError as e:
            self.log(f"❌ Не удалось открыть транспорт: {e}", "err")
            messagebox.showerror("Ошибка подключения", str(e))
            self._disconnect_device()

    def _do_ping(self):
        if self.wallet is None:
            return

        def task():
            rtt = self.wallet.ping(b"hello")
            info = self.wallet.info()
            return rtt, info

        def on_ok(res):
            rtt, info = res
            self.log(f"PING → PONG ({rtt*1000:.1f} ms)", "ok")
            self.log(f"FW: {info.get('fw')} / board: {info.get('board')}", "esp")
            self.log(f"state={mwlink.STATE_NAMES.get(info.get('state'))}, "
                     f"wallet='{info.get('wallet')}', "
                     f"{mwlink.describe_reset(info)}", "esp")

        self._do_async(task, on_ok=on_ok, busy_note="PING...")

    def _disconnect_device(self):
        if self.wallet is not None:
            try:
                self.wallet.close()
            except Exception:
                pass
        self.wallet = None
        self.transport = None
        self.exchange = None
        self.connect_btn.set_text("Подключиться")
        self.status_pill.set("ESP32 отключено", C.text_mute)
        self.view_key_btn.set_enabled(False)
        self.address_btn.set_enabled(False)
        self.set_busy(False)

    # --------------------------------------------------------- files
    def _refresh_files(self):
        for iid in self.tree.get_children():
            self.tree.delete(iid)
        self.file_info.clear()

        if not os.path.isdir(EXCHANGE_DIR):
            os.makedirs(EXCHANGE_DIR, exist_ok=True)
        try:
            names = [n for n in os.listdir(EXCHANGE_DIR)
                     if not n.startswith(".")
                     and not n.endswith(SIDECAR_SUFFIX)
                     and os.path.isfile(os.path.join(EXCHANGE_DIR, n))]
        except Exception as e:
            self.log(f"Не могу прочитать exchange/: {e}", "err")
            return

        rows = []
        for name in names:
            path = os.path.join(EXCHANGE_DIR, name)
            kind_str = detect_kind_label(path)
            if kind_str == "?":
                continue
            try:
                size = os.path.getsize(path)
                mtime = os.path.getmtime(path)
            except Exception:
                size = 0
                mtime = 0
            rows.append({
                "name": name, "path": path, "kind": kind_str,
                "size": size, "mtime": mtime,
            })

        rows.sort(key=lambda r: r["mtime"], reverse=True)

        for r in rows:
            iid = self.tree.insert(
                "", "end",
                values=(r["name"], r["kind"], human_size(r["size"]),
                        format_mtime(r["mtime"])),
                tags=(r["kind"],))
            self.file_info[iid] = {"path": r["path"], "kind": r["kind"],
                                   "size": r["size"]}

        self.log(f"Скан exchange/: {len(rows)} файлов")

    def _on_file_select(self, _evt=None):
        if self.busy:
            return
        info = self._selected()
        kind = info["kind"] if info else None
        self.keyimages_btn.set_enabled(kind == "outputs")
        self.sign_btn.set_enabled(kind == "unsigned_tx")
        self.send_btn.set_enabled(kind == "signed_tx")
        self.details_btn.set_enabled(kind in ("unsigned_tx", "signed_tx",
                                              "outputs", "keyimages"))

    def _on_file_double_click(self, _evt):
        self._on_show_details()

    # --------------------------------------------------------- async
    def set_busy(self, busy, note=""):
        self.busy = busy
        info = self._selected()
        kind = info["kind"] if info else None
        if busy:
            for b in (self.keyimages_btn, self.sign_btn,
                      self.send_btn, self.details_btn,
                      self.view_key_btn, self.address_btn):
                b.set_enabled(False)
            self.connect_btn.set_enabled(False)
            if note:
                self.status_pill.set(note, C.warning)
            return
        self.connect_btn.set_enabled(True)
        self.keyimages_btn.set_enabled(kind == "outputs")
        self.sign_btn.set_enabled(kind == "unsigned_tx")
        self.send_btn.set_enabled(kind == "signed_tx")
        self.details_btn.set_enabled(kind in ("unsigned_tx", "signed_tx",
                                              "outputs", "keyimages"))
        self.view_key_btn.set_enabled(self.wallet is not None)
        self.address_btn.set_enabled(self.wallet is not None)
        if self.wallet is not None and self.transport is not None:
            self.status_pill.set(f"ESP32 · {self.transport.describe()}", C.success)
        else:
            self.status_pill.set("ESP32 отключено", C.text_mute)

    def _do_async(self, fn, on_ok=None, on_err=None, busy_note=""):
        if self.busy:
            return
        self.set_busy(True, busy_note)

        def runner():
            try:
                res = fn()
                self.event_q.put(("ok", on_ok, res))
            except Exception as e:
                self.event_q.put(("err", on_err, (e, traceback.format_exc())))
        threading.Thread(target=runner, daemon=True).start()

    def _poll_events(self):
        while True:
            try:
                kind, cb, payload = self.event_q.get_nowait()
            except queue.Empty:
                break
            if kind == "ok":
                self.set_busy(False)
                if cb:
                    try:
                        cb(payload)
                    except Exception as e:
                        self.log(f"callback error: {e}", "err")
            elif kind == "err":
                self.set_busy(False)
                e, tb = payload
                self.log(f"❌ {e}", "err")
                self.log(tb.strip(), "err")
                if cb:
                    cb(e)
                else:
                    messagebox.showerror("Ошибка", str(e))
        self.root.after(80, self._poll_events)

    # --------------------------------------------------------- actions
    def _require_device(self):
        if self.wallet is None:
            messagebox.showwarning("Устройство", "Сначала подключитесь к ESP32")
            return False
        return True

    def _require_wallet_open(self):
        if not self._require_device():
            return False
        try:
            info = self.wallet.info()
        except mwlink.LinkError as e:
            messagebox.showerror("Устройство", str(e))
            return False
        if info["state"] not in (mwlink.STATE_WALLET, mwlink.STATE_BUSY):
            messagebox.showwarning(
                "Кошелёк закрыт",
                "На устройстве не открыт кошелёк — операция невозможна.")
            return False
        return True

    def _send_file(self, path, what):
        if not self._require_wallet_open():
            return
        self.log(f"=== {what}: {os.path.basename(path)} ===")

        def task():
            return self.exchange.send(path, move_to_sent=False)

        def on_ok(msg):
            self.log(f"[esp] {msg}", "esp")
            self.log("Ожидание результата от устройства "
                     "(подтвердите на нём)...", "info")

        self._do_async(task, on_ok=on_ok, busy_note=f"{what}...")

    def _action_get_keyimages(self):
        info = self._selected()
        if not info or info["kind"] != "outputs":
            messagebox.showinfo("Не тот файл",
                                "«Получить key images» работает с файлом outputs.")
            return
        self._send_file(info["path"], "Отправка outputs")

    def _action_sign_tx_clicked(self):
        info = self._selected()
        if not info or info["kind"] != "unsigned_tx":
            messagebox.showinfo("Не тот файл",
                                "«Подписать транзакцию» работает только с "
                                "unsigned_monero_tx.")
            return
        self._send_file(info["path"], "Отправка unsigned tx")

    def _action_get_view_key(self):
        if not self._require_device():
            return
        self._request_something(mwlink.REQ_VIEWONLY, "viewonly")

    def _action_get_address(self):
        if not self._require_device():
            return
        self._request_something(mwlink.REQ_ADDRESS, "address")

    def _request_something(self, what_int, label):
        self._pending_req = label
        self.log(f"=== Запрос {label} ===")

        def task():
            self.wallet.request(what_int)
            return True

        def on_ok(_):
            self.log("Запрос отправлен. Подтвердите на устройстве.", "info")

        self._do_async(task, on_ok=on_ok, busy_note=f"Запрос {label}...")

    def _on_send_network(self):
        info = self._selected()
        if not info or info["kind"] != "signed_tx":
            messagebox.showinfo("Не тот файл",
                                "«Отправить в сеть» работает с подписанной tx.")
            return
        self._send_via_rpc(info["path"])

    def _send_via_rpc(self, path):
        """Отправка в сеть: RPC если есть raw_tx_hex, иначе — диалог
        с подсказкой импортировать Feather-файл вручную."""
        side = load_sidecar(path) or {}
        raw_hex = side.get("raw_tx_hex")

        if not raw_hex:
            dlg = tk.Toplevel(self.root)
            dlg.title("Отправка в сеть")
            dlg.transient(self.root)
            dlg.grab_set()
            dlg.configure(bg=C.bg)
            dlg.geometry("840x400")
            root = tk.Frame(dlg, bg=C.bg)
            root.pack(fill="both", expand=True, padx=16, pady=16)
            card = Card(root, title="Feather-файл сохранён",
                        subtitle=os.path.basename(path), pad=18)
            card.pack(fill="both", expand=True)

            msg = (
                "Подписанная транзакция сохранена в формате Feather Wallet:\n"
                f"    {os.path.basename(path)}\n\n"
                "Чтобы отправить её в сеть:\n"
                "  1. Откройте Feather Wallet (или Monero GUI).\n"
                "  2. File → Import → From file…\n"
                f"  3. Выберите {os.path.basename(path)}.\n"
                "  4. Проверьте получателей и суммы и отправьте.\n\n"
                "Feather Wallet расшифрует контейнер своим view-ключом."
            )
            tk.Label(card.body, text=msg, bg=C.bg_card, fg=C.text,
                     font=(FONT_MONO, SZ_MONO_SM), justify="left", anchor="w")\
                .pack(fill="x")

            foot = tk.Frame(card.body, bg=C.bg_card)
            foot.pack(fill="x", pady=(18, 0))
            ModernButton(foot, text="Открыть папку", variant="ghost",
                         command=self._open_exchange_folder,
                         width=180, height=44).pack(side="left")
            ModernButton(foot, text="Закрыть", variant="primary",
                         command=dlg.destroy,
                         width=160, height=44).pack(side="right")
            return

        # RPC-режим
        self._pull_config_from_ui()

        def task():
            self.log(f"RPC send_raw_transaction, {len(raw_hex)//2} байт...", "info")
            return rpc_send_raw_tx(self.cfg, raw_hex)

        def on_ok(resp):
            status = resp.get("status", "?")
            reason = resp.get("reason", "")
            tx_hash = resp.get("tx_hash") or resp.get("result", {}).get("tx_hash")
            if str(status).lower() == "ok":
                self.log(f"✅ Принято нодой. tx_hash={tx_hash or '(н/д)'}", "ok")
                side["txid"] = tx_hash or side.get("txid", "")
                side["sent_time"] = _dt.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                save_sidecar(path, side)
                append_history({
                    "time": side["sent_time"],
                    "kind": "signed_tx_sent",
                    "file": os.path.basename(path),
                    "size": side.get("size", 0),
                    "crc32": side.get("crc32", ""),
                    "magic": side.get("magic", ""),
                    "version": side.get("version", ""),
                    "iv": side.get("iv", ""),
                    "txid": side["txid"],
                    "note": "отправлено через RPC",
                })
                messagebox.showinfo(
                    "Отправлено",
                    f"Транзакция принята узлом.\n\ntx_hash: {tx_hash or '(н/д)'}")
            else:
                self.log(f"❌ {status}: {reason}", "err")
                messagebox.showerror("Отклонено узлом",
                                     f"status: {status}\nreason: {reason}")

        def on_err(e):
            messagebox.showerror("RPC ошибка", str(e))

        self._do_async(task, on_ok=on_ok, on_err=on_err,
                       busy_note="Отправка через RPC...")

    def _on_test_rpc(self):
        self._pull_config_from_ui()
        cfg = self.cfg

        def task():
            return rpc_call(cfg, "get_info")

        def on_ok(res):
            r = res.get("result", {})
            self.log(f"RPC OK: height={r.get('height')}, "
                     f"version={r.get('version')}, status={r.get('status')}", "ok")
            messagebox.showinfo("RPC OK",
                                f"Высота: {r.get('height')}\n"
                                f"Версия: {r.get('version')}\n"
                                f"Статус: {r.get('status')}")

        def on_err(e):
            messagebox.showerror("RPC ошибка", str(e))

        self._do_async(task, on_ok=on_ok, on_err=on_err,
                       busy_note="Проверка RPC...")

    # --------------------------------------------------------- details
    def _on_show_details(self):
        info = self._selected()
        if not info:
            return
        if info["kind"] in ("outputs", "keyimages", "unsigned_tx", "signed_tx"):
            FileInfoDialog(self.root, info["path"], info["kind"])
        else:
            messagebox.showinfo("Не тот файл", "Нет деталей для этого файла.")

    # --------------------------------------------------------- history
    def _on_show_history(self):
        entries = load_history()
        self.log(f"История кошелька: {len(entries)} записей", "info")
        HistoryDialog(self.root, entries)

    # --------------------------------------------------------- dialogs
    def _show_secret_dialog(self, title, subtitle, fields):
        dlg = tk.Toplevel(self.root)
        dlg.title(title)
        dlg.transient(self.root)
        dlg.grab_set()
        dlg.configure(bg=C.bg)
        dlg.geometry("900x420")

        root = tk.Frame(dlg, bg=C.bg)
        root.pack(fill="both", expand=True, padx=16, pady=16)
        card = Card(root, title=title, subtitle=subtitle, pad=18)
        card.pack(fill="both", expand=True)

        for label, value in fields:
            tk.Label(card.body, text=label.upper(), bg=C.bg_card,
                     fg=C.text_mute, font=(FONT_UI, SZ_TINY, "bold"),
                     anchor="w").pack(fill="x", pady=(10, 4))
            CopyField(card.body, value, mono=True, size=SZ_MONO,
                      bg=C.bg_elev, fg=C.accent, wrap="word", height=2)\
                .pack(fill="x")

        foot = tk.Frame(card.body, bg=C.bg_card)
        foot.pack(fill="x", pady=(18, 0))
        ModernButton(foot, text="Закрыть", variant="ghost",
                     command=dlg.destroy, width=160, height=44).pack(side="right")

    # --------------------------------------------------------- shutdown
    def _on_close(self):
        self._pull_config_from_ui()
        self._disconnect_device()
        self.root.destroy()


# ============================================================================
# main
# ============================================================================
def main():
    if not os.path.isdir(EXCHANGE_DIR):
        os.makedirs(EXCHANGE_DIR, exist_ok=True)
    root = tk.Tk()
    App(root)
    root.mainloop()


if __name__ == "__main__":
    main()