#!/usr/bin/env python3
"""mwlink_gui - PC frontend for the Monero Cold Wallet (link protocol 2).

Windows first (tkinter ships with the python.org installer); Linux/macOS work
the same. What it does, and nothing more:

  * connects to the device over the vendor HID interface or the USB serial
    port (auto: HID first, then serial; or pick one), and reconnects by
    itself when the device restarts;
  * sends ANY file to the device ("Send file..."): the device recognises
    Feather / Monero files by content, whatever their name or extension;
  * watches the exchange folder (optional): a Feather "export outputs" or
    "unsigned transaction" file saved there is sent automatically;
  * saves what the device produces, named the way Feather names its files,
    next to the file that was sent (files from the watched folder: into the
    folder):
        borya-view2_1789637203_outputs  ->  borya-view2_1789638364_keyImages
        1789839233_unsigned_monero_tx   ->  1789839961_signed_monero_tx
  * asks the device for the wallet address or for the view-only data
    (address + private view key) Feather needs to create a view-only wallet -
    the device shows the request and sends nothing without confirmation; the
    view key is shown in its own window, never in the log;
  * shows the device log: what the device is doing, refusals with their
    reasons, and the extended stream when the device's debug mode is on.

Every conversion happens on the device; this program moves bytes and shows
text.

    pip install pyserial hidapi
    python mwlink_gui.py
"""

import json
import os
import queue
import sys
import threading
import time
import traceback
import tkinter as tk
from tkinter import ttk, filedialog, messagebox

import mwlink
from mwlink import (LinkError, LinkDisconnected, Wallet, Exchange, open_transport,
                    list_serial_ports, find_hid_path, find_serial_port, describe_reset,
                    KINDS, LOG_LEVELS, STATE_NAMES, REQ_ADDRESS, REQ_VIEWONLY,
                    RESET_CRASHES, default_exchange_dir)

RECONNECT_S = 2.0


# ---------------------------------------------------------------------------
# Worker thread: owns the transport. The GUI only posts jobs and reads the
# event queue; nothing touches the port from the Tk thread.
#
# Events: ("log", (level|None, text)), ("error", text), ("conn", state) with
# state connecting|connected|reconnecting|disconnected, ("info", dict|None),
# ("status", dict), ("saved", path).
# ---------------------------------------------------------------------------
class Worker(threading.Thread):
    def __init__(self, events, folder=None, watch=False):
        super().__init__(daemon=True)
        self.jobs = queue.Queue()
        self.events = events
        self.wallet = None
        self.exchange = None
        self.watch = watch
        self.folder = folder or default_exchange_dir()
        self.info = None
        self.transport_text = ""
        self._halt = threading.Event()
        self._conn_args = None         # (kind, port) of the last good connect
        self._reconnect = None         # (kind, port) while waiting for the device
        self._next_try = 0.0
        self._last_step = 0.0
        self._last_state = None

    def post(self, fn, *args):
        self.jobs.put((fn, args))

    def stop(self):
        self._halt.set()

    def emit(self, kind, payload=None):
        self.events.put((kind, payload))

    def log(self, text):
        self.emit("log", (None, text))

    def on_device_log(self, level, text):
        self.emit("log", (level, text))

    # ---- connection ---------------------------------------------------------
    def _close_link(self):
        w, self.wallet, self.exchange, self.info = self.wallet, None, None, None
        self._last_state = None
        if w:
            try:
                w.close()
            except Exception:
                pass

    def job_connect(self, kind, port, quiet=False):
        """Opens the device. Everything is built in locals and kept only when
        all of it worked. quiet: an automatic reconnect attempt."""
        self._close_link()
        self._reconnect = None
        if not quiet:
            self.emit("conn", "connecting")
        t = None
        try:
            t = open_transport(kind, port or None, timeout=10.0)
            w = Wallet(t, self.on_device_log)
            info = w.info()
            os.makedirs(os.path.join(self.folder, "sent"), exist_ok=True)
            ex = Exchange(w, self.folder, watch=self.watch)
        except ImportError as e:
            if t:
                t.close()
            self.emit("error", "Missing dependency: %s\n\npip install pyserial hidapi" % e)
            self.emit("conn", "disconnected")
            return False
        except (LinkError, OSError) as e:
            if t:
                t.close()
            if quiet:
                self._reconnect = (kind, port)
                return False
            self.emit("error", "could not connect: %s" % e)
            self.emit("conn", "disconnected")
            return False
        ex.wallet_name = info.get("wallet", "")
        self.wallet, self.exchange, self.info = w, ex, info
        self.transport_text = t.describe()
        self._conn_args = (kind, port)
        self._last_step = 0.0
        self.log("connected over %s" % self.transport_text)
        level = 1 if info.get("reset_reason") in RESET_CRASHES else None
        self.emit("log", (level, "device %s" % describe_reset(info)))
        self.emit("conn", "connected")
        self.emit("info", dict(info, transport=self.transport_text))
        return True

    def job_disconnect(self):
        had = self.wallet is not None or self._reconnect is not None
        self._reconnect = None
        self._close_link()
        if had:
            self.log("disconnected")
        self.emit("conn", "disconnected")
        self.emit("info", None)

    def _link_lost(self, e):
        self._close_link()
        self.emit("error", "device disconnected: %s" % e)
        self.log("waiting for the device to come back; results it produced before a "
                 "reset are lost (send the file again if nothing was saved)")
        self._reconnect = self._conn_args
        self._next_try = time.monotonic() + RECONNECT_S
        self.emit("conn", "reconnecting")
        self.emit("info", None)

    def _try_reconnect(self):
        kind, port = self._reconnect
        try:
            present = bool(find_hid_path() or find_serial_port() or
                           (port and any(p[0] == port for p in list_serial_ports())))
        except Exception:
            present = False
        if present and self.job_connect(kind, port, quiet=True):
            self.log("reconnected")

    # ---- jobs ---------------------------------------------------------------
    def job_info(self):
        if not self.wallet:
            return
        self.info = self.wallet.info()
        if self.exchange:
            self.exchange.wallet_name = self.info.get("wallet", "")
        self.emit("info", dict(self.info, transport=self.transport_text))

    def job_send(self, path):
        if not self.wallet:
            self.emit("error", "not connected")
            return
        name = os.path.basename(path)
        try:
            self.log(self.exchange.send(path))
        except LinkDisconnected:
            raise
        except LinkError as e:
            if e.code is not None:
                self.emit("error", "the device refused %s: %s" % (name, e))
            else:
                self.emit("error", "could not send %s: %s" % (name, e))
        except OSError as e:
            self.emit("error", "could not read %s: %s" % (name, e))

    def job_request(self, what):
        if not self.wallet:
            self.emit("error", "not connected")
            return
        try:
            self.wallet.request(what)
            self.log("request sent (%s): confirm it on the device" %
                     ("address" if what == REQ_ADDRESS else "view-only data"))
        except LinkDisconnected:
            raise
        except LinkError as e:
            self.emit("error", "the device refused the request: %s" % e if e.code is not None
                      else "could not send the request: %s" % e)

    def job_set_folder(self, folder):
        if self.exchange:
            try:
                self.exchange.set_folder(folder)
            except OSError as e:
                self.emit("error", "cannot use %s: %s" % (folder, e))
                return
        self.folder = folder
        self.log("exchange folder: %s" % folder)

    def job_set_watch(self, on):
        self.watch = bool(on)
        if self.exchange:
            self.exchange.set_watch(on)
        self.log("folder watch %s" % ("on" if on else "off"))

    # ---- loop ---------------------------------------------------------------
    def _poll(self):
        self.wallet.pump(0.05)
        now = time.monotonic()
        if now - self._last_step <= 1.0 or not self.exchange:
            return
        self._last_step = now
        for ev in self.exchange.step():
            self.log(ev)
        for path in self.exchange.take_saved():
            self.emit("saved", path)
        st = self.exchange.last_status
        self.emit("status", st)
        if st["state"] != self._last_state:
            self._last_state = st["state"]
            self.job_info()

    def run(self):
        while not self._halt.is_set():
            try:
                fn, args = self.jobs.get(timeout=0.1)
            except queue.Empty:
                fn = None
            try:
                if fn:
                    fn(*args)
                elif self.wallet:
                    self._poll()
                elif self._reconnect and time.monotonic() >= self._next_try:
                    self._next_try = time.monotonic() + RECONNECT_S
                    self._try_reconnect()
            except LinkDisconnected as e:
                self._link_lost(e)
            except LinkError as e:
                self.emit("error", str(e))
            except Exception:                         # never let the worker die
                tb = traceback.format_exc()
                print(tb, file=sys.stderr)
                self.emit("error", "internal error (the connection is kept):\n" + tb)
        self._close_link()


# ---------------------------------------------------------------------------
# GUI
# ---------------------------------------------------------------------------
class App:
    def __init__(self, root):
        self.root = root
        root.title("Monero Cold Wallet")
        root.geometry("900x640")
        root.minsize(680, 500)

        self.events = queue.Queue()
        self.conn_state = "disconnected"
        self.dev_state = None
        self.closing = False
        self.view_key_window = None
        self.worker = Worker(self.events)
        self.worker.start()

        self._build()
        self.root.after(100, self._poll_events)
        self.root.protocol("WM_DELETE_WINDOW", self._on_close)

    # ---- layout -------------------------------------------------------------
    def _build(self):
        pad = {"padx": 4, "pady": 3}

        conn = ttk.LabelFrame(self.root, text="Device")
        conn.pack(fill="x", **pad)
        ttk.Label(conn, text="Transport:").grid(row=0, column=0, sticky="w", **pad)
        self.kind = tk.StringVar(value="auto")
        ttk.Combobox(conn, textvariable=self.kind, values=["auto", "hid", "serial"],
                     width=8, state="readonly").grid(row=0, column=1, **pad)
        ttk.Label(conn, text="Port:").grid(row=0, column=2, sticky="w", **pad)
        # Empty = find the device by VID/PID. A port is used only when the
        # user picks one.
        self.port = tk.StringVar(value="")
        self.port_box = ttk.Combobox(conn, textvariable=self.port, width=28)
        self.port_box.grid(row=0, column=3, **pad)
        ttk.Button(conn, text="Refresh", command=self._refresh_ports).grid(row=0, column=4, **pad)
        self.btn_connect = ttk.Button(conn, text="Connect", command=self._connect)
        self.btn_connect.grid(row=0, column=5, **pad)
        self.btn_disconnect = ttk.Button(conn, text="Disconnect", command=self._disconnect,
                                         state="disabled")
        self.btn_disconnect.grid(row=0, column=6, **pad)
        self.lbl_info = ttk.Label(conn, text="not connected")
        self.lbl_info.grid(row=1, column=0, columnspan=7, sticky="w", **pad)
        self.lbl_state = ttk.Label(conn, text="", font=("Segoe UI", 10, "bold"))
        self.lbl_state.grid(row=2, column=0, columnspan=7, sticky="w", **pad)

        ex = ttk.LabelFrame(self.root, text="Exchange with Feather")
        ex.pack(fill="x", **pad)
        ttk.Label(ex, text="Folder:").grid(row=0, column=0, sticky="w", **pad)
        self.folder = tk.StringVar(value=default_exchange_dir())
        ttk.Entry(ex, textvariable=self.folder, width=70).grid(row=0, column=1, columnspan=3,
                                                              sticky="we", **pad)
        ttk.Button(ex, text="Browse", command=self._browse).grid(row=0, column=4, **pad)
        ttk.Button(ex, text="Open", command=self._open_folder).grid(row=0, column=5, **pad)

        self.watch = tk.BooleanVar(value=True)
        ttk.Checkbutton(ex, text="Watch the folder: send Feather's outputs / unsigned "
                                 "transaction files automatically",
                        variable=self.watch, command=self._toggle_watch).grid(
            row=1, column=0, columnspan=6, sticky="w", **pad)

        self.btn_send = ttk.Button(ex, text="Send file...", command=self._send_any,
                                   state="disabled")
        self.btn_send.grid(row=2, column=0, columnspan=2, sticky="we", **pad)
        self.btn_req_addr = ttk.Button(ex, text="Request address", state="disabled",
                                       command=lambda: self._request(REQ_ADDRESS))
        self.btn_req_addr.grid(row=2, column=2, sticky="we", **pad)
        self.btn_req_view = ttk.Button(ex, text="Request view-only wallet data", state="disabled",
                                       command=lambda: self._request(REQ_VIEWONLY))
        self.btn_req_view.grid(row=2, column=3, columnspan=2, sticky="we", **pad)
        self.lbl_hint = ttk.Label(ex, text="connect the device first", foreground="#b36b00")
        self.lbl_hint.grid(row=3, column=0, columnspan=6, sticky="w", **pad)

        ttk.Label(ex, text="Results are saved next to the file you sent (files picked up by "
                           "the folder watch: into the folder); wallet data goes into the "
                           "folder.", foreground="#666").grid(
            row=4, column=0, columnspan=6, sticky="w", **pad)
        self.lbl_status = ttk.Label(ex, text="", font=("Consolas", 9))
        self.lbl_status.grid(row=5, column=0, columnspan=6, sticky="w", **pad)

        con = ttk.LabelFrame(self.root, text="Device log")
        con.pack(fill="both", expand=True, **pad)
        bar = ttk.Frame(con)
        bar.pack(fill="x")
        self.show_debug = tk.BooleanVar(value=True)
        ttk.Checkbutton(bar, text="show debug lines", variable=self.show_debug).pack(side="left", **pad)
        ttk.Button(bar, text="Save log...", command=self._save_log).pack(side="right", **pad)
        ttk.Button(bar, text="Clear", command=self._clear_console).pack(side="right", **pad)

        self.console = tk.Text(con, height=14, wrap="word", font=("Consolas", 9),
                               bg="#111", fg="#ddd", insertbackground="#ddd")
        self.console.pack(fill="both", expand=True, side="left")
        sb = ttk.Scrollbar(con, command=self.console.yview)
        sb.pack(side="right", fill="y")
        self.console.configure(yscrollcommand=sb.set, state="disabled")
        self.console.tag_configure("P", foreground="#7fd7ff")
        self.console.tag_configure("E", foreground="#ff6b6b")
        self.console.tag_configure("I", foreground="#ddd")
        self.console.tag_configure("D", foreground="#888")
        self.console.tag_configure("host", foreground="#b8e986")

        self._refresh_ports()
        self.worker.post(self.worker.job_set_watch, True)

    # ---- actions ------------------------------------------------------------
    def _refresh_ports(self):
        values = []
        for dev, vid, pid, _d in list_serial_ports():
            wallet = vid == mwlink.USB_VID and pid in mwlink.USB_PIDS
            values.append(dev if wallet else "%s  (not a wallet)" % dev)
        self.port_box["values"] = values

    def _picked_port(self):
        v = self.port.get().strip()
        return v.split()[0] if v else ""

    def _connect(self):
        self._refresh_ports()
        self.worker.post(self.worker.job_set_folder, self.folder.get())
        self.worker.post(self.worker.job_connect, self.kind.get(), self._picked_port())

    def _disconnect(self):
        self.worker.post(self.worker.job_disconnect)

    def _browse(self):
        d = filedialog.askdirectory(initialdir=self.folder.get() or ".")
        if d:
            self.folder.set(d)
            self.worker.post(self.worker.job_set_folder, d)

    def _open_folder(self):
        d = self.folder.get()
        try:
            os.makedirs(d, exist_ok=True)
        except OSError as e:
            self._append("E", "error: cannot create %s: %s" % (d, e))
            return
        if sys.platform.startswith("win"):
            os.startfile(d)                      # noqa
        else:
            self._append("host", "folder: %s" % d)

    def _toggle_watch(self):
        self.worker.post(self.worker.job_set_folder, self.folder.get())
        self.worker.post(self.worker.job_set_watch, bool(self.watch.get()))

    def _send_any(self):
        # Any file: wallets do not agree on extensions, the device checks the
        # content.
        path = filedialog.askopenfilename(initialdir=self.folder.get() or ".",
                                          filetypes=[("all files", "*"), ("all files", "*.*")])
        if path:
            self.worker.post(self.worker.job_send, path)

    def _request(self, what):
        if what == REQ_VIEWONLY and not messagebox.askyesno(
                "View-only wallet data",
                "The device will show the request and, after you confirm it there, send "
                "the wallet address and the PRIVATE VIEW KEY. With them this PC can see "
                "every incoming payment of the wallet (it can never spend).\n\nContinue?"):
            return
        self.worker.post(self.worker.job_request, what)

    def _clear_console(self):
        self.console.configure(state="normal")
        self.console.delete("1.0", "end")
        self.console.configure(state="disabled")

    def _save_log(self):
        path = filedialog.asksaveasfilename(defaultextension=".txt",
                                            initialfile="mwlink-%s.txt" % time.strftime("%Y%m%d-%H%M%S"))
        if path:
            try:
                with open(path, "w", encoding="utf-8") as f:
                    f.write(self.console.get("1.0", "end"))
            except OSError as e:
                self._append("E", "error: could not save the log: %s" % e)

    # ---- worker -> GUI ------------------------------------------------------
    def _append(self, tag, text):
        self.console.configure(state="normal")
        self.console.insert("end", "%s %s\n" % (time.strftime("%H:%M:%S"), text), tag)
        self.console.see("end")
        self.console.configure(state="disabled")

    def _check_worker(self):
        """Restarts the worker should it ever end; the old one's port is
        closed first so the new one can open it."""
        if self.closing or self.worker.is_alive():
            return
        old = self.worker
        if old.wallet:
            try:
                old.wallet.close()
            except Exception:
                pass
        self.worker = Worker(self.events, folder=old.folder, watch=old.watch)
        self.worker.start()
        self._append("E", "error: the link worker stopped; restarted it - press Connect")
        self._set_conn("disconnected")

    def _poll_events(self):
        try:
            self._check_worker()
            for _ in range(500):
                try:
                    kind, payload = self.events.get_nowait()
                except queue.Empty:
                    break
                try:
                    self._handle_event(kind, payload)
                except Exception:
                    self._append("E", "error: GUI: %s" % traceback.format_exc())
        finally:
            self.root.after(100, self._poll_events)

    def _handle_event(self, kind, payload):
        if kind == "log":
            level, text = payload
            if level is None:
                self._append("host", text)
            else:
                tag = LOG_LEVELS.get(level, "I")
                if tag == "D" and not self.show_debug.get():
                    return
                self._append(tag, "[%s] %s" % (tag, text))
        elif kind == "conn":
            self._set_conn(payload)
        elif kind == "info":
            self._show_info(payload)
        elif kind == "status":
            self._show_status(payload)
        elif kind == "saved":
            self._maybe_show_export(payload)
        elif kind == "error":
            self._append("E", "error: %s" % payload)

    def _set_conn(self, state):
        self.conn_state = state
        busy = state in ("connecting", "connected", "reconnecting")
        self.btn_connect.configure(state="disabled" if busy else "normal")
        self.btn_disconnect.configure(state="normal" if busy else "disabled")
        on = "normal" if state == "connected" else "disabled"
        for b in (self.btn_send, self.btn_req_addr, self.btn_req_view):
            b.configure(state=on)
        if state != "connected":
            self.dev_state = None
            self.lbl_status.configure(text="")
            self.lbl_hint.configure(text={
                "connecting": "connecting...",
                "reconnecting": "device disconnected: waiting for it to come back...",
            }.get(state, "connect the device first"))
            if state == "reconnecting":
                self.lbl_info.configure(text="reconnecting...")
        else:
            self._update_hint()

    def _update_hint(self):
        s = self.dev_state
        if s in (mwlink.STATE_LOCKED, mwlink.STATE_MENU):
            text = "open a wallet on the device to send files"
        elif s == mwlink.STATE_BUSY:
            text = "the device is busy with the previous file: finish or cancel it there"
        else:
            text = ""
        self.lbl_hint.configure(text=text)

    def _maybe_show_export(self, path):
        if not path.endswith(".json"):
            return
        try:
            with open(path, "r", encoding="utf-8") as f:
                data = json.load(f)
        except (OSError, ValueError):
            return
        lines = ["Wallet: %s (%s)" % (data.get("wallet", ""), data.get("network", "")),
                 "Address: %s" % data.get("address", ""),
                 "Restore height: %s" % data.get("restore_height", "")]
        if "view_key" in data:
            # The key never goes into the log (and so never into "Save log").
            lines.append("The private view key is shown in a separate window.")
            self._append("host", "\n".join(lines))
            self._show_view_key(data)
        else:
            self._append("host", "\n".join(lines))

    def _show_view_key(self, data):
        key = data.get("view_key", "")
        win = tk.Toplevel(self.root)
        win.title("View-only wallet data")
        ttk.Label(win, text="PRIVATE VIEW KEY - whoever has it sees every incoming payment of "
                            "this wallet (it cannot spend). Do not share it.",
                  foreground="#b00", wraplength=520).pack(fill="x", padx=8, pady=6)
        ttk.Label(win, text="Address: %s" % data.get("address", ""), wraplength=520).pack(
            fill="x", padx=8)
        ttk.Label(win, text="Restore height: %s" % data.get("restore_height", "")).pack(
            fill="x", padx=8)
        box = tk.Text(win, height=2, wrap="char", font=("Consolas", 10))
        box.insert("end", key)
        box.configure(state="disabled")
        box.pack(fill="x", padx=8, pady=6)
        ttk.Label(win, text="Feather: File > New / Restore wallet > Restore from keys "
                            "(view-only: leave the spend key empty).", wraplength=520).pack(
            fill="x", padx=8)
        bar = ttk.Frame(win)
        bar.pack(fill="x", padx=8, pady=6)

        def copy():
            self.root.clipboard_clear()
            self.root.clipboard_append(key)
            self._append("host", "view key copied to the clipboard - clear it when done")

        ttk.Button(bar, text="Copy view key", command=copy).pack(side="left")
        ttk.Button(bar, text="Close", command=win.destroy).pack(side="right")
        self.view_key_window = win

    def _show_info(self, info):
        if not info:
            if self.conn_state != "reconnecting":
                self.lbl_info.configure(text="not connected")
            self.lbl_state.configure(text="")
            return
        self.lbl_info.configure(text="firmware %s on %s, link protocol %d, over %s; %s" %
                                (info["fw"], info["board"], info["proto"],
                                 info.get("transport", "?"), describe_reset(info)))
        self._show_state(info["state"], info)

    def _show_state(self, state, info=None):
        info = info or self.worker.info or {}
        self.dev_state = state
        if state == mwlink.STATE_LOCKED:
            text = "Device locked: unlock it and open a wallet"
        elif state == mwlink.STATE_MENU:
            text = "Device unlocked: open a wallet to exchange files"
        else:
            text = "Wallet '%s'%s (%s): %s" % (
                info.get("wallet", ""),
                " with passphrase" if info.get("passphrase") else "",
                info.get("network", ""),
                "ready for files" if state == mwlink.STATE_WALLET else "busy - look at the device")
        self.lbl_state.configure(text=text)
        if self.conn_state == "connected":
            self._update_hint()

    def _show_status(self, st):
        self._show_state(st["state"])
        pend = ", ".join("%s %d B" % (KINDS[k], st["outbox"][k]) for k in range(len(KINDS))
                         if st["outbox"][k])
        self.lbl_status.configure(text=("device state: %s" % STATE_NAMES.get(st["state"], "?")) +
                                  ("   results waiting: " + pend if pend else ""))

    def _on_close(self):
        self.closing = True
        self.worker.post(self.worker.job_disconnect)
        self.worker.stop()
        self.root.after(200, self.root.destroy)


def main():
    root = tk.Tk()
    try:
        ttk.Style().theme_use("vista" if sys.platform.startswith("win") else "clam")
    except tk.TclError:
        pass
    App(root)
    root.mainloop()


if __name__ == "__main__":
    main()
