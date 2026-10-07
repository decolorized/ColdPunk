#!/usr/bin/env python3
"""Headless tests for mwlink_gui.py: the real App and Worker on a fake tkinter
(tests/faketk), against link_sim over a fake pyserial and a fake hidapi
(tests/simdev.py).

    python -B test_mwlink_gui.py [path/to/link_sim]

Covers connecting (button states, transport choice, a COM port held by another
program, a folder that cannot be created), sending Feather files over serial
and HID, a device that resets or is unplugged (the worker survives and
reconnects), the folder watch (move errors, files sent by hand, toggles keeping
the result name), the busy and declined cases, the view key kept out of the
log, and the event loop surviving a bad event.
"""
import os
import queue
import shutil
import sys
import tempfile
import threading
import time
import traceback

sys.dont_write_bytecode = True
HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(HERE, "tests", "faketk"))
sys.path.insert(1, os.path.join(HERE, "tests"))
sys.path.insert(2, HERE)

import simdev  # noqa: E402
simdev.install_fake_serial()
simdev.install_fake_hid()

import tkinter as tk  # noqa: E402  (the fake)
from tkinter import filedialog, messagebox  # noqa: E402
import mwlink  # noqa: E402
import mwlink_gui  # noqa: E402

mwlink_gui.RECONNECT_S = 0.5
FAILS = []
TMP = None


def check(cond, what):
    if not cond:
        FAILS.append(what)
        print("  FAIL", what, flush=True)


# ---------------------------------------------------------------------------
# helpers
# ---------------------------------------------------------------------------
def device(transport, *args):
    """Starts a link_sim and attaches it as 'serial', 'hid' or 'both' (the
    sim listed as COM7 and as the HID interface; only one is opened)."""
    sim = simdev.SimProc(*args)
    simdev.SERIAL["cur"] = sim if transport in ("serial", "both") else None
    simdev.HID["cur"] = simdev.HidBridge(sim) if transport in ("hid", "both") else None
    return sim


def no_device():
    for s in (simdev.SERIAL["cur"], simdev.HID["cur"] and simdev.HID["cur"].sim):
        if s:
            s.kill()
    simdev.SERIAL["cur"] = None
    simdev.HID["cur"] = None
    simdev.SERIAL["held"] = set()
    simdev.HID["fail_reads"] = False


class Ctx:
    def __init__(self, name):
        self.dir = os.path.join(TMP, name)
        self.exchange = os.path.join(self.dir, "exchange")
        self.feather = os.path.join(self.dir, "Feather")
        os.makedirs(self.feather)
        self.root = tk.Tk()
        self.app = mwlink_gui.App(self.root)
        self.app.folder.set(self.exchange)

    def run(self, seconds):
        self.root.run_for(seconds)

    def wait(self, pred, timeout=10.0):
        end = time.monotonic() + timeout
        while time.monotonic() < end:
            self.root.run_for(0.05)
            if pred():
                return True
        return False

    def console(self):
        return self.app.console.get("1.0", "end")

    def connect(self, timeout=12.0):
        self.app.btn_connect.invoke()
        return self.wait(lambda: self.app.conn_state == "connected" and
                         self.app.dev_state is not None, timeout)

    def send(self, path):
        filedialog.NEXT_OPEN = path.replace("\\", "/")       # Tk returns forward slashes
        self.app.btn_send.invoke()

    def worker_alive(self):
        return self.app.worker in threading.enumerate()

    def close(self):
        self.app._on_close()
        self.run(0.4)
        self.app.worker.join(2)
        no_device()


def outputs_file(path, n=200, age=0):
    with open(path, "wb") as f:
        f.write(b"Monero output export\x04" + os.urandom(n))
    if age:
        t = time.time() - age
        os.utime(path, (t, t))
    return path


def unsigned_file(path, n=500):
    with open(path, "wb") as f:
        f.write(b"Monero unsigned tx set\x05" + os.urandom(n))
    return path


def btn(w):
    return w.cget("state")


# ---------------------------------------------------------------------------
# tests
# ---------------------------------------------------------------------------
def test_connect_buttons():
    device("serial")
    c = Ctx("buttons")
    try:
        check(btn(c.app.btn_send) == "disabled", "Send disabled before connect")
        check(c.app.port.get() == "", "no port pre-selected")
        check("COM3  (not a wallet)" in c.app.port_box["values"], "foreign port labelled %r"
              % (c.app.port_box["values"],))
        check(c.connect(), "connected")
        check(btn(c.app.btn_connect) == "disabled" and btn(c.app.btn_disconnect) == "normal",
              "Connect disabled / Disconnect enabled after connect")
        for b in (c.app.btn_send, c.app.btn_req_addr, c.app.btn_req_view):
            check(btn(b) == "normal", "%s enabled when connected" % b.cget("text"))
        info = c.app.lbl_info.text()
        check("over serial COM7" in info and "last reset: power-on" in info, "info line %r" % info)
        check("connected over serial COM7" in c.console(), "transport logged")
        c.app.btn_disconnect.invoke()
        check(c.wait(lambda: c.app.conn_state == "disconnected"), "disconnected")
        check(btn(c.app.btn_connect) == "normal" and btn(c.app.btn_send) == "disabled",
              "buttons after disconnect")
    finally:
        c.close()


def _send_outputs_and_unsigned(c, label):
    p1 = outputs_file(os.path.join(c.feather, "tedtt_1790787000_outputs"))
    c.send(p1)
    ok = c.wait(lambda: any(n.endswith("_keyImages") for n in os.listdir(c.feather)), 10)
    out = [n for n in os.listdir(c.feather) if n.endswith("_keyImages")]
    check(ok and len(out) == 1 and out[0].startswith("tedtt_"),
          "%s: keyImages next to the input %r" % (label, out))
    p2 = unsigned_file(os.path.join(c.feather, "1790787458_unsigned_monero_tx"))
    c.send(p2)
    ok = c.wait(lambda: any(n.endswith("_signed_monero_tx") for n in os.listdir(c.feather)), 10)
    check(ok, "%s: signed tx saved %r" % (label, os.listdir(c.feather)))
    c.wait(lambda: c.console().count("saved ") >= 2, 5)
    c.run(1.5)
    con = c.console()
    check(con.count("saved ") == 2 and "result saved" not in con,
          "%s: each result logged once" % label)
    check("[I] [file] key images ready" in con, "%s: device log shown" % label)


def test_send_outputs_serial():
    device("serial")
    c = Ctx("send_serial")
    try:
        check(c.connect(), "serial connect")
        _send_outputs_and_unsigned(c, "serial")
    finally:
        c.close()


def test_send_outputs_hid():
    device("both")
    simdev.HID["timeouts"].clear()
    simdev.HID["blocking_reads"] = 0
    c = Ctx("send_hid")
    try:
        check(c.connect(), "hid connect")
        check("connected over hid" in c.console(), "auto prefers HID")
        _send_outputs_and_unsigned(c, "hid")
        check(simdev.HID["blocking_reads"] == 0 and min(simdev.HID["timeouts"]) >= 1,
              "no blocking / zero-timeout HID read (min %r)" % min(simdev.HID["timeouts"]))
    finally:
        c.close()


def _survive(transport):
    sim = device(transport)
    c = Ctx("survive_" + transport)
    try:
        check(c.connect(), "%s: connect" % transport)
        sim.kill()                                    # device resets / unplugged
        ok = c.wait(lambda: "device disconnected" in c.console(), 8)
        check(ok, "%s: link loss reported" % transport)
        check(c.worker_alive(), "%s: worker alive after link loss" % transport)
        check(c.app.conn_state == "reconnecting" and btn(c.app.btn_send) == "disabled",
              "%s: waiting for the device, Send disabled" % transport)
        check("results it produced before a reset are lost" in c.console(),
              "%s: lost results explained" % transport)
        device(transport, "--crash")                  # it comes back after a panic
        ok = c.wait(lambda: c.app.conn_state == "connected", 10)
        check(ok and "reconnected" in c.console(), "%s: reconnected by itself" % transport)
        check("last reset: crash (panic) during signing / CLSAG" in c.console(),
              "%s: reset reason shown" % transport)
        p = outputs_file(os.path.join(c.feather, "w_1790000000_outputs"))
        c.send(p)
        ok = c.wait(lambda: any(n.endswith("_keyImages") for n in os.listdir(c.feather)), 10)
        check(ok, "%s: send works after reconnect" % transport)
    finally:
        c.close()


def test_worker_survives_disconnect_hid():
    _survive("hid")


def test_worker_survives_disconnect_serial():
    _survive("serial")


def test_watch_move_permission_error():
    device("serial")
    c = Ctx("watch_move")
    real_move = mwlink.shutil.move

    def held(a, b):
        raise PermissionError(13, "The process cannot access the file because it is being "
                                  "used by another process")
    try:
        check(c.connect(), "connect")
        mwlink.shutil.move = held
        outputs_file(os.path.join(c.exchange, "w_1790000001_outputs"), age=5)
        ok = c.wait(lambda: "could not move it to sent/" in c.console(), 8)
        check(ok, "move error reported")
        c.wait(lambda: "saved " in c.console(), 8)
        c.run(2.5)
        check(c.console().count("sent w_1790000001_outputs") == 1, "watched file sent once")
        check(c.worker_alive() and c.app.conn_state == "connected",
              "local file error keeps the connection")
    finally:
        mwlink.shutil.move = real_move
        c.close()


def test_manual_send_in_watched_folder_sent_once():
    device("serial", "--confirm-ms", "1500")
    c = Ctx("manual_watched")
    try:
        check(c.connect(), "connect")
        os.makedirs(c.exchange, exist_ok=True)
        p = os.path.join(c.exchange, "w_1790000002_outputs")
        c.app.watch.set(False)
        c.app._toggle_watch()
        c.run(0.3)
        outputs_file(p, age=5)
        c.send(p)
        c.wait(lambda: "sent w_1790000002_outputs" in c.console(), 5)
        c.app.watch.set(True)
        c.app._toggle_watch()
        ok = c.wait(lambda: "saved " in c.console(), 10)
        c.run(2.5)
        check(ok, "result saved")
        check(c.console().count("sent w_1790000002_outputs") == 1,
              "sent exactly once:\n" + c.console())
        check(os.path.exists(p), "hand-picked file left in place")
    finally:
        c.close()


def test_toggle_watch_and_browse_keep_pending_name():
    device("serial", "--confirm-ms", "1500")
    c = Ctx("toggle")
    try:
        check(c.connect(), "connect")
        p = outputs_file(os.path.join(c.feather, "zed_1790000003_outputs"))
        c.send(p)
        c.wait(lambda: c.app.dev_state == mwlink.STATE_BUSY, 5)
        c.app.watch.set(False)
        c.app._toggle_watch()
        other = os.path.join(c.dir, "other")
        filedialog.NEXT_DIR = other
        c.app._browse()
        c.app.watch.set(True)
        c.app._toggle_watch()
        ok = c.wait(lambda: any(n.endswith("_keyImages") for n in os.listdir(c.feather)), 10)
        out = [n for n in os.listdir(c.feather) if n.endswith("_keyImages")]
        check(ok and out and out[0].startswith("zed_"), "name kept across toggles %r / %r"
              % (out, os.listdir(other) if os.path.isdir(other) else None))
    finally:
        c.close()


def test_busy_refusal_message():
    device("serial", "--confirm-ms", "3000")
    c = Ctx("busy")
    try:
        check(c.connect(), "connect")
        c.send(outputs_file(os.path.join(c.feather, "a_1790000004_outputs")))
        ok = c.wait(lambda: c.app.dev_state == mwlink.STATE_BUSY, 5)
        check(ok and "busy with the previous file" in c.app.lbl_hint.text(),
              "busy hint %r" % c.app.lbl_hint.text())
        c.send(outputs_file(os.path.join(c.feather, "b_1790000005_outputs")))
        ok = c.wait(lambda: "refused b_1790000005_outputs" in c.console(), 5)
        con = c.console()
        check(ok and "busy with the previous file" in con and "no wallet open" not in con,
              "busy refusal wording:\n" + con)
    finally:
        c.close()


def test_locked_hint():
    device("serial", "--locked")
    c = Ctx("locked")
    try:
        check(c.connect(), "connect")
        check("open a wallet on the device" in c.app.lbl_hint.text(), "locked hint %r"
              % c.app.lbl_hint.text())
        check("last reset: power-on" in c.app.lbl_info.text(), "reset shown while locked")
    finally:
        c.close()


def test_pending_name_after_decline():
    device("serial", "--confirm-ms", "2500", "--decline", "1")   # a review is seen as BUSY
    c = Ctx("decline")
    try:
        check(c.connect(), "connect")
        c.send(outputs_file(os.path.join(c.feather, "first_1790000006_outputs")))
        ok = c.wait(lambda: "no result for first_1790000006_outputs" in c.console(), 10)
        check(ok, "decline noticed")
        check(not c.app.worker.exchange.pending, "pending name dropped")
        c.send(outputs_file(os.path.join(c.feather, "second_1790000007_outputs")))
        ok = c.wait(lambda: any(n.endswith("_keyImages") for n in os.listdir(c.feather)), 10)
        out = [n for n in os.listdir(c.feather) if n.endswith("_keyImages")]
        check(ok and out[0].startswith("second_"), "result named after the second file %r" % out)
    finally:
        c.close()


def test_port_busy_falls_back_to_hid():
    device("both")
    simdev.SERIAL["held"] = {"COM7"}                 # Arduino IDE Serial Monitor
    c = Ctx("port_busy")
    try:
        c.app.port.set("COM7")                       # picked by the user
        check(c.connect(), "connected despite the held port")
        check("connected over hid" in c.console(), "fell back to HID:\n" + c.console())
    finally:
        c.close()


def test_connect_folder_error_leaves_clean_state():
    device("serial")
    c = Ctx("folder_error")
    try:
        blocker = os.path.join(c.dir, "not_a_dir")
        with open(blocker, "w") as f:
            f.write("x")
        c.app.folder.set(os.path.join(blocker, "exchange"))
        c.app.btn_connect.invoke()
        ok = c.wait(lambda: "could not connect" in c.console(), 8)
        check(ok, "folder error reported")
        c.run(0.3)
        w = c.app.worker
        check(w.wallet is None and w.exchange is None, "no half-open connection")
        check(c.app.conn_state == "disconnected" and btn(c.app.btn_connect) == "normal",
              "Connect available again")
        check(all(s.closed for s in simdev.SERIAL["opened"]), "port closed after the failure")
        c.app.folder.set(c.exchange)
        check(c.connect(), "connect after fixing the folder")
    finally:
        c.close()


def test_poll_events_survive_bad_event():
    c = Ctx("bad_event")
    try:
        c.app.events.put(("status", {"broken": True}))
        c.app.events.put(("log", (None, "still alive after a bad event")))
        ok = c.wait(lambda: "still alive after a bad event" in c.console(), 3)
        check(ok and "GUI: Traceback" in c.console(), "bad event reported, loop continues")
        c.app.events.put(("log", (None, "second round")))
        check(c.wait(lambda: "second round" in c.console(), 3), "poll re-armed")
    finally:
        c.close()


def test_worker_stop_join():
    w = mwlink_gui.Worker(queue.Queue())
    w.start()
    w.stop()
    try:
        w.join(2)
        check(not w.is_alive(), "worker stopped")
    except TypeError as e:
        check(False, "join raised %s" % e)


def test_restart_worker_releases_port():
    device("serial")
    c = Ctx("restart")
    try:
        check(c.connect(), "connect")
        old = c.app.worker
        port = old.wallet.t.ser
        old.stop()
        old.join(2)
        ok = c.wait(lambda: c.app.worker is not old and c.app.worker.is_alive(), 3)
        check(ok and "worker stopped; restarted" in c.console(), "worker restarted")
        check(port.closed, "old worker's port closed")
        check(c.app.conn_state == "disconnected", "GUI shows disconnected")
        check(c.connect(), "the new worker connects")
    finally:
        c.close()


def test_view_key_not_in_log():
    device("serial")
    c = Ctx("viewkey")
    key = "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff"
    try:
        check(c.connect(), "connect")
        messagebox.ANSWER = True
        c.app.btn_req_view.invoke()
        ok = c.wait(lambda: c.app.view_key_window is not None, 8)
        check(ok, "view key window shown")
        check(key not in c.console(), "view key not in the console")
        texts = [w for w in tk.ALL_WIDGETS if isinstance(w, tk.Text) and key in w.get("1.0")]
        check(texts, "view key in the dialog")
        copy = [w for w in tk.ALL_WIDGETS if w.cget("text") == "Copy view key"]
        copy[-1].invoke()
        check(getattr(c.root, "clipboard", "") == key, "copied to the clipboard")
        check(key not in c.console(), "still not in the console after copying")
        saved = os.path.join(c.dir, "log.txt")
        filedialog.NEXT_SAVE = saved
        c.app._save_log()
        with open(saved, encoding="utf-8") as f:
            check(key not in f.read(), "Save log does not contain the key")
    finally:
        c.close()


TESTS = [
    test_connect_buttons, test_send_outputs_serial, test_send_outputs_hid,
    test_worker_survives_disconnect_hid, test_worker_survives_disconnect_serial,
    test_watch_move_permission_error, test_manual_send_in_watched_folder_sent_once,
    test_toggle_watch_and_browse_keep_pending_name, test_busy_refusal_message,
    test_locked_hint, test_pending_name_after_decline, test_port_busy_falls_back_to_hid,
    test_connect_folder_error_leaves_clean_state, test_poll_events_survive_bad_event,
    test_worker_stop_join, test_restart_worker_releases_port, test_view_key_not_in_log,
]


def main():
    global TMP
    sim = sys.argv[1] if len(sys.argv) > 1 else os.path.join(HERE, "link_sim")
    if os.name == "nt" and not sim.endswith(".exe") and os.path.exists(sim + ".exe"):
        sim += ".exe"
    simdev.SIM["exe"] = sim
    TMP = tempfile.mkdtemp(prefix="mwlink-gui-")
    try:
        for t in TESTS:
            n = len(FAILS)
            t0 = time.monotonic()
            try:
                t()
            except Exception:
                FAILS.append(t.__name__)
                traceback.print_exc()
            finally:
                no_device()
            print("%-50s %s (%.1f s)" % (t.__name__, "ok" if len(FAILS) == n else "FAILED",
                                         time.monotonic() - t0), flush=True)
    finally:
        shutil.rmtree(TMP, ignore_errors=True)
    print("%d failures" % len(FAILS))
    return 1 if FAILS else 0


if __name__ == "__main__":
    sys.exit(main())
