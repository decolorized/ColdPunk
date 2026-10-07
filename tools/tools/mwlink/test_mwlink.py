#!/usr/bin/env python3
"""Tests for mwlink.py against link_sim (the real link core on the host).

    gcc ... -o link_sim   (see link_sim.c for the command line)
    python test_mwlink.py [path/to/link_sim]

Checks the Feather-style result names, COBS, the protocol-3 commands, the
exchange logic (any file sent, results saved and named after the input,
refusals reported with the device's reason, folder watch) and requests, the
INFO reset/crash fields, the HID receiver (frame start, timeouts, messages
split over several reads) and the transport choice.
The GUI is covered by test_mwlink_gui.py.
"""

import os
import random
import shutil
import subprocess
import sys
import tempfile
import time
import types

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import mwlink  # noqa: E402

FAILS = []


def check(cond, what):
    if not cond:
        FAILS.append(what)
        print("  FAIL", what)


class PipeSerial:
    """Enough of pyserial's Serial for SerialTransport, over a subprocess."""

    def __init__(self, proc):
        self.p = proc

    def reset_input_buffer(self):
        pass

    def write(self, data):
        self.p.stdin.write(data)
        self.p.stdin.flush()
        return len(data)

    def flush(self):
        self.p.stdin.flush()

    def read(self, n):
        return os.read(self.p.stdout.fileno(), 1)

    def close(self):
        try:
            self.p.stdin.close()
        except OSError:
            pass
        self.p.wait(5)


def open_sim(sim, *args):
    proc = subprocess.Popen([sim] + list(args), stdin=subprocess.PIPE, stdout=subprocess.PIPE)
    t = mwlink.SerialTransport.__new__(mwlink.SerialTransport)
    t.ser = PipeSerial(proc)
    t.timeout = 10.0
    t.port = "sim"
    t._rx = bytearray()
    return t


def test_names():
    now = 1789638364
    check(mwlink.result_name("borya-view2_1789637203_outputs", mwlink.K_KEYIMAGES, now)
          == "borya-view2_1789638364_keyImages", "outputs name")
    check(mwlink.result_name("1789839233_unsigned_monero_tx", mwlink.K_SIGNED, now)
          == "1789638364_signed_monero_tx", "unsigned name")
    check(mwlink.result_name("outputs.bin", mwlink.K_KEYIMAGES, now)
          == "1789638364_keyImages.bin", "outputs.bin name")
    check(mwlink.result_name("weird.dat", mwlink.K_SIGNED, now)
          == "weird.dat_1789638364_signed_monero_tx", "fallback name")
    check(mwlink.result_name("viewonly", mwlink.K_EXPORT, now, wallet="bo rya")
          == "bo_rya_1789638364_viewonly.json", "export name")


def test_cobs():
    rnd = random.Random(1)
    for n in (0, 1, 253, 254, 255, 600, 5000):
        data = bytes(rnd.choice((0, 1, 7, 255)) for _ in range(n))
        enc = mwlink.cobs_encode(data)
        check(b"\x00" not in enc, "cobs no zero %d" % n)
        check(mwlink.cobs_decode(enc) == data, "cobs roundtrip %d" % n)


def test_protocol(sim, folder):
    logs = []
    w = mwlink.Wallet(open_sim(sim), lambda lvl, text: logs.append(text))
    try:
        info = w.info()
        check(info["proto"] == mwlink.PROTO_VERSION == 3 and info["state"] == mwlink.STATE_WALLET, "info state")
        check(info["wallet"] == "sim" and info["network"] == "stagenet", "info wallet")
        st = w.status()
        check(st["accept"] == 0x05, "status accept mask")

        ex = mwlink.Exchange(w, folder)
        # Feather's file names, no extension.
        p1 = os.path.join(folder, "borya-view2_1789637203_outputs")
        with open(p1, "wb") as f:
            f.write(b"Monero output export\x04" + os.urandom(200))
        msg = ex.send(p1)
        check("as outputs" in msg, "send outputs")
        ev = ex.step()
        saved = [e for e in ev if e.startswith("saved ")]
        check(len(saved) == 1 and "_keyImages" in saved[0], "keyImages saved: %r" % ev)
        out = [n for n in os.listdir(folder) if n.endswith("_keyImages")]
        check(len(out) == 1 and out[0].startswith("borya-view2_"), "keyImages name %r" % out)
        with open(os.path.join(folder, out[0]), "rb") as f:
            check(f.read().startswith(b"Monero key image export"), "keyImages content")
        check(any("key images ready" in l for l in logs), "device log delivered")

        p2 = os.path.join(folder, "1789839233_unsigned_monero_tx")
        with open(p2, "wb") as f:
            f.write(b"Monero unsigned tx set\x05" + os.urandom(300))
        ex.send(p2)
        ev = ex.step()
        check(any("_signed_monero_tx" in e for e in ev), "signed saved: %r" % ev)

        # Any other file: refused by the DEVICE, with its reason.
        p3 = os.path.join(folder, "photo.jpg")
        with open(p3, "wb") as f:
            f.write(b"\xff\xd8\xff" + os.urandom(100))
        try:
            ex.send(p3)
            check(False, "junk accepted")
        except mwlink.LinkError as e:
            check(e.code == mwlink.ERR_BAD_FORMAT and "not a Monero" in str(e), "junk refused: %s" % e)

        # Requests.
        ex.wallet_name = "sim"
        w.request(mwlink.REQ_VIEWONLY)
        ev = ex.step()
        js = [n for n in os.listdir(folder) if n.endswith("_viewonly.json")]
        check(len(js) == 1, "viewonly json saved %r / %r" % (js, ev))

        # Folder watch: a file dropped by Feather is sent and moved to sent/.
        ex.watch = True
        p4 = os.path.join(folder, "wallet_1789999999_outputs")
        with open(p4, "wb") as f:
            f.write(b"Monero output export\x04" + os.urandom(64))
        old = time.time() - 5
        os.utime(p4, (old, old))
        ev = ex.step()
        check(any(e.startswith("sent wallet_1789999999_outputs") for e in ev), "watch sent: %r" % ev)
        check(not os.path.exists(p4), "watched file moved to sent/")
        ev = ex.step()
        check(any("wallet_" in e and "_keyImages" in e for e in ev), "watch result: %r" % ev)
        # Foreign files in the folder are left alone.
        check(os.path.exists(p3), "junk left in place")
    finally:
        w.close()


def test_info_reset(sim):
    # Unlocked, after a crash: reason, operation, stage and the stack figure.
    w = mwlink.Wallet(open_sim(sim, "--crash"))
    try:
        i = w.info()
        check(i["reset_reason"] == 4 and i["crash_op"] == 1 and i["crash_stage"] == 4,
              "crash fields %r" % i)
        check(i["crash_flags"] == 3 and i["crash_stack"] == 480, "crash flags/stack %r" % i)
        text = mwlink.describe_reset(i)
        check(text == "last reset: crash (panic) during signing / CLSAG, crypto stack min "
                      "free 480 B", "describe_reset %r" % text)
    finally:
        w.close()
    # Locked: the reason only, nothing about what the device was doing.
    w = mwlink.Wallet(open_sim(sim, "--crash", "--locked"))
    try:
        i = w.info()
        check(i["reset_reason"] == 4 and not i["unlocked"], "locked reason %r" % i)
        check(i["crash_op"] == 0 and i["crash_stage"] == 0 and i["crash_flags"] == 0
              and i["crash_stack"] == 0, "locked hides the crash %r" % i)
        check(mwlink.describe_reset(i) == "last reset: crash (panic)", "locked text")
    finally:
        w.close()
    w = mwlink.Wallet(open_sim(sim))
    try:
        check(mwlink.describe_reset(w.info()) == "last reset: power-on", "power-on text")
    finally:
        w.close()


def test_busy_and_decline(sim, folder):
    """A second file while the device reviews the first is refused as BUSY;
    a declined file's name is not used for a later result."""
    w = mwlink.Wallet(open_sim(sim, "--confirm-ms", "300", "--decline", "1"))
    try:
        ex = mwlink.Exchange(w, folder)
        a = os.path.join(folder, "alice_1789000001_outputs")
        b = os.path.join(folder, "bob_1789000002_outputs")
        for p in (a, b):
            with open(p, "wb") as f:
                f.write(b"Monero output export\x04" + os.urandom(80))
        ex.send(a)
        ev = ex.step()
        check(ex.device_state == mwlink.STATE_BUSY, "busy after send %r" % ev)
        try:
            ex.send(b)
            check(False, "busy device accepted a file")
        except mwlink.LinkError as e:
            check(e.code == mwlink.ERR_BUSY and "busy with the previous file" in str(e)
                  and "no wallet" not in str(e), "busy refusal: %s" % e)
        time.sleep(0.4)
        events = []
        for _ in range(3):
            events += ex.step()
        check(any("no result for alice_1789000001_outputs" in e for e in events),
              "decline reported %r" % events)
        check(not ex.pending, "declined name dropped %r" % ex.pending)
        ex.send(b)
        ex.step()
        time.sleep(0.4)
        events = ex.step() + ex.step()
        saved = [e for e in events if e.startswith("saved ")]
        check(len(saved) == 1 and "bob_" in saved[0] and "_keyImages" in saved[0],
              "result named after the file that produced it %r" % events)
        check(ex.take_saved() and not ex.take_saved(), "take_saved once")
    finally:
        w.close()


def test_exchange_files(sim, folder):
    """Folder changes keep pending names; manual sends are never re-sent by
    the watcher; local file errors are reported and keep the result."""
    w = mwlink.Wallet(open_sim(sim, "--confirm-ms", "200"))
    try:
        watch = os.path.join(folder, "watch")
        os.makedirs(watch)
        ex = mwlink.Exchange(w, watch, watch=True)
        p = os.path.join(watch, "carol_1789000003_outputs")
        with open(p, "wb") as f:
            f.write(b"Monero output export\x04" + os.urandom(80))
        old = time.time() - 5
        os.utime(p, (old, old))
        ex.device_state = mwlink.STATE_WALLET
        # Hand-picked, through a differently spelled path: the watcher must
        # recognise the same file.
        alias = os.path.join(watch, ".", "carol_1789000003_outputs").replace("\\", "/")
        ex.send(alias)
        check(os.path.exists(p), "a hand-picked file is not moved")
        other = os.path.join(folder, "elsewhere")
        ex.set_folder(other)
        ex.set_watch(True)
        ex.set_folder(watch)
        check(ex.pending.get(mwlink.K_KEYIMAGES, ("",))[0] == "carol_1789000003_outputs",
              "pending kept across set_folder/set_watch %r" % ex.pending)
        time.sleep(0.3)
        events = []
        for _ in range(3):
            events += ex.step()
        sent = [e for e in events if e.startswith("sent ")]
        check(not sent, "watcher did not re-send the hand-picked file %r" % events)
        saved = [e for e in events if e.startswith("saved ")]
        check(len(saved) == 1 and "carol_" in saved[0], "result after folder toggles %r" % events)

        # Watcher: the move to sent/ fails (Feather still has the file open).
        q = os.path.join(watch, "dave_1789000004_outputs")
        with open(q, "wb") as f:
            f.write(b"Monero output export\x04" + os.urandom(60))
        os.utime(q, (old, old))
        real_move = mwlink.shutil.move

        def busy_move(a, b):
            raise PermissionError(13, "The process cannot access the file")
        mwlink.shutil.move = busy_move
        try:
            events = ex.step()
        finally:
            mwlink.shutil.move = real_move
        check(any(e.startswith("sent dave_") and "could not move it to sent/" in e
                  for e in events), "move error reported %r" % events)
        time.sleep(0.3)
        events = ex.step() + ex.step()
        check(not any(e.startswith("sent ") for e in events), "not re-sent after move error")

        # The result cannot be saved: reported once, kept on the device.
        r = os.path.join(watch, "erin_1789000005_outputs")
        with open(r, "wb") as f:
            f.write(b"Monero output export\x04" + os.urandom(60))
        ex.send(r)
        ex.step()
        time.sleep(0.3)
        real_write = ex._write_new

        def no_space(folder_, name, data):
            raise OSError(28, "No space left on device")
        ex._write_new = no_space
        try:
            ev1 = ex.step()
            ev2 = ex.step()
        finally:
            ex._write_new = real_write
        check(sum("could not save the keyimages result" in e for e in ev1 + ev2) == 1,
              "save error reported once %r" % (ev1 + ev2))
        check(ex.last_status["outbox"][mwlink.K_KEYIMAGES] > 0, "result kept on the device")
        ev = ex.step()
        check(any(e.startswith("saved ") and "erin_" in e for e in ev), "saved on retry %r" % ev)
        check(mwlink.detect_kind(b"\xef\xbb\xbfMonero unsigned tx set") == mwlink.K_UNSIGNED,
              "BOM stripped")
    finally:
        w.close()


# ---------------------------------------------------------------------------
# HID transport against a scripted device
# ---------------------------------------------------------------------------
class FakeHidDev:
    def __init__(self, reports=()):
        self.reports = list(reports)
        self.timeouts = []
        self.nonblocking = None
        self.fail = None

    def set_nonblocking(self, nb):
        self.nonblocking = nb

    def read(self, n, timeout_ms=0):
        self.timeouts.append(timeout_ms)
        if self.fail:
            raise self.fail
        if self.reports:
            r = self.reports.pop(0)
            if r is None:                    # "nothing yet" within this read
                return []
            return list(r)
        return []

    def write(self, data):
        if self.fail:
            raise self.fail
        return len(data)

    def close(self):
        pass


def hid_reports(msg):
    out = [bytes([1]) + (b"?##" + msg[:60]).ljust(63, b"\x00")]
    off = 60
    while off < len(msg):
        out.append(bytes([1]) + (b"?" + msg[off:off + 62]).ljust(63, b"\x00"))
        off += 62
    return out


def hid_transport(dev):
    t = mwlink.HidTransport.__new__(mwlink.HidTransport)
    t.dev = dev
    t.timeout = 10.0
    t.path = b"fake"
    t.port = "hid"
    t._buf = bytearray()
    t._expect = None
    return t


def test_hid_transport():
    # A continuation whose data starts with "##" is not a new frame.
    payload = bytearray(os.urandom(200))
    payload[40:42] = b"##"                       # first continuation starts here (20-byte header)
    msg = mwlink.build_msg(mwlink.EVT_LOG, 2, bytes(payload))
    reps = hid_reports(msg)
    check(reps[1][1:4] == b"?##", "test vector has '?##' continuation")
    t = hid_transport(FakeHidDev(reps))
    check(t.recv(1.0) == msg, "continuation starting with ## kept")

    # Protocol 3: even "##" + the whole 8-byte magic in a continuation is not
    # a frame start - its header CRC does not match.
    payload = bytearray(os.urandom(200))
    payload[40:42] = b"##"
    payload[42:50] = mwlink.MAGIC
    payload[50] = mwlink.PROTO_VERSION
    msg = mwlink.build_msg(mwlink.EVT_LOG, 2, bytes(payload))
    reps = hid_reports(msg)
    check(reps[1][1:12] == b"?##" + mwlink.MAGIC, "test vector has '?##'+magic continuation")
    check(not mwlink.hid_is_start(reps[1][1:]), "continuation with magic is not a start")
    t = hid_transport(FakeHidDev(reps))
    check(t.recv(1.0) == msg, "continuation starting with ##+magic kept")

    # Header layout and the old-protocol diagnosis.
    m = mwlink.build_msg(mwlink.CMD_PING, 5, b"abc")
    check(m[:8] == mwlink.MAGIC and m[8] == 3 and m[9] == mwlink.CMD_PING and m[10] == 5,
          "protocol-3 header layout")
    check(mwlink.parse_msg(m) == (mwlink.CMD_PING, 5, b"abc"), "parse round trip")
    bad = bytearray(m); bad[10] ^= 1
    try:
        mwlink.parse_msg(bytes(bad))
        check(False, "header crc not checked")
    except mwlink.LinkError as e:
        check("header crc" in str(e), "header crc error reported")

    # A message split across two reads (pump windows) is not lost.
    msg2 = mwlink.build_msg(mwlink.EVT_LOG, 2, b"x" * 150)
    reps2 = hid_reports(msg2)
    dev = FakeHidDev([reps2[0], reps2[1]])
    t = hid_transport(dev)
    try:
        t.recv(0.01)
        check(False, "partial message returned")
    except mwlink.LinkTimeout:
        pass
    dev.reports = [reps2[2]]
    check(t.recv(1.0) == msg2, "message split across reads delivered")

    # Never a 0 ms read (hidapi would call blocking hid_read()).
    dev = FakeHidDev()
    t = hid_transport(dev)
    for left in (0.0005, 0.0009999, 0.000001):
        dev.reports = [None]
        try:
            t._read_report(time.monotonic() + left)
        except mwlink.LinkTimeout:
            pass
    check(dev.timeouts and min(dev.timeouts) >= 1, "read timeouts >= 1 ms: %r" % dev.timeouts)

    # A failing device is a LinkDisconnected, not a bare OSError.
    dev = FakeHidDev()
    dev.fail = OSError("read error")
    t = hid_transport(dev)
    try:
        t.recv(0.5)
        check(False, "read error swallowed")
    except mwlink.LinkDisconnected as e:
        check("read error" in str(e), "hid read error -> LinkDisconnected")
    try:
        t.send(b"MW" + b"\x00" * 10)
        check(False, "write error swallowed")
    except mwlink.LinkDisconnected:
        pass


def test_open_transport():
    """auto: HID first; a port that cannot be opened falls back to HID."""
    saved = {k: sys.modules.get(k) for k in ("hid", "serial")}
    opened = []

    class Dev(FakeHidDev):
        def open_path(self, path):
            opened.append(path)

    hid = types.ModuleType("hid")
    hid.enumerate = lambda vid=0, pid=0: [{"path": b"p1", "product_id": 0x4024,
                                           "usage_page": 0xFF00}]
    hid.device = Dev
    serial = types.ModuleType("serial")

    class SerialException(IOError):
        pass

    def Serial(port, *a, **kw):
        raise SerialException("could not open port %r: PermissionError(13, 'Access is denied.')"
                              % port)
    serial.Serial = Serial
    serial.SerialException = SerialException
    sys.modules["hid"] = hid
    sys.modules["serial"] = serial
    try:
        t = mwlink.open_transport("auto", "COM7")
        check(isinstance(t, mwlink.HidTransport) and t.dev.nonblocking is True,
              "busy port falls back to HID (non-blocking)")
        check(t.describe() == "hid", "describe hid")
        t = mwlink.open_transport("auto", None)
        check(isinstance(t, mwlink.HidTransport), "auto prefers HID")
        try:
            mwlink.open_transport("serial", "COM7")
            check(False, "explicit serial fell back")
        except mwlink.LinkError as e:
            check("Access is denied" in str(e), "explicit serial error %s" % e)
        hid.enumerate = lambda vid=0, pid=0: []
        try:
            mwlink.open_transport("auto", "COM7")
            check(False, "no device opened")
        except mwlink.LinkError as e:
            check("COM7" in str(e), "error names the port: %s" % e)
    finally:
        for k, v in saved.items():
            if v is None:
                sys.modules.pop(k, None)
            else:
                sys.modules[k] = v


def test_locked(sim, folder):
    w = mwlink.Wallet(open_sim(sim, "--locked"))
    try:
        p = os.path.join(folder, "x_1789637203_outputs")
        with open(p, "wb") as f:
            f.write(b"Monero output export\x04" + b"\x01" * 50)
        try:
            w.put(mwlink.KIND_AUTO, open(p, "rb").read())
            check(False, "locked accepted a file")
        except mwlink.LinkError as e:
            check(e.code == mwlink.ERR_LOCKED and "wallet" in str(e), "locked refusal: %s" % e)
        try:
            w.request(mwlink.REQ_ADDRESS)
            check(False, "locked accepted a request")
        except mwlink.LinkError as e:
            check(e.code == mwlink.ERR_LOCKED, "locked request refusal")
    finally:
        w.close()


def main():
    sim = sys.argv[1] if len(sys.argv) > 1 else os.path.join(HERE, "link_sim")
    if os.name == "nt" and not sim.endswith(".exe") and os.path.exists(sim + ".exe"):
        sim += ".exe"
    test_names()
    test_cobs()
    tmp = tempfile.mkdtemp(prefix="mwlink-")
    try:
        test_protocol(sim, tmp)
        test_locked(sim, tmp)
        test_info_reset(sim)
        for name, fn in (("busy", test_busy_and_decline), ("files", test_exchange_files)):
            d = os.path.join(tmp, name)
            os.makedirs(d)
            fn(sim, d)
        test_hid_transport()
        test_open_transport()
    finally:
        shutil.rmtree(tmp, ignore_errors=True)
    print("%d failures" % len(FAILS))
    return 1 if FAILS else 0


if __name__ == "__main__":
    sys.exit(main())
