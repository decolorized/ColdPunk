"""Device stand-ins for driving mwlink / mwlink_gui headless (test_mwlink_gui.py).

* SimProc    - link_sim (the real link core) behind pipes, with a reader thread
               so reads honour timeouts like a real port. kill() is a device
               reset or an unplug.
* fake `serial` (pyserial look-alike): the wallet's CDC port COM7 bridged to
               the current SimProc, a foreign port COM3, and ports that are
               "held by another program" (PermissionError on open).
* fake `hid` (cython-hidapi look-alike): read(max_length, timeout_ms) where
               timeout_ms <= 0 in blocking mode means hid_read(), i.e. waiting
               forever; a dead device raises IOError('read error'). Reports are
               bridged to link_sim by re-framing them as COBS frames.
"""
import os
import queue
import struct
import subprocess
import sys
import threading
import time
import types

SIM = {"exe": None}


def cobs_encode(data):
    out = bytearray()
    idx, n = 0, len(data)
    while True:
        end = data.find(b"\x00", idx)
        if end < 0:
            end = n
        while end - idx >= 254:
            out.append(0xFF)
            out += data[idx:idx + 254]
            idx += 254
        out.append(end - idx + 1)
        out += data[idx:end]
        idx = end + 1
        if end >= n:
            break
    return bytes(out)


def cobs_decode(data):
    out = bytearray()
    idx, n = 0, len(data)
    while idx < n:
        code = data[idx]
        idx += 1
        run = code - 1
        out += data[idx:idx + run]
        idx += run
        if code != 0xFF and idx < n:
            out.append(0)
    return bytes(out)


class SimProc:
    def __init__(self, *args):
        self.p = subprocess.Popen([SIM["exe"]] + list(args), stdin=subprocess.PIPE,
                                  stdout=subprocess.PIPE)
        self.rx = queue.Queue()
        self.wlock = threading.Lock()
        self.dead = False
        threading.Thread(target=self._reader, daemon=True).start()

    def _reader(self):
        fd = self.p.stdout.fileno()
        while True:
            try:
                b = os.read(fd, 4096)
            except OSError:
                b = b""
            if not b:
                self.dead = True
                self.rx.put(None)
                return
            self.rx.put(b)

    def write(self, data):
        with self.wlock:
            self.p.stdin.write(data)
            self.p.stdin.flush()

    def kill(self):
        self.dead = True
        try:
            self.p.kill()
            self.p.wait(5)
        except Exception:
            pass


# ---------------------------------------------------------------------------
# fake pyserial
# ---------------------------------------------------------------------------
SERIAL = {"cur": None, "dev_port": "COM7", "other_ports": ["COM3"], "held": set(),
          "opened": []}


class PipeSerial:
    def __init__(self, sim, timeout=0.05):
        self.sim = sim
        self.timeout = timeout
        self._buf = bytearray()
        self.closed = False

    def reset_input_buffer(self):
        pass

    def write(self, data):
        if self.closed:
            raise ValueError("port not open")
        if self.sim.dead:
            raise OSError("WriteFile failed (PermissionError(13, 'Access is denied.'))")
        self.sim.write(data)
        return len(data)

    def flush(self):
        pass

    def read(self, n):
        if self.sim.dead and not self._buf:
            raise OSError("ClearCommError failed (device gone)")
        if not self._buf:
            try:
                b = self.sim.rx.get(timeout=self.timeout)
            except queue.Empty:
                return b""
            if b is None:
                raise OSError("ClearCommError failed (device gone)")
            self._buf += b
        out = bytes(self._buf[:n])
        del self._buf[:n]
        return out

    def close(self):
        self.closed = True


class _ForeignPort:
    """A COM port that is not the wallet (a USB-UART bridge, say)."""

    def reset_input_buffer(self):
        pass

    def write(self, d):
        return len(d)

    def flush(self):
        pass

    def read(self, n):
        time.sleep(0.05)
        return b""

    def close(self):
        pass


def install_fake_serial():
    serial = types.ModuleType("serial")
    tools = types.ModuleType("serial.tools")
    lp = types.ModuleType("serial.tools.list_ports")

    class SerialException(IOError):
        pass

    def Serial(port, baud=115200, timeout=None, write_timeout=None):
        if port in SERIAL["held"]:
            raise SerialException("could not open port '%s': PermissionError(13, 'Access is "
                                  "denied.', None, 5)" % port)
        if port == SERIAL["dev_port"] and SERIAL["cur"] is not None:
            s = PipeSerial(SERIAL["cur"], timeout or 0.05)
            SERIAL["opened"].append(s)
            return s
        if port in SERIAL["other_ports"]:
            return _ForeignPort()
        raise SerialException("could not open port '%s': FileNotFoundError" % port)

    class P:
        def __init__(self, dev, vid, pid, desc):
            self.device, self.vid, self.pid, self.description = dev, vid, pid, desc

    def comports():
        out = [P(p, 0x1A86, 0x7523, "USB-SERIAL CH340 (%s)" % p) for p in SERIAL["other_ports"]]
        if SERIAL["cur"] is not None:
            out.append(P(SERIAL["dev_port"], 0x303A, 0x4024, "USB Serial Device"))
        return out

    serial.Serial = Serial
    serial.SerialException = SerialException
    lp.comports = comports
    tools.list_ports = lp
    serial.tools = tools
    sys.modules["serial"] = serial
    sys.modules["serial.tools"] = tools
    sys.modules["serial.tools.list_ports"] = lp


# ---------------------------------------------------------------------------
# fake hidapi
# ---------------------------------------------------------------------------
HID = {"cur": None, "timeouts": [], "blocking_reads": 0, "block_limit": 20.0,
       "fail_reads": False}


class HidBridge:
    """Device side of the fake HID, the same rules as link.c: a frame starts
    on '?##MW'; IN reports carry report ID 1 + 63 data bytes, as Windows
    hidapi returns them."""

    def __init__(self, sim):
        self.sim = sim
        self.inq = queue.Queue()
        self.rxbuf = bytearray()
        self.expect = None
        self.in_frame = False
        self.dead = False
        self._sbuf = bytearray()
        threading.Thread(target=self._from_sim, daemon=True).start()

    def push_msg(self, msg):
        self.inq.put(bytes([1]) + (b"?##" + msg[:60]).ljust(63, b"\x00"))
        off = 60
        while off < len(msg):
            self.inq.put(bytes([1]) + (b"?" + msg[off:off + 62]).ljust(63, b"\x00"))
            off += 62

    def _from_sim(self):
        while True:
            b = self.sim.rx.get()
            if b is None:
                self.dead = True
                return
            self._sbuf += b
            while True:
                z = self._sbuf.find(b"\x00")
                if z < 0:
                    break
                frame = bytes(self._sbuf[:z])
                del self._sbuf[:z + 1]
                if frame:
                    self.push_msg(cobs_decode(frame))

    def host_write(self, rep63):
        if rep63[:5] == b"?##MW":
            self.rxbuf = bytearray(rep63[3:])
            self.expect = None
            self.in_frame = True
        elif rep63[:1] == b"?" and self.in_frame:
            self.rxbuf += rep63[1:]
        else:
            return
        if self.expect is None and len(self.rxbuf) >= 8:
            (plen,) = struct.unpack("<I", self.rxbuf[4:8])
            self.expect = 12 + plen
        if self.expect is not None and len(self.rxbuf) >= self.expect:
            msg = bytes(self.rxbuf[:self.expect])
            self.rxbuf = bytearray()
            self.in_frame = False
            self.expect = None
            self.sim.write(cobs_encode(msg) + b"\x00")


class _Device:
    def __init__(self):
        self.blocking = True
        self.bridge = None

    def open_path(self, path):
        self.bridge = HID["cur"]
        if self.bridge is None or self.bridge.dead:
            raise IOError("open failed")

    def set_nonblocking(self, nb):
        self.blocking = not nb

    def write(self, data):
        if self.bridge.dead or self.bridge.sim.dead:
            return -1
        data = bytes(data)
        if len(data) != 64 or data[0] != 1:
            return -1
        self.bridge.host_write(data[1:])
        return len(data)

    def read(self, max_length, timeout_ms=0):
        HID["timeouts"].append(timeout_ms)
        if self.bridge.dead or self.bridge.sim.dead or HID["fail_reads"]:
            raise IOError("read error")
        if timeout_ms > 0:
            wait = timeout_ms / 1000.0
        elif self.blocking:
            HID["blocking_reads"] += 1            # hid_read(): would wait forever
            wait = HID["block_limit"]
        else:
            wait = 0
        try:
            rep = self.bridge.inq.get(timeout=wait) if wait > 0 else self.bridge.inq.get_nowait()
        except queue.Empty:
            if self.bridge.dead:
                raise IOError("read error")
            return []
        return list(rep[:max_length])

    def close(self):
        pass


def install_fake_hid():
    m = types.ModuleType("hid")

    def enumerate(vid=0, pid=0):
        if HID["cur"] is None or HID["cur"].dead:
            return []
        return [{"path": b"\\\\?\\hid#fake", "vendor_id": 0x303A, "product_id": 0x4024,
                 "usage_page": 0xFF00, "usage": 1}]

    m.enumerate = enumerate
    m.device = _Device
    sys.modules["hid"] = m


def remove_fake_hid():
    """hidapi not installed."""
    sys.modules["hid"] = None
