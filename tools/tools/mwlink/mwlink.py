#!/usr/bin/env python3
"""mwlink - host-side courier for the Monero Cold Wallet USB link (protocol 3).

The program is transport only. It moves Feather / Monero exchange files
between a folder on the PC and the device, over the standard USB serial port
(COBS + CRC32) or the vendor HID interface (64-byte reports). It never sees a
seed or a key: the files are encrypted by the wallets on both ends, every
conversion happens on the device, and the device asks its user before it
produces anything.

  * Any file can be sent, whatever its name or extension: the DEVICE
    recognises it by content ("Monero output export", "Monero unsigned tx
    set") and refuses anything else with a reason.
  * Results are fetched as soon as the device has them and saved next to the
    input, named like Feather names its files:
        borya-view2_1789637203_outputs   ->  borya-view2_1789638364_keyImages
        1789839233_unsigned_monero_tx    ->  1789839961_signed_monero_tx
  * The device log (what it is doing, errors with details, and the extended
    stream in its debug mode) is printed to stderr / shown by mwlink_gui.py.

Protocol: see docs/usb_link_protocol.md and src/transfer/link.h.

Usage:
    mwlink.py [--serial PORT | --hid] ping
    mwlink.py [...] info
    mwlink.py [...] status
    mwlink.py [...] send FILE [--out DIR]    send any file, wait for the result
    mwlink.py [...] put  [KIND|auto] FILE    raw PUT (default: auto)
    mwlink.py [...] get  KIND OUT [--keep]   saves the outbox file; clears it unless --keep
    mwlink.py [...] clear [KIND|all]
    mwlink.py [...] request address|viewonly [--out DIR]
    mwlink.py [...] console                  print the device log until Ctrl-C
    mwlink.py [...] exchange [DIR]           watch DIR (default ./exchange next to this
                                             file): send new Feather files, save results

    KIND: outputs | keyimages | unsigned_tx | signed_tx | wallet_export | 0..4

Without --serial/--hid the tool looks for the device by VID/PID and prefers
the vendor HID interface (it can be shared with other programs and keeps
working while the COM port is held by, say, the Arduino IDE); it uses the
serial port when hidapi is missing or the board has no HID interface (USB Mode
"Hardware CDC and JTAG"). `--serial PORT` without --hid still falls back to
HID when that port cannot be opened.
Dependencies: pyserial for serial, hidapi ("pip install hidapi") for HID.

If the device resets in the middle of a command (it says "read error" or the
port vanishes), the tool waits up to 10 s for it to come back and prints why it
restarted (INFO "last reset").
"""

import argparse
import math
import os
import re
import shutil
import struct
import sys
import time
import zlib

# ---------------------------------------------------------------------------
# Constants mirrored from src/transfer/link.h and usb_descriptors.h
# ---------------------------------------------------------------------------
USB_VID = 0x303A
USB_PIDS = (0x4024, 0x4025, 0x1001)   # link, CDC-only, Espressif default (CDC On Boot)

# Protocol 3: 8-byte magic, version byte and a CRC32 of the header itself, so
# a frame start can be recognised (and a false one rejected) from the first
# HID report alone. Protocol 2 used the 2-byte magic "MW" only.
PROTO_VERSION = 3
MAGIC = bytes([0x4D, 0x57, 0x50, 0x4B, 0xC7, 0x3A, 0x5E, 0x91])   # "MWPK" + 4 random
HDR_CRC_OFF = 16
HDR_LEN = 20
CRC_LEN = 4
MAX_PAYLOAD = 256 * 1024
MAX_MSG = HDR_LEN + MAX_PAYLOAD + CRC_LEN

HID_REPORT_ID = 0x01
HID_DATA = 63
HID_FIRST_DATA = HID_DATA - 3
HID_CONT_DATA = HID_DATA - 1

CMD_PING, CMD_INFO, CMD_PUT, CMD_GET, CMD_STATUS, CMD_CLEAR, CMD_REQ = 1, 2, 3, 4, 5, 6, 7
RSP_PONG, RSP_INFO, RSP_ACK, RSP_FILE, RSP_STATUS, RSP_ERROR = 0x81, 0x82, 0x83, 0x84, 0x85, 0xFF
EVT_LOG = 0x90

ERR_NOT_READY, ERR_BAD_FORMAT, ERR_BUSY, ERR_LOCKED = 4, 9, 10, 11
ERR_NAMES = {
    1: "bad command", 2: "bad file kind", 3: "too big", 4: "not ready",
    5: "no memory", 6: "crc", 7: "bad length", 8: "bad magic",
    9: "unrecognised file", 10: "busy", 11: "not accepted",
}
LOG_LEVELS = {0: "P", 1: "E", 2: "I", 3: "D"}   # progress, error, info, debug

KINDS = ["outputs", "keyimages", "unsigned_tx", "signed_tx", "wallet_export"]
K_OUTPUTS, K_KEYIMAGES, K_UNSIGNED, K_SIGNED, K_EXPORT = range(5)
N_KINDS = len(KINDS)
KIND_ALL = 0xFF
KIND_AUTO = 0xFE

REQ_ADDRESS, REQ_VIEWONLY = 1, 2
REQ_NAMES = {"address": REQ_ADDRESS, "viewonly": REQ_VIEWONLY}

STATE_NAMES = {0: "locked", 1: "menu", 2: "wallet open", 3: "busy"}
STATE_LOCKED, STATE_MENU, STATE_WALLET, STATE_BUSY = 0, 1, 2, 3
NETWORKS = {0: "mainnet", 1: "testnet", 2: "stagenet"}

CAP_SERIAL, CAP_HID, CAP_MSC, CAP_AUTO_KIND, CAP_REQ = 1, 2, 4, 8, 16

# INFO bytes 92..97 (link.h, hal.h): why the device last restarted, and - only
# while it is unlocked - what it was doing when it crashed.
RESET_NAMES = {
    0: "unknown", 1: "power-on", 2: "reset pin", 3: "software restart",
    4: "crash (panic)", 5: "interrupt watchdog", 6: "task watchdog", 7: "watchdog",
    8: "deep sleep wake", 9: "brownout", 10: "USB/JTAG reset", 11: "other",
}
RESET_CRASHES = (4, 5, 6, 7, 9)
CRASH_OPS = {1: "signing", 2: "key images", 3: "opening a wallet", 4: "wallet export"}
CRASH_STAGES = {1: "loading", 2: "review", 3: "keys", 4: "CLSAG", 5: "Bulletproofs+",
                6: "sealing", 7: "output"}
CRASH_VALID, CRASH_STACK = 1, 2

# File magics, only to name and pre-filter files on the PC. The device makes
# the real decision and explains a refusal.
MAGICS = [
    (b"Monero output export", K_OUTPUTS),
    (b"Monero unsigned tx set", K_UNSIGNED),
    (b"Monero key image export", K_KEYIMAGES),
    (b"Monero signed tx set", K_SIGNED),
]


UTF8_BOM = b"\xef\xbb\xbf"
ASCII_EXPORT_MAGIC = b"MoneroAsciiDataV1"


def detect_kind(data):
    """Kind of a Monero exchange file by its magic, or None."""
    if data.startswith(UTF8_BOM):
        data = data[len(UTF8_BOM):]
    for magic, kind in MAGICS:
        if data.startswith(magic):
            return kind
    return None


def default_exchange_dir():
    base = os.path.dirname(os.path.abspath(sys.argv[0] if getattr(sys, "frozen", False) else __file__))
    return os.path.join(base, "exchange")


# ---------------------------------------------------------------------------
# Output file names (task 3 step 6)
# ---------------------------------------------------------------------------
_TS = r"(?P<ts>\d{9,11})"
_EXT = r"(?P<ext>\.[A-Za-z0-9]{1,8})?"


def result_name(input_name, out_kind, now=None, wallet=None):
    """Name of a result file, following Feather's naming:
        <prefix><ts>_outputs            -> <prefix><now>_keyImages
        <prefix><ts>_unsigned_monero_tx -> <prefix><now>_signed_monero_tx
    Anything else keeps its name with a suffix."""
    now = str(int(time.time() if now is None else now))
    base = os.path.basename(input_name or "")
    if out_kind == K_KEYIMAGES:
        m = re.match(r"^(?P<pre>.*?)" + _TS + r"_outputs" + _EXT + r"$", base)
        if m:
            return "%s%s_keyImages%s" % (m.group("pre"), now, m.group("ext") or "")
        m = re.match(r"^(?P<pre>.*?)outputs" + _EXT + r"$", base, re.IGNORECASE)
        if m and base:
            return "%s%s_keyImages%s" % (m.group("pre"), now, m.group("ext") or "")
        return "%s_%s_keyImages" % (base or "wallet", now)
    if out_kind == K_SIGNED:
        m = re.match(r"^(?P<pre>.*?)" + _TS + r"_unsigned_monero_tx" + _EXT + r"$", base)
        if m:
            return "%s%s_signed_monero_tx%s" % (m.group("pre"), now, m.group("ext") or "")
        if "unsigned" in base:
            name = re.sub(r"\d{9,11}", now, base, count=1)
            return name.replace("unsigned", "signed", 1)
        return "%s_%s_signed_monero_tx" % (base or "tx", now)
    if out_kind == K_EXPORT:
        safe = re.sub(r"[^A-Za-z0-9_.-]+", "_", wallet or "wallet").strip("_") or "wallet"
        return "%s_%s_%s.json" % (safe, now, input_name or "export")
    return "%s_%s_%s" % (base or "file", now, KINDS[out_kind])


class LinkError(Exception):
    def __init__(self, msg, code=None):
        super().__init__(msg)
        self.code = code


class LinkTimeout(LinkError):
    pass


class LinkDisconnected(LinkError):
    """The transport failed: device reset, unplugged or port closed. Raised
    only by the transports; the connection must be reopened."""
    pass


def describe_reset(info):
    """'last reset: ...' from an info() dict."""
    text = "last reset: %s" % RESET_NAMES.get(info.get("reset_reason", 0), "unknown")
    flags = info.get("crash_flags", 0)
    if flags & CRASH_VALID:
        text += " during %s / %s" % (CRASH_OPS.get(info["crash_op"], "op %d" % info["crash_op"]),
                                     CRASH_STAGES.get(info["crash_stage"],
                                                      "stage %d" % info["crash_stage"]))
    if flags & CRASH_STACK:
        text += ", crypto stack min free %d B" % info["crash_stack"]
    return text


# ---------------------------------------------------------------------------
# Message layer
# ---------------------------------------------------------------------------
def _crc(data):
    return zlib.crc32(data) & 0xFFFFFFFF


def build_header(cmd, arg, plen):
    head = MAGIC + struct.pack("<BBBBI", PROTO_VERSION, cmd, arg, 0, plen)
    return head + struct.pack("<I", _crc(head))


def header_valid(buf):
    """Payload length if buf starts with a valid protocol-3 header, else None."""
    if len(buf) < HDR_LEN or bytes(buf[:len(MAGIC)]) != MAGIC:
        return None
    if buf[8] != PROTO_VERSION:
        return None
    (hcrc,) = struct.unpack("<I", bytes(buf[HDR_CRC_OFF:HDR_LEN]))
    if hcrc != _crc(bytes(buf[:HDR_CRC_OFF])):
        return None
    (plen,) = struct.unpack("<I", bytes(buf[12:16]))
    return plen


def build_msg(cmd, arg=0, payload=b""):
    if len(payload) > MAX_PAYLOAD:
        raise LinkError("file larger than %d bytes" % MAX_PAYLOAD)
    body = build_header(cmd, arg, len(payload)) + payload
    return body + struct.pack("<I", _crc(body))


def parse_msg(buf):
    if len(buf) < HDR_LEN + CRC_LEN:
        raise LinkError("short frame (%d bytes)" % len(buf))
    if bytes(buf[:len(MAGIC)]) != MAGIC:
        raise LinkError("bad magic %r (device firmware with an older link protocol?)"
                        % bytes(buf[:len(MAGIC)]))
    if buf[8] != PROTO_VERSION:
        raise LinkError("link protocol %d, this program speaks %d: update the firmware "
                        "or mwlink" % (buf[8], PROTO_VERSION))
    if header_valid(buf) is None:
        raise LinkError("header crc mismatch")
    _ver, cmd, arg, _res, plen = struct.unpack("<BBBBI", bytes(buf[8:16]))
    if HDR_LEN + plen + CRC_LEN != len(buf):
        raise LinkError("length mismatch: header says %d, frame is %d" % (plen, len(buf)))
    body = buf[:HDR_LEN + plen]
    (crc,) = struct.unpack("<I", buf[HDR_LEN + plen:])
    if crc != (zlib.crc32(body) & 0xFFFFFFFF):
        raise LinkError("crc mismatch")
    return cmd, arg, bytes(buf[HDR_LEN:HDR_LEN + plen])


def msg_total_len(head):
    plen = header_valid(head)
    if plen is None:
        return None
    return HDR_LEN + plen + CRC_LEN


# ---------------------------------------------------------------------------
# COBS
# ---------------------------------------------------------------------------
def cobs_encode(data):
    out = bytearray()
    idx = 0
    n = len(data)
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
    idx = 0
    n = len(data)
    while idx < n:
        code = data[idx]
        idx += 1
        if code == 0:
            raise LinkError("zero inside COBS frame")
        run = code - 1
        if idx + run > n:
            raise LinkError("truncated COBS block")
        chunk = data[idx:idx + run]
        if b"\x00" in chunk:
            raise LinkError("zero inside COBS block")
        out += chunk
        idx += run
        if code != 0xFF and idx < n:
            out.append(0)
    return bytes(out)


# ---------------------------------------------------------------------------
# Transports
# ---------------------------------------------------------------------------
class SerialTransport:
    name = "serial"

    def __init__(self, port, timeout=10.0):
        import serial  # pyserial
        self.timeout = timeout
        self.port = port
        self._rx = bytearray()
        try:
            self.ser = serial.Serial(port, 115200, timeout=0.05, write_timeout=timeout)
        except (OSError, ValueError) as e:      # SerialException is an OSError
            raise LinkError("could not open %s: %s" % (port, e))
        try:
            self.ser.reset_input_buffer()
            self.ser.write(b"\x00")
        except (OSError, ValueError) as e:
            self.close()
            raise LinkError("could not open %s: %s" % (port, e))

    def describe(self):
        return "serial %s" % self.port

    def close(self):
        try:
            self.ser.close()
        except Exception:
            pass

    def send(self, msg):
        try:
            self.ser.write(cobs_encode(msg) + b"\x00")
            self.ser.flush()
        except (OSError, ValueError) as e:
            raise LinkDisconnected("serial %s: %s" % (self.port, e))

    def recv(self, timeout=None):
        deadline = time.monotonic() + (self.timeout if timeout is None else timeout)
        while True:
            zero = self._rx.find(b"\x00")
            if zero >= 0:
                frame = bytes(self._rx[:zero])
                del self._rx[:zero + 1]
                if not frame:
                    continue
                try:
                    return cobs_decode(frame)
                except LinkError:
                    continue
            if time.monotonic() > deadline:
                raise LinkTimeout("timeout waiting for a serial frame")
            try:
                chunk = self.ser.read(4096)
            except (OSError, ValueError) as e:
                raise LinkDisconnected("serial %s: %s" % (self.port, e))
            if chunk:
                self._rx += chunk


HID_FRAME_START = b"?##" + MAGIC


def hid_is_start(rep):
    """A report starts a frame only with "?##", the 8-byte magic and a valid
    header CRC - all of it inside this one report."""
    return rep[:3] == b"?##" and header_valid(rep[3:]) is not None


class HidTransport:
    name = "hid"

    def __init__(self, path=None, timeout=10.0):
        import hid  # hidapi
        self.timeout = timeout
        if path is None:
            path = find_hid_path()
            if path is None:
                raise LinkError("no wallet HID interface found (VID 0x%04X)" % USB_VID)
        try:
            self.dev = hid.device()
            self.dev.open_path(path)
            # Non-blocking: a read can never wait forever, whatever timeout
            # reaches it.
            self.dev.set_nonblocking(True)
        except (OSError, ValueError) as e:
            raise LinkError("could not open the wallet HID interface: %s" % e)
        self.path = path
        self.port = "hid"
        # A message split over several reads (pump windows) is kept here.
        self._buf = bytearray()
        self._expect = None

    def describe(self):
        return "hid"

    def close(self):
        try:
            self.dev.close()
        except Exception:
            pass

    def _write_report(self, data63):
        report = bytes([HID_REPORT_ID]) + data63
        try:
            n = self.dev.write(report)
        except (OSError, ValueError) as e:
            raise LinkDisconnected("hid: %s" % e)
        if n < 0:
            raise LinkDisconnected("hid write failed")

    def send(self, msg):
        first = msg[:HID_FIRST_DATA]
        self._write_report((b"?##" + first).ljust(HID_DATA, b"\x00"))
        off = HID_FIRST_DATA
        while off < len(msg):
            part = msg[off:off + HID_CONT_DATA]
            self._write_report((b"?" + part).ljust(HID_DATA, b"\x00"))
            off += HID_CONT_DATA

    def _read_report(self, deadline):
        while True:
            left = deadline - time.monotonic()
            if left <= 0:
                raise LinkTimeout("timeout waiting for a HID report")
            # Never 0: hidapi's read(timeout 0) is a plain hid_read().
            ms = max(1, int(math.ceil(min(left, 1.0) * 1000)))
            try:
                rep = self.dev.read(64, timeout_ms=ms)
            except (OSError, ValueError) as e:
                raise LinkDisconnected("hid: %s" % e)
            if rep:
                rep = bytes(rep)
                if len(rep) == HID_DATA + 1 and rep[0] == HID_REPORT_ID:
                    rep = rep[1:]
                return rep

    def recv(self, timeout=None):
        deadline = time.monotonic() + (self.timeout if timeout is None else timeout)
        while True:
            rep = self._read_report(deadline)
            # A frame starts only on "?##" + magic + valid header CRC:
            # continuation data may begin with "##" or even with the magic.
            if hid_is_start(rep):
                self._buf = bytearray(rep[3:])
                self._expect = None
            elif rep[:1] == b"?" and self._buf:
                self._buf += rep[1:]
            else:
                continue
            if self._expect is None and len(self._buf) >= HDR_LEN:
                expect = msg_total_len(self._buf)
                if expect is None or expect > MAX_MSG:
                    self._buf = bytearray()
                    continue
                self._expect = expect
            if self._expect is not None and len(self._buf) >= self._expect:
                msg = bytes(self._buf[:self._expect])
                self._buf = bytearray()
                self._expect = None
                return msg


def list_serial_ports():
    try:
        from serial.tools import list_ports
    except ImportError:
        return []
    return [(p.device, p.vid, p.pid, p.description) for p in list_ports.comports()]


def find_serial_port():
    for dev, vid, pid, _desc in list_serial_ports():
        if vid == USB_VID and pid in USB_PIDS:
            return dev
    return None


def find_hid_path():
    try:
        import hid
    except ImportError:
        return None
    try:
        devs = hid.enumerate(USB_VID, 0)
    except (OSError, ValueError):
        return None
    for d in devs:
        if d["product_id"] in USB_PIDS and d.get("usage_page", 0xFF00) == 0xFF00:
            return d["path"]
    return None


def open_transport(kind="auto", port=None, timeout=10.0):
    """kind: 'auto' | 'serial' | 'hid'.

    auto: the port given is tried first, falling back to HID when it cannot
    be opened (held by another program); without a port the wallet's HID
    interface is preferred, then its serial port (found by VID/PID)."""
    if kind == "serial":
        return SerialTransport(port or find_serial_port() or _no_port(), timeout)
    if kind == "hid":
        return HidTransport(None, timeout)
    errors = []
    if port:
        try:
            return SerialTransport(port, timeout)
        except LinkError as e:
            errors.append(str(e))
    path = find_hid_path()
    if path:
        try:
            return HidTransport(path, timeout)
        except LinkError as e:
            errors.append(str(e))
    if not port:
        p = find_serial_port()
        if p:
            try:
                return SerialTransport(p, timeout)
            except LinkError as e:
                errors.append(str(e))
    if errors:
        raise LinkError("; ".join(errors))
    raise LinkError("device not found; pass --serial PORT or --hid")


def _no_port():
    raise LinkError("no serial port given and none found by VID/PID")


# ---------------------------------------------------------------------------
# Client
# ---------------------------------------------------------------------------
def _cstr(b):
    return b.split(b"\x00", 1)[0].decode("utf-8", "replace")


class Wallet:
    """One device over one transport.

    `on_log(level, text)` is called for every LOG event the device sends,
    whether it arrives while a request is pending or during pump()."""

    def __init__(self, transport, on_log=None):
        self.t = transport
        self.on_log = on_log

    def close(self):
        self.t.close()

    def _handle_event(self, cmd, arg, payload):
        if cmd == EVT_LOG:
            if self.on_log:
                self.on_log(arg, payload.decode("utf-8", "replace"))
            return True
        return False

    def _recv_response(self, timeout):
        deadline = time.monotonic() + timeout
        while True:
            left = deadline - time.monotonic()
            if left <= 0:
                raise LinkTimeout("no response from the device")
            frame = self.t.recv(left)
            try:
                cmd, arg, payload = parse_msg(frame)
            except LinkError:
                if frame[:2] == b"MW" and frame[:len(MAGIC)] != MAGIC:
                    raise LinkError("the device speaks the old link protocol 2; flash the "
                                    "current firmware (this program needs protocol %d)"
                                    % PROTO_VERSION)
                continue
            if self._handle_event(cmd, arg, payload):
                continue
            return cmd, arg, payload

    def call(self, cmd, arg=0, payload=b"", timeout=None):
        self.t.send(build_msg(cmd, arg, payload))
        rcmd, rarg, rpay = self._recv_response(self.t.timeout if timeout is None else timeout)
        if rcmd == RSP_ERROR:
            text = rpay.decode("utf-8", "replace")
            raise LinkError("%s: %s" % (ERR_NAMES.get(rarg, "error %d" % rarg), text), rarg)
        return rcmd, rarg, rpay

    def pump(self, timeout=0.05):
        """Reads pending events for up to `timeout` seconds."""
        n = 0
        deadline = time.monotonic() + timeout
        while True:
            left = deadline - time.monotonic()
            if left <= 0:
                return n
            try:
                frame = self.t.recv(left)
            except LinkTimeout:
                return n
            try:
                cmd, arg, payload = parse_msg(frame)
            except LinkError:
                continue
            if self._handle_event(cmd, arg, payload):
                n += 1

    # ---- commands ----------------------------------------------------------
    def ping(self, payload=b"ping"):
        t0 = time.monotonic()
        cmd, _, echo = self.call(CMD_PING, 0, payload)
        if cmd != RSP_PONG or echo != payload[:256]:
            raise LinkError("bad PONG")
        return time.monotonic() - t0

    def info(self):
        cmd, _, p = self.call(CMD_INFO)
        if cmd != RSP_INFO:
            raise LinkError("bad INFO")
        if p[0] != PROTO_VERSION or len(p) < 128:
            raise LinkError("device speaks link protocol %d; this program needs %d "
                            "(update the firmware or the program)" % (p[0], PROTO_VERSION))
        (max_payload,) = struct.unpack("<I", p[4:8])
        return {
            "proto": p[0], "caps": p[1], "state": p[2],
            "network": NETWORKS.get(p[3], "?"), "max_payload": max_payload,
            "wallets": p[8], "unlocked": bool(p[9]), "passphrase": bool(p[10]),
            "kinds": p[11],
            "fw": _cstr(p[12:28]), "board": _cstr(p[28:60]), "wallet": _cstr(p[60:92]),
            "reset_reason": p[92], "crash_op": p[93], "crash_stage": p[94],
            "crash_flags": p[95], "crash_stack": struct.unpack("<H", p[96:98])[0],
        }

    def status(self):
        cmd, _, p = self.call(CMD_STATUS)
        if cmd != RSP_STATUS or len(p) < 48:
            raise LinkError("bad STATUS")
        inbox = struct.unpack("<5I", p[0:20])
        outbox = struct.unpack("<5I", p[20:40])
        (seq,) = struct.unpack("<I", p[44:48])
        return {"inbox": inbox, "outbox": outbox, "state": p[40], "request": p[41],
                "accept": p[42], "seq": seq}

    def put(self, kind, data):
        """PUT; kind KIND_AUTO lets the device classify the file. Returns the
        kind the device stored it as."""
        cmd, arg, _ = self.call(CMD_PUT, kind, data, timeout=max(self.t.timeout, 60.0))
        if cmd != RSP_ACK or (kind != KIND_AUTO and arg != kind):
            raise LinkError("bad ACK")
        return arg

    def get(self, kind):
        cmd, arg, p = self.call(CMD_GET, kind, timeout=max(self.t.timeout, 60.0))
        if cmd != RSP_FILE or arg != kind:
            raise LinkError("bad FILE")
        return p

    def clear(self, kind=KIND_ALL):
        cmd, _, _ = self.call(CMD_CLEAR, kind)
        if cmd != RSP_ACK:
            raise LinkError("bad ACK")

    def request(self, what):
        cmd, _, _ = self.call(CMD_REQ, what)
        if cmd != RSP_ACK:
            raise LinkError("bad ACK")


# ---------------------------------------------------------------------------
# Exchange logic, shared by the CLI and the GUI
# ---------------------------------------------------------------------------
def file_key(path):
    """Identity of a file across 8.3 / long names and slash styles."""
    return os.path.normcase(os.path.realpath(path))


def _sig(path):
    st = os.stat(path)
    return (st.st_size, int(st.st_mtime))


class Exchange:
    """Sends files to the device and saves what it produces.

    * send(path): any file; the device classifies it. The name of the latest
      file of each kind is remembered so the result can be named after it
      (and saved next to it).
    * step(): one round - watch the folder (when enabled) and fetch every
      result the device has ready. Returns human-readable events, one per
      thing that happened; paths of saved results are collected for
      take_saved().
    """

    RESULT_FOR = {K_OUTPUTS: K_KEYIMAGES, K_UNSIGNED: K_SIGNED}

    def __init__(self, wallet, folder, watch=False):
        self.w = wallet
        self.folder = folder
        self.watch = watch
        self.pending = {}          # result kind -> (input name, output folder)
        self.seen = {}             # file_key -> (size, mtime) already handled / refused
        self.device_state = None
        self.last_status = None
        self.wallet_name = ""
        self.saved = []            # paths saved since the last take_saved()
        self._busy_seen = False    # the device showed BUSY after our last send
        self._idle_polls = 0
        self._save_failed = set()  # kinds whose save error was already reported
        os.makedirs(os.path.join(folder, "sent"), exist_ok=True)

    def set_folder(self, folder):
        """Changes the exchange folder in place: pending result names stay."""
        os.makedirs(os.path.join(folder, "sent"), exist_ok=True)
        self.folder = folder

    def set_watch(self, on):
        self.watch = bool(on)

    def take_saved(self):
        out, self.saved = self.saved, []
        return out

    # ---- sending --------------------------------------------------------
    def send(self, path, move_to_sent=False):
        """Sends a file. Raises LinkError (refusal: e.code set) or OSError
        (the file cannot be read). With move_to_sent the file is moved to
        <folder>/sent afterwards; a failed move is reported in the message."""
        with open(path, "rb") as f:
            data = f.read()
        if not data:
            raise LinkError("%s is empty" % path)
        try:
            sig = _sig(path)
        except OSError:
            sig = None
        kind = self.w.put(KIND_AUTO, data)
        name = os.path.basename(path)
        out_kind = self.RESULT_FOR.get(kind)
        if out_kind is not None:
            self.pending[out_kind] = (name, os.path.dirname(os.path.abspath(path)))
            self._busy_seen = False
            self._idle_polls = 0
        msg = "sent %s (%d bytes) as %s: confirm on the device" % (name, len(data), KINDS[kind])
        key = file_key(path)
        if move_to_sent:
            stamp = time.strftime("%Y%m%d-%H%M%S")
            try:
                shutil.move(path, os.path.join(self.folder, "sent", "%s.%s" % (name, stamp)))
                self.seen.pop(key, None)
            except OSError as e:
                self.seen[key] = sig
                msg += " (could not move it to sent/: %s)" % e
        elif sig is not None:
            # A hand-picked file is never moved; the watcher must not send it
            # a second time.
            self.seen[key] = sig
        return msg

    def _scan_folder(self, events):
        try:
            names = sorted(os.listdir(self.folder))
        except OSError:
            return
        for name in names:
            path = os.path.join(self.folder, name)
            if not os.path.isfile(path):
                continue
            key = file_key(path)
            try:
                sig = _sig(path)
            except OSError:
                continue
            if self.seen.get(key) == sig:
                continue
            # A file being written right now: wait until it is a second old.
            if time.time() - sig[1] < 1.0:
                continue
            try:
                with open(path, "rb") as f:
                    head = f.read(32)
            except OSError:
                continue
            kind = detect_kind(head)
            if kind not in (K_OUTPUTS, K_UNSIGNED):
                self.seen[key] = sig                 # not ours to send
                if head.lstrip(UTF8_BOM).startswith(ASCII_EXPORT_MAGIC):
                    events.append("skipped %s: an ASCII export; save it from Feather in the "
                                  "binary format" % name)
                continue
            if self.device_state not in (STATE_WALLET,):
                return                               # try again once a wallet is open
            try:
                events.append(self.send(path, move_to_sent=True))
            except LinkDisconnected:
                raise
            except LinkError as e:
                self.seen[key] = sig
                if e.code is None:
                    events.append("could not send %s: %s" % (name, e))
                else:
                    events.append("device refused %s: %s" % (name, e))
                if e.code == ERR_BUSY:
                    self.seen.pop(key, None)         # retry later
            except OSError as e:
                self.seen[key] = sig
                events.append("could not read %s: %s" % (name, e))
            return                                   # one file per round

    # ---- results --------------------------------------------------------
    def _write_new(self, folder, name, data):
        path = os.path.join(folder, name)
        n = 1
        while os.path.exists(path):
            path = os.path.join(folder, "%s.%d" % (name, n))
            n += 1
        with open(path, "wb") as f:
            f.write(data)
        return path

    def _save(self, kind, data):
        """Writes a result; raises OSError when neither the input's folder nor
        the exchange folder can take it."""
        if kind == K_EXPORT:
            base, folder = "export", self.folder
            try:
                import json
                obj = json.loads(data.decode("utf-8"))
                base = "viewonly" if "view_key" in obj else "address"
            except Exception:
                pass
            name = result_name(base, K_EXPORT, wallet=self.wallet_name)
        else:
            inp, folder = self.pending.get(kind, (None, self.folder))
            name = result_name(inp, kind)
        try:
            path = self._write_new(folder, name, data)
        except OSError:
            if os.path.abspath(folder) == os.path.abspath(self.folder):
                raise
            path = self._write_new(self.folder, name, data)
        self.pending.pop(kind, None)
        return path

    def _track_declines(self, st, events):
        """Forgets the name of a sent file the device produced nothing for
        (declined or refused on the device): BUSY, then WALLET twice in a row
        without a result of that kind."""
        state = st["state"]
        if state == STATE_BUSY:
            self._busy_seen = True
            self._idle_polls = 0
        elif state == STATE_WALLET and self._busy_seen:
            if any(st["outbox"][k] for k in self.pending):
                self._busy_seen = False
                self._idle_polls = 0
                return
            self._idle_polls += 1
            if self._idle_polls >= 2:
                for k, (name, _folder) in list(self.pending.items()):
                    events.append("no result for %s: declined or refused on the device" % name)
                self.pending.clear()
                self._busy_seen = False
                self._idle_polls = 0
        elif state in (STATE_LOCKED, STATE_MENU):
            self.pending.clear()                     # the wallet was closed
            self._busy_seen = False

    def step(self):
        events = []
        st = self.w.status()
        self.last_status = st
        self.device_state = st["state"]
        self._track_declines(st, events)
        if self.watch:
            self._scan_folder(events)
        for kind in (K_KEYIMAGES, K_SIGNED, K_EXPORT):
            if not st["outbox"][kind]:
                continue
            data = self.w.get(kind)
            try:
                path = self._save(kind, data)
            except OSError as e:
                if kind not in self._save_failed:
                    self._save_failed.add(kind)
                    events.append("could not save the %s result: %s (it stays on the device; "
                                  "retrying)" % (KINDS[kind], e))
                continue
            self._save_failed.discard(kind)
            self.w.clear(kind)
            self.saved.append(path)
            events.append("saved %s (%d bytes)" % (path, len(data)))
        return events


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------
def parse_kind(text, allow_auto=False):
    if allow_auto and text == "auto":
        return KIND_AUTO
    if text in KINDS:
        return KINDS.index(text)
    if text == "all":
        return KIND_ALL
    try:
        k = int(text)
    except ValueError:
        raise LinkError("unknown kind %r" % text)
    if not 0 <= k < N_KINDS:
        raise LinkError("kind must be 0..%d" % (N_KINDS - 1))
    return k


def print_log(level, text):
    print("  [%s] %s" % (LOG_LEVELS.get(level, "?"), text), file=sys.stderr)


def describe_state(info_or_status, wallet=""):
    s = STATE_NAMES.get(info_or_status["state"], "?")
    if info_or_status["state"] in (STATE_WALLET, STATE_BUSY) and wallet:
        s += " '%s'" % wallet
    return s


def cmd_ping(w, args):
    for _ in range(args.count):
        rtt = w.ping(os.urandom(args.size))
        print("pong %d bytes, %.1f ms" % (args.size, rtt * 1000))


def _print_boxes(st):
    print("%-14s %8s %8s" % ("kind", "inbox", "outbox"))
    for k in range(N_KINDS):
        print("%-14s %8d %8d" % (KINDS[k], st["inbox"][k], st["outbox"][k]))


def cmd_info(w, args):
    i = w.info()
    caps = [n for bit, n in ((CAP_SERIAL, "serial"), (CAP_HID, "hid"),
                             (CAP_AUTO_KIND, "auto-kind"), (CAP_REQ, "requests"))
            if i["caps"] & bit]
    print("firmware    %s" % i["fw"])
    print("board       %s" % i["board"])
    print("protocol    %d" % i["proto"])
    print("caps        %s" % ", ".join(caps))
    print("max payload %d bytes" % i["max_payload"])
    print("state       %s" % describe_state(i, i["wallet"]))
    print("%-11s %s" % ("last reset", describe_reset(i)[len("last reset: "):]))
    if i["unlocked"]:
        print("wallets     %d, network %s%s" % (i["wallets"], i["network"],
                                                ", passphrase wallet" if i["passphrase"] else ""))


def cmd_status(w, args):
    st = w.status()
    print("state %s, request %d, accepts %s, seq %d" % (
        STATE_NAMES.get(st["state"], "?"), st["request"],
        ",".join(KINDS[k] for k in range(N_KINDS) if st["accept"] & (1 << k)) or "-",
        st["seq"]))
    _print_boxes(st)


def _wait_result(w, ex, what, timeout=600.0):
    """Waits for the device to produce a result (the user confirms on it)."""
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        for ev in ex.step():
            print(ev)
            if ev.startswith("saved "):
                return True
        w.pump(0.5)
    print("no %s from the device within %d s" % (what, timeout), file=sys.stderr)
    return False


def cmd_send(w, args):
    folder = args.out or os.path.dirname(os.path.abspath(args.file))
    ex = Exchange(w, folder)
    print(ex.send(args.file))
    _wait_result(w, ex, "result")


def cmd_put(w, args):
    if args.file is None:
        args.kind, args.file = "auto", args.kind
    kind = parse_kind(args.kind, allow_auto=True)
    with open(args.file, "rb") as f:
        data = f.read()
    if not data:
        raise LinkError("%s is empty" % args.file)
    t0 = time.monotonic()
    got = w.put(kind, data)
    dt = time.monotonic() - t0
    print("sent %s (%d bytes) as %s in %.2f s (%.1f KB/s)" %
          (args.file, len(data), KINDS[got], dt, len(data) / 1024 / max(dt, 1e-6)))


def cmd_get(w, args):
    kind = parse_kind(args.kind)
    data = w.get(kind)
    with open(args.out, "wb") as f:
        f.write(data)
    print("saved %s (%d bytes) from %s" % (args.out, len(data), KINDS[kind]))
    if not args.keep:
        w.clear(kind)


def cmd_clear(w, args):
    kind = parse_kind(args.kind) if args.kind else KIND_ALL
    w.clear(kind)
    print("cleared %s" % ("all" if kind == KIND_ALL else KINDS[kind]))


def cmd_request(w, args):
    what = REQ_NAMES[args.what]
    ex = Exchange(w, args.out or default_exchange_dir())
    try:
        ex.wallet_name = w.info()["wallet"]
    except LinkError:
        pass
    w.request(what)
    print("request sent: confirm it on the device")
    _wait_result(w, ex, args.what)


def cmd_console(w, args):
    print("device log (Ctrl-C to stop)")
    while True:
        w.pump(0.5)
        try:
            w.status()        # keeps the device's "host active" timer alive
        except LinkError:
            pass


def cmd_exchange(w, args):
    folder = args.dir or default_exchange_dir()
    os.makedirs(folder, exist_ok=True)
    ex = Exchange(w, folder, watch=True)
    print("watching %s (Ctrl-C to stop)" % folder)
    while True:
        try:
            for ev in ex.step():
                print("[%s] %s" % (time.strftime("%H:%M:%S"), ev))
        except LinkError as e:
            print("[%s] %s" % (time.strftime("%H:%M:%S"), e), file=sys.stderr)
        w.pump(0.5)


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    g = ap.add_mutually_exclusive_group()
    g.add_argument("--serial", metavar="PORT", help="COM port / tty of the CDC interface")
    g.add_argument("--hid", action="store_true", help="use the vendor HID interface")
    ap.add_argument("--timeout", type=float, default=10.0, help="response timeout, seconds")
    ap.add_argument("--quiet", action="store_true", help="do not print device log lines")
    sub = ap.add_subparsers(dest="cmd", required=True)

    p = sub.add_parser("ping"); p.add_argument("--count", type=int, default=3); p.add_argument("--size", type=int, default=32)
    p.set_defaults(fn=cmd_ping)
    sub.add_parser("info").set_defaults(fn=cmd_info)
    sub.add_parser("status").set_defaults(fn=cmd_status)
    p = sub.add_parser("send"); p.add_argument("file"); p.add_argument("--out"); p.set_defaults(fn=cmd_send)
    p = sub.add_parser("put"); p.add_argument("kind"); p.add_argument("file", nargs="?"); p.set_defaults(fn=cmd_put)
    p = sub.add_parser("get"); p.add_argument("kind"); p.add_argument("out"); p.add_argument("--keep", action="store_true")
    p.set_defaults(fn=cmd_get)
    p = sub.add_parser("clear"); p.add_argument("kind", nargs="?"); p.set_defaults(fn=cmd_clear)
    p = sub.add_parser("request"); p.add_argument("what", choices=sorted(REQ_NAMES)); p.add_argument("--out")
    p.set_defaults(fn=cmd_request)
    sub.add_parser("console").set_defaults(fn=cmd_console)
    p = sub.add_parser("exchange"); p.add_argument("dir", nargs="?"); p.set_defaults(fn=cmd_exchange)

    args = ap.parse_args(argv)
    kind = "hid" if args.hid else "auto"
    try:
        t = open_transport(kind, args.serial, args.timeout)
    except ImportError as e:
        print("missing dependency: %s (pip install pyserial hidapi)" % e, file=sys.stderr)
        return 2
    except LinkError as e:
        print("error: %s" % e, file=sys.stderr)
        return 2
    print("connected over %s" % t.describe())
    w = Wallet(t, None if args.quiet else print_log)
    try:
        args.fn(w, args)
    except KeyboardInterrupt:
        pass
    except LinkDisconnected as e:
        print("error: %s" % e, file=sys.stderr)
        w.close()
        report_after_reset(kind, args.serial, args.timeout)
        return 1
    except (LinkError, OSError) as e:
        print("error: %s" % e, file=sys.stderr)
        return 1
    finally:
        w.close()
    return 0


def report_after_reset(kind, port, timeout, wait=10.0):
    """After the link broke: waits up to `wait` seconds for the device to come
    back and prints why it restarted. Returns the info dict or None."""
    print("the link broke (device reset or unplugged?); waiting up to %d s for it" % wait,
          file=sys.stderr)
    deadline = time.monotonic() + wait
    while time.monotonic() < deadline:
        time.sleep(0.5)
        try:
            t = open_transport(kind, port, min(timeout, 2.0))
        except (LinkError, ImportError):
            continue
        w = Wallet(t)
        try:
            i = w.info()
        except LinkError:
            continue
        finally:
            w.close()
        print("device is back: %s" % describe_reset(i), file=sys.stderr)
        print("results it produced before the reset are lost: send the file again",
              file=sys.stderr)
        return i
    print("the device did not come back within %d s" % wait, file=sys.stderr)
    return None


if __name__ == "__main__":
    sys.exit(main())
