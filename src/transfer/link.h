// ============================================================================
// USB link protocol (TZ 2.0, stage 1): the same request/response protocol over
// two transports - CDC-ACM serial (COBS + CRC32, TZ 3.3 "Serial") and a
// vendor-specific HID interface with 64-byte reports (TZ 3.3 "HID", Trezor
// style). The host side is a plain file courier: it pushes outputs.bin /
// unsigned_tx_set.bin into the device INBOX and pulls keyimages.bin /
// signed_tx_set.bin out of the device OUTBOX. Every transformation happens on
// the device; nothing here ever sees a seed or a key (TZ 1.2, 3.8).
//
// This file and link.c are platform independent and compiled into the host
// test runner. The transports themselves live in usb_link_arduino.cpp.
//
// ---------------------------------------------------------------------------
// Message (identical on both transports)
//
//     offset  size  field                                   (protocol 3)
//     0       8     magic   4D 57 50 4B C7 3A 5E 91   ("MWPK" + 4 random)
//     8       1     version MW_LINK_PROTO_VERSION
//     9       1     cmd            (MW_LINK_CMD_* / MW_LINK_RSP_*)
//     10      1     arg            (file kind, error code, ...)
//     11      1     reserved (0)
//     12      4     len            payload length, little-endian
//     16      4     hdr_crc32      IEEE, little-endian, over bytes [0, 16)
//     20      len   payload
//     20+len  4     crc32          IEEE, little-endian, over bytes [0, 20+len)
//
// Why protocol 3: version 2 started a frame on a 2-byte magic "MW" (5 bytes
// with the HID "?##"), and the header had no checksum of its own, so a
// continuation report or serial garbage that happened to look like a start
// could only be rejected after the whole (up to 256 KiB) payload had been
// waited for. Now a frame start needs all 8 magic bytes AND a valid header
// CRC, both of which are inside the first HID report (60 data bytes), so a
// false start is rejected immediately; the chance of one is about 2^-96.
//
// Serial framing:   COBS(message) followed by a single 0x00 delimiter. A 0x00
//                   byte never appears inside an encoded frame, so it also
//                   resynchronises a receiver that lost track.
// HID framing:      reports of MW_LINK_HID_DATA bytes (the report ID byte is
//                   handled by the driver and is NOT part of these bytes):
//                   first report  "?##" + 60 bytes of message,
//                   continuation  "?"   + 62 bytes of message,
//                   the last one zero-padded. This is exactly the Trezor v1
//                   wire format, so existing host tooling patterns apply.
//                   Receivers start a frame only on "?##" + the 8-byte
//                   magic + a header whose hdr_crc32 matches, so a
//                   continuation whose data happens to start with "##" is
//                   not taken for a new frame.
//
// Commands (host -> device) and their responses (device -> host):
//
//     PING   0x01  payload echoed            -> PONG   0x81
//     INFO   0x02  -                         -> INFO   0x82  info wire (128 B)
//     PUT    0x03  arg=kind or 0xFE (auto),  -> ACK    0x83  arg=detected kind
//                  payload=file
//     GET    0x04  arg=kind                  -> FILE   0x84  arg=kind, payload
//     STATUS 0x05  -                         -> STATUS 0x85  status wire (48 B)
//     CLEAR  0x06  arg=kind or 0xFF (all)    -> ACK    0x83
//     REQ    0x07  arg=MW_LINK_REQ_*         -> ACK    0x83  (the user confirms
//                                               on the device; the answer
//                                               appears in the WALLET_EXPORT
//                                               outbox slot)
//     any error                              -> ERROR  0xFF  arg=code, text
//
// Version 2 (task 3):
//   * PUT with arg 0xFE lets the device classify the file by its magic
//     ("Monero output export", "Monero unsigned tx set", ...), whatever its
//     name or extension on the PC. Only the kinds the device currently
//     accepts are taken (outputs / unsigned tx while a wallet is open);
//     anything else is refused with a reason.
//   * The device reports its state (locked / menu / wallet open / busy) in
//     STATUS and INFO, and pushes LOG events with what it is doing.
//
// SPDX-License-Identifier: MIT
// ============================================================================
#ifndef MW_LINK_H
#define MW_LINK_H

#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>

#include "transfer.h"

#ifdef __cplusplus
extern "C" {
#endif

// ---------------------------------------------------------------------------
// Wire constants
// ---------------------------------------------------------------------------
#define MW_LINK_PROTO_VERSION   3

#define MW_LINK_MAGIC_LEN       8
#define MW_LINK_MAGIC_BYTES     { 0x4D, 0x57, 0x50, 0x4B, 0xC7, 0x3A, 0x5E, 0x91 }
#define MW_LINK_HDR_LEN         20        // magic..len (16) + hdr_crc32 (4)
#define MW_LINK_HDR_CRC_OFF     16
#define MW_LINK_CRC_LEN         4

extern const uint8_t mw_link_magic[MW_LINK_MAGIC_LEN];
#define MW_LINK_OVERHEAD        (MW_LINK_HDR_LEN + MW_LINK_CRC_LEN)

// The link carries exactly one exchange file (MW_TRANSFER_MAX_FILE).
#define MW_LINK_MAX_PAYLOAD     MW_TRANSFER_MAX_FILE
#define MW_LINK_MAX_MSG         (MW_LINK_OVERHEAD + MW_LINK_MAX_PAYLOAD)

// HID: 64 bytes on the wire = 1 report-ID byte + MW_LINK_HID_DATA data bytes.
// The ESP32-S3 is a full-speed device with a 64-byte HID endpoint buffer, so
// the report including its ID must not exceed one USB packet.
#define MW_LINK_HID_REPORT_ID   0x01
#define MW_LINK_HID_DATA        63
#define MW_LINK_HID_FIRST_HDR   3         // "?##"
#define MW_LINK_HID_CONT_HDR    1         // "?"
#define MW_LINK_HID_FIRST_DATA  (MW_LINK_HID_DATA - MW_LINK_HID_FIRST_HDR)   // 60
#define MW_LINK_HID_CONT_DATA   (MW_LINK_HID_DATA - MW_LINK_HID_CONT_HDR)    // 62

#define MW_LINK_FILE_KINDS      MW_FILE_KIND_COUNT   // mw_file_kind_id_t
#define MW_LINK_PING_MAX        256

enum {
    MW_LINK_CMD_PING    = 0x01,
    MW_LINK_CMD_INFO    = 0x02,
    MW_LINK_CMD_PUT     = 0x03,
    MW_LINK_CMD_GET     = 0x04,
    MW_LINK_CMD_STATUS  = 0x05,
    MW_LINK_CMD_CLEAR   = 0x06,
    MW_LINK_CMD_REQ     = 0x07,

    MW_LINK_RSP_PONG    = 0x81,
    MW_LINK_RSP_INFO    = 0x82,
    MW_LINK_RSP_ACK     = 0x83,
    MW_LINK_RSP_FILE    = 0x84,
    MW_LINK_RSP_STATUS  = 0x85,
    MW_LINK_RSP_ERROR   = 0xFF,

    // Unsolicited device -> host event (task2 item 3): one log line.
    // arg = mw_log_level_t (0 progress, 1 error, 2 info, 3 debug),
    // payload = the text, no trailing newline. The host program shows it in
    // its console and never answers it.
    MW_LINK_EVT_LOG     = 0x90
};

// ERROR.arg
enum {
    MW_LINK_ERR_BAD_CMD    = 1,   // unknown command byte
    MW_LINK_ERR_BAD_KIND   = 2,   // arg is not a file kind
    MW_LINK_ERR_TOO_BIG    = 3,   // payload above MW_LINK_MAX_PAYLOAD
    MW_LINK_ERR_NOT_READY  = 4,   // GET on an empty outbox
    MW_LINK_ERR_NO_MEMORY  = 5,
    MW_LINK_ERR_CRC        = 6,   // frame arrived, checksum wrong
    MW_LINK_ERR_BAD_LEN    = 7,   // frame length disagrees with the header
    MW_LINK_ERR_BAD_MAGIC  = 8,
    MW_LINK_ERR_BAD_FORMAT = 9,   // PUT auto: not a file the device handles
    MW_LINK_ERR_BUSY       = 10,  // the previous file is still being processed
    MW_LINK_ERR_LOCKED     = 11   // kind not accepted now (locked, menu, wrong kind)
};

// CLEAR.arg
#define MW_LINK_KIND_ALL        0xFF
// PUT.arg: let the device classify the file by its magic.
#define MW_LINK_KIND_AUTO       0xFE

// REQ.arg
#define MW_LINK_REQ_ADDRESS     1     // primary address (JSON)
#define MW_LINK_REQ_VIEWONLY    2     // address + private view key + height

// Device state (STATUS / INFO).
#define MW_LINK_STATE_LOCKED    0     // start-up game or password prompt
#define MW_LINK_STATE_MENU      1     // unlocked, no wallet open
#define MW_LINK_STATE_WALLET    2     // wallet open, files accepted
#define MW_LINK_STATE_BUSY      3     // processing a file / waiting for the user

// INFO.caps bits
#define MW_LINK_CAP_SERIAL      (1u << 0)
#define MW_LINK_CAP_HID         (1u << 1)
#define MW_LINK_CAP_MSC         (1u << 2)
#define MW_LINK_CAP_AUTO_KIND   (1u << 3)
#define MW_LINK_CAP_REQ         (1u << 4)

// INFO response payload, fixed layout (128 bytes):
//     0   u8   protocol version
//     1   u8   caps
//     2   u8   state (MW_LINK_STATE_*)
//     3   u8   network (0 mainnet, 1 testnet, 2 stagenet)
//     4   u32  max payload
//     8   u8   wallet_count
//     9   u8   unlocked
//     10  u8   passphrase variant of the open wallet (0 none, 1 with)
//     11  u8   file kinds
//     12  char fw_version[16]   NUL padded
//     28  char board[32]        NUL padded
//     60  char wallet_name[32]  NUL padded (open wallet, else empty)
//     92  u8   reset reason of this boot (MW_RESET_* in hal.h), always set
//     93  u8   last crash: operation (MW_CRUMB_OP_*)      //     94  u8   last crash: stage (MW_CRUMB_STAGE_*)        | only while
//     95  u8   last crash flags (MW_LINK_CRASH_*)          | unlocked,
//     96  u16  last crash: crypto stack min free, bytes   /  else 0
//     98  30   reserved (0)
#define MW_LINK_INFO_WIRE_LEN   128

// INFO byte 95
#define MW_LINK_CRASH_VALID     (1u << 0)   // bytes 93..94 describe the last crash
#define MW_LINK_CRASH_STACK     (1u << 1)   // bytes 96..97 hold a measured value

// STATUS response payload (48 bytes):
//     0   u32  inbox_len[5]
//     20  u32  outbox_len[5]
//     40  u8   state
//     41  u8   pending request (MW_LINK_REQ_* or 0)
//     42  u8   accepted kinds mask (bit = mw_file_kind_id_t)
//     43  u8   reserved
//     44  u32  event sequence number (bumped on every state change / output)
#define MW_LINK_STATUS_WIRE_LEN 48

typedef enum {
    MW_LINK_TRANSPORT_SERIAL = 0,
    MW_LINK_TRANSPORT_HID    = 1
} mw_link_transport_t;

// ---------------------------------------------------------------------------
// COBS (RFC-less, Cheshire & Baker). Encoded output never contains 0x00.
// ---------------------------------------------------------------------------
// Worst-case encoded size for `len` input bytes, without the delimiter.
size_t   mw_cobs_max_encoded(size_t len);
// Returns the encoded length, 0 when `cap` is too small.
size_t   mw_cobs_encode(const uint8_t* in, size_t len, uint8_t* out, size_t cap);
// `out` may alias `in` (in-place decoding is safe). MW_ERR_FORMAT on a
// malformed frame, MW_ERR_TOO_MANY when `cap` is too small.
mw_err_t mw_cobs_decode(const uint8_t* in, size_t len, uint8_t* out, size_t cap,
                        size_t* out_len);

// ---------------------------------------------------------------------------
// Messages
// ---------------------------------------------------------------------------
typedef struct {
    uint8_t        cmd;
    uint8_t        arg;
    uint32_t       len;
    const uint8_t* payload;      // points into the parsed buffer
} mw_link_msg_t;

size_t   mw_link_msg_size(uint32_t payload_len);        // MW_LINK_OVERHEAD + len

// Writes the header, copies `payload` and appends the CRC. `payload` may be
// NULL when `len` is 0.
mw_err_t mw_link_msg_build(uint8_t cmd, uint8_t arg, const uint8_t* payload,
                           uint32_t len, uint8_t* out, size_t cap, size_t* out_len);

// Two-step build for payloads produced in place (GET): begin() writes the
// header and returns the payload pointer, finish() appends the CRC.
uint8_t* mw_link_msg_begin(uint8_t cmd, uint8_t arg, uint32_t len,
                           uint8_t* out, size_t cap);
size_t   mw_link_msg_finish(uint8_t* out, uint32_t len);

// Validates magic, version, header CRC, length and CRC. Returns MW_OK, or
// MW_ERR_MAGIC (magic or version), MW_ERR_FORMAT (length mismatch),
// MW_ERR_CHECKSUM, MW_ERR_TOO_MANY.
mw_err_t mw_link_msg_parse(const uint8_t* buf, size_t len, mw_link_msg_t* out);

// Checks the first MW_LINK_HDR_LEN bytes of a message: magic, version and
// header CRC. On success stores the payload length (not yet bounded).
bool     mw_link_hdr_valid(const uint8_t* hdr, size_t avail, uint32_t* payload_len);

// ---------------------------------------------------------------------------
// Transport framing on the way OUT
// ---------------------------------------------------------------------------
// Serial: COBS(msg) + 0x00. Returns bytes written (including the delimiter),
// 0 when `cap` is too small.
size_t   mw_link_serial_frame(const uint8_t* msg, size_t len, uint8_t* out, size_t cap);

// HID: number of reports a message needs, and report number `index` of it.
// `out` receives exactly MW_LINK_HID_DATA bytes (zero padded).
size_t   mw_link_hid_report_count(size_t msg_len);
void     mw_link_hid_report(const uint8_t* msg, size_t len, size_t index,
                            uint8_t out[MW_LINK_HID_DATA]);

// ---------------------------------------------------------------------------
// Receiver state machine, one per transport
// ---------------------------------------------------------------------------
typedef struct {
    mw_link_transport_t transport;
    uint8_t*  buf;
    size_t    cap;
    size_t    len;           // bytes accumulated; once ready: decoded message length
    size_t    expect;        // HID: total message bytes announced by the header
    bool      in_frame;      // HID: a valid start report has been seen
    bool      overflow;      // serial: frame too long, discarding until 0x00
    bool      ready;         // buf[0..len) holds one complete raw message
    uint32_t  dropped;       // frames discarded for any reason (diagnostics)
} mw_link_rx_t;

void mw_link_rx_init(mw_link_rx_t* rx, mw_link_transport_t t, uint8_t* buf, size_t cap);
void mw_link_rx_reset(mw_link_rx_t* rx);

// Feeds transport bytes. For SERIAL any byte count; for HID exactly one
// report's data (MW_LINK_HID_DATA bytes, report ID already stripped). Returns
// true when a complete message is in rx->buf[0..rx->len); `consumed` tells how
// many input bytes were used, so a serial chunk holding two frames is fed
// twice. The caller handles the message and then calls mw_link_rx_reset().
bool mw_link_rx_feed(mw_link_rx_t* rx, const uint8_t* data, size_t n, size_t* consumed);

// ---------------------------------------------------------------------------
// Device-side state: inbox / outbox and the request dispatcher
// ---------------------------------------------------------------------------
typedef struct {
    char    fw_version[16];
    char    board[32];
    char    wallet_name[32];
    uint8_t wallet_count;
    uint8_t unlocked;
    uint8_t network;
    uint8_t pp_variant;
    // Diagnostics (INFO bytes 92..97). The core zeroes the crash fields
    // while `unlocked` is 0.
    uint8_t  reset_reason;
    uint8_t  crash_op;
    uint8_t  crash_stage;
    uint8_t  crash_flags;
    uint16_t crash_stack_free;
} mw_link_info_t;

typedef void (*mw_link_info_fn)(mw_link_info_t* out, void* ctx);

// Port hooks. All optional: without a lock the store is single-threaded (host
// tests); without an allocator malloc/free are used.
typedef struct {
    void  (*lock)(void* ctx);
    void  (*unlock)(void* ctx);
    void* (*alloc)(size_t n);
    void  (*free)(void* p, size_t n);
    void*   ctx;
} mw_link_port_t;

mw_err_t mw_link_init(void);                 // idempotent; clears both boxes
void     mw_link_deinit(void);               // frees everything
void     mw_link_set_port(const mw_link_port_t* port);
void     mw_link_set_info_provider(mw_link_info_fn fn, void* ctx);

// The transport driver reports whether a host-facing interface is enumerated.
void     mw_link_set_up(bool up, uint8_t caps);
bool     mw_link_is_up(void);
uint8_t  mw_link_caps(void);

// Handles one raw message (as left in mw_link_rx_t) and writes the complete
// response message into `out`. Always produces a response, an ERROR one for
// anything it could not parse or serve. Returns the response length, or 0
// only when `cap` cannot even hold an ERROR frame.
size_t   mw_link_handle(const uint8_t* msg, size_t msg_len, uint8_t* out, size_t cap);

// ---- firmware side --------------------------------------------------------
// Device state and the file kinds PUT currently accepts (bit per kind).
// Kinds outside the mask are refused with MW_LINK_ERR_LOCKED, except in
// MW_LINK_STATE_BUSY, where every PUT gets MW_LINK_ERR_BUSY.
void     mw_link_set_state(uint8_t state, uint8_t accept_mask);
uint8_t  mw_link_state(void);

// PUT auto: returns the mw_file_kind_id_t of a file, or -1 when the file is
// not something the device understands. Installed by the firmware
// (file_formats.h knows the magics; the link core stays independent of it).
typedef int  (*mw_link_classify_fn)(const uint8_t* data, size_t len,
                                    char* why, size_t why_cap);
void     mw_link_set_classifier(mw_link_classify_fn fn);

// Called on the LINK task after a file was stored or a request queued, so the
// firmware can wake the screen that waits for it. Must not block.
typedef void (*mw_link_event_fn)(void* ctx);
void     mw_link_set_event_hook(mw_link_event_fn fn, void* ctx);

// Pending host request (MW_LINK_REQ_*), 0 when none. take() clears it.
uint8_t  mw_link_request_peek(void);
uint8_t  mw_link_request_take(void);

// Bumps the STATUS event counter (the host polls it to notice new outputs).
void     mw_link_bump_seq(void);

// First inbox slot holding a file, or -1.
int      mw_link_inbox_any(size_t* len);

bool     mw_link_inbox_pending(mw_file_kind_id_t kind, size_t* len);
// Copies the file out and empties the slot.
mw_err_t mw_link_inbox_take(mw_file_kind_id_t kind, uint8_t* buf, size_t cap, size_t* len);
void     mw_link_inbox_clear(mw_file_kind_id_t kind);

// Stores a file for the host to GET. The slot keeps it until the host CLEARs
// it or the firmware puts another one, so a failed transfer can be retried.
mw_err_t mw_link_outbox_put(mw_file_kind_id_t kind, const uint8_t* buf, size_t len);
bool     mw_link_outbox_pending(mw_file_kind_id_t kind, size_t* len);
void     mw_link_outbox_clear(mw_file_kind_id_t kind);

// Blocking wait used by mw_transfer_receive(MW_CHANNEL_USB_LINK). Polls the
// inbox every MW_LINK_POLL_MS; the hook (if any) is called on every poll and
// may return false to abort (MW_ERR_ABORTED). `timeout_ms` = 0 waits forever;
// otherwise MW_ERR_IO once it expires.
typedef bool (*mw_link_wait_hook_t)(uint32_t elapsed_ms, void* ctx);
void     mw_link_set_wait_hook(mw_link_wait_hook_t hook, void* ctx);
mw_err_t mw_link_wait_inbox(mw_file_kind_id_t kind, uint8_t* buf, size_t cap,
                            size_t* len, uint32_t timeout_ms);
#define MW_LINK_POLL_MS 20

// ---- helpers shared with the host tool description --------------------------
const char* mw_link_cmd_name(uint8_t cmd);
const char* mw_link_err_name(uint8_t code);

#ifdef __cplusplus
}
#endif
#endif
