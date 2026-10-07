// link_sim - a stand-in for the device on the host, for testing mwlink.py.
//
// It runs the REAL link core (src/transfer/link.c) and the real file
// classifier (src/monero/file_formats.c) behind stdin/stdout, framed like the
// USB serial port (COBS + 0x00). Instead of a user confirming on a screen it
// answers immediately:
//
//     outputs file   -> a "Monero key image export" result
//     unsigned set   -> a "Monero signed tx set" result
//     REQ address    -> wallet export JSON (no view key)
//     REQ viewonly   -> wallet export JSON with a (fake) view key
//
// The results are placeholders with the right magic, not real key images:
// the point is the protocol and the frontend's file handling. The real
// processing is covered by test/test_feather_flow.c.
//
// Build (from the repository root, one command line):
//   gcc -std=c11 -O2 -DMW_HOST_BUILD=1 -IMoneroColdWallet/src tools/mwlink/link_sim.c
//       MoneroColdWallet/src/transfer/link.c MoneroColdWallet/src/monero/*.c
//       MoneroColdWallet/src/crypto/*.c MoneroColdWallet/src/hal/hal_host.c
//       MoneroColdWallet/src/hal/log.c MoneroColdWallet/src/data/*.c -o link_sim
//
// Options:
//   --locked         start in the locked state (PUT is refused)
//   --confirm-ms N   keep the device BUSY for N ms after a file arrives, like a
//                    user reviewing it (the delay runs out on the next message)
//   --decline N      the user declines the first N files: no result, the
//                    device goes back to the wallet
//   --crash          INFO reports a panic reset during signing (CLSAG)
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "transfer/link.h"
#include "monero/file_formats.h"
#include "hal/hal.h"
#include "hal/log.h"

#if defined(_WIN32)
#include <fcntl.h>
#include <io.h>
#endif

static uint8_t g_rx[MW_LINK_MAX_MSG + MW_LINK_MAX_MSG / 254 + 16];
static uint8_t g_rsp[MW_LINK_MAX_MSG];
static uint8_t g_frame[MW_LINK_MAX_MSG + MW_LINK_MAX_MSG / 254 + 16];
static uint8_t g_file[MW_LINK_MAX_PAYLOAD];

static int      g_locked;
static int      g_crash;
static long     g_confirm_ms;
static long     g_decline;
static int      g_busy_kind = -1;            // file under "review"
static uint32_t g_busy_until;

#define WALLET_MASK ((uint8_t)((1u << MW_FILE_KIND_OUTPUTS) | (1u << MW_FILE_KIND_UNSIGNED_TX)))

static int classify(const uint8_t* data, size_t len, char* why, size_t cap) {
    switch (mw_file_detect(data, len)) {
    case MW_FMT_OUTPUTS:     return MW_FILE_KIND_OUTPUTS;
    case MW_FMT_UNSIGNED_TX: return MW_FILE_KIND_UNSIGNED_TX;
    default:
        snprintf(why, cap, "not a Monero outputs export or unsigned transaction file");
        return -1;
    }
}

static void send_frame(const uint8_t* msg, size_t n) {
    size_t f = mw_link_serial_frame(msg, n, g_frame, sizeof g_frame);
    fwrite(g_frame, 1, f, stdout);
    fflush(stdout);
}

static void emit_log(const char* text) {
    size_t n = 0;
    if (mw_link_msg_build(MW_LINK_EVT_LOG, MW_LOG_INFO, (const uint8_t*)text,
                          (uint32_t)strlen(text), g_rsp, sizeof g_rsp, &n) == MW_OK)
        send_frame(g_rsp, n);
}

static void produce(int kind) {
    if (g_decline > 0) {
        g_decline--;
        emit_log("[file] declined by the user (simulated)");
        return;
    }
    if (kind == MW_FILE_KIND_OUTPUTS) {
        static const char r[] = "Monero key image export\003-simulated-";
        mw_link_outbox_put(MW_FILE_KIND_KEYIMAGES, (const uint8_t*)r, sizeof r - 1);
        emit_log("[file] key images ready for the PC (simulated)");
    } else if (kind == MW_FILE_KIND_UNSIGNED_TX) {
        static const char r[] = "Monero signed tx set\005-simulated-";
        mw_link_outbox_put(MW_FILE_KIND_SIGNED_TX, (const uint8_t*)r, sizeof r - 1);
        emit_log("[file] signed transaction set ready for the PC (simulated)");
    }
}

// What the device would do after the user confirmed.
static void process(void) {
    size_t len = 0;
    if (g_busy_kind >= 0) {
        if ((int32_t)(mw_millis() - g_busy_until) < 0) return;
        const int kind = g_busy_kind;
        g_busy_kind = -1;
        produce(kind);
        mw_link_set_state(MW_LINK_STATE_WALLET, WALLET_MASK);
    } else {
        int kind = mw_link_inbox_any(&len);
        if (kind >= 0 && mw_link_inbox_take((mw_file_kind_id_t)kind, g_file, sizeof g_file, &len) == MW_OK) {
            if (g_confirm_ms > 0) {
                g_busy_kind = kind;
                g_busy_until = mw_millis() + (uint32_t)g_confirm_ms;
                mw_link_set_state(MW_LINK_STATE_BUSY, 0);
                emit_log("[file] waiting for the user (simulated)");
            } else {
                produce(kind);
            }
        }
    }
    uint8_t req = mw_link_request_take();
    if (req) {
        char json[256];
        int n = snprintf(json, sizeof json,
                         "{\n  \"version\": 1,\n  \"wallet\": \"sim\",\n  \"network\": \"stagenet\",\n"
                         "  \"address\": \"5Asim\",\n  \"restore_height\": 1%s\n}\n",
                         req == MW_LINK_REQ_VIEWONLY
                             ? ",\n  \"view_key\": \"00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff\""
                             : "");
        mw_link_outbox_put(MW_FILE_KIND_WALLET_EXPORT, (const uint8_t*)json, (size_t)n);
        emit_log("[req] wallet data sent to the PC (simulated)");
    }
}

static void info(mw_link_info_t* out, void* ctx) {
    (void)ctx;
    snprintf(out->fw_version, sizeof out->fw_version, "sim");
    snprintf(out->board, sizeof out->board, "host");
    out->unlocked = g_locked ? 0 : 1;
    out->reset_reason = g_crash ? MW_RESET_PANIC : MW_RESET_POWERON;
    if (g_locked) return;                   // the locked device is "just a game"
    snprintf(out->wallet_name, sizeof out->wallet_name, "sim");
    out->wallet_count = 1;
    out->network = 2;
    if (g_crash) {
        out->crash_op = MW_CRUMB_OP_SIGN;
        out->crash_stage = MW_CRUMB_STAGE_CLSAG;
        out->crash_flags = MW_LINK_CRASH_VALID | MW_LINK_CRASH_STACK;
        out->crash_stack_free = 480;
    }
}

int main(int argc, char** argv) {
#if defined(_WIN32)
    _setmode(_fileno(stdin), _O_BINARY);
    _setmode(_fileno(stdout), _O_BINARY);
#endif
    for (int i = 1; i < argc; ++i) {
        if (strcmp(argv[i], "--locked") == 0) g_locked = 1;
        else if (strcmp(argv[i], "--crash") == 0) g_crash = 1;
        else if (strcmp(argv[i], "--confirm-ms") == 0 && i + 1 < argc) g_confirm_ms = atol(argv[++i]);
        else if (strcmp(argv[i], "--decline") == 0 && i + 1 < argc) g_decline = atol(argv[++i]);
        else {
            fprintf(stderr, "link_sim: unknown option %s\n", argv[i]);
            return 2;
        }
    }
    mw_link_init();
    mw_link_set_up(true, MW_LINK_CAP_SERIAL);
    mw_link_set_classifier(classify);
    mw_link_set_info_provider(info, NULL);
    mw_link_set_state(g_locked ? MW_LINK_STATE_LOCKED : MW_LINK_STATE_WALLET,
                      g_locked ? 0 : WALLET_MASK);

    mw_link_rx_t rx;
    mw_link_rx_init(&rx, MW_LINK_TRANSPORT_SERIAL, g_rx, sizeof g_rx);
    uint8_t chunk[1];
    for (;;) {
        size_t got = fread(chunk, 1, 1, stdin);        // byte-wise: no deadlock on pipes
        if (got == 0) break;
        size_t used = 0;
        if (mw_link_rx_feed(&rx, chunk, got, &used)) {
            // Let a finished review produce its result before STATUS answers.
            process();
            size_t n = mw_link_handle(rx.buf, rx.len, g_rsp, sizeof g_rsp);
            mw_link_rx_reset(&rx);
            if (n) send_frame(g_rsp, n);
            process();
        }
    }
    return 0;
}
