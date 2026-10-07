// ============================================================================
// Unified logging (task2 items 3 and 10).
//
// One API for every debug and progress line in the firmware, replacing the
// mix of printf() and Serial0.printf() that used to be scattered over the UI,
// the HAL and the sketch. Two destinations:
//
//   * an immediate sink (UART0 on the device, nothing on the host), installed
//     by the platform with mw_log_set_sink();
//   * a small ring buffer that the USB link task drains and forwards to the
//     host program as LOG events (link.h, MW_LINK_EVT_LOG), where the frontend
//     shows them in its console. The link frames them like any other message,
//     so a debug line can never corrupt the exchange protocol on the same
//     serial port.
//
// Levels:
//   MW_LOG_PROGRESS  what the device is doing right now ("parsing file",
//                    "signing CLSAG", "building Bulletproof+"). Always sent.
//   MW_LOG_ERROR     an operation failed. Always sent.
//   MW_LOG_INFO      what happens with the device (wallet opened, file
//                    received, screen changed). Always sent (task 3: "в
//                    обычном режиме базовые сообщения").
//   MW_LOG_DEBUG     extended messages: parser details, internal tracing.
//                    Only in the debug mode (Settings > Debug log).
//
// RULE: nothing that goes through this API may carry a secret. No seed
// words, no keys, no passphrases, no device password, no plaintext of a
// sealed record - not even at MW_LOG_DEBUG. Pointers, sizes, indices, error
// codes and public identifiers are fine.
//
// SPDX-License-Identifier: MIT
// ============================================================================
#ifndef MW_LOG_H
#define MW_LOG_H

#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef enum {
    MW_LOG_PROGRESS = 0,
    MW_LOG_ERROR    = 1,
    MW_LOG_INFO     = 2,
    MW_LOG_DEBUG    = 3
} mw_log_level_t;

#define MW_LOG_LINE_MAX 160
#define MW_LOG_RING     48

// Immediate sink: gets every emitted line (already filtered), without the
// trailing newline.
typedef void (*mw_log_sink_fn)(mw_log_level_t level, const char* line, void* ctx);
// Lock hooks for multi-task builds (FreeRTOS); the host leaves them NULL.
typedef void (*mw_log_lock_fn)(void* ctx);

void mw_log_init(void);
void mw_log_set_sink(mw_log_sink_fn sink, void* ctx);
void mw_log_set_lock(mw_log_lock_fn lock, mw_log_lock_fn unlock, void* ctx);
void mw_log_set_debug(bool on);
bool mw_log_debug_enabled(void);

// Formats and emits one line: "[tag] text".
void mw_log_write(mw_log_level_t level, const char* tag, const char* fmt, ...)
#if defined(__GNUC__)
    __attribute__((format(printf, 3, 4)))
#endif
    ;

// Ring consumer (the USB link task). Returns false when the ring is empty.
bool     mw_log_pop(mw_log_level_t* level, char* out, size_t cap);
uint32_t mw_log_dropped(void);

// One-character level marker used by the UART sink and the host console.
char mw_log_level_char(mw_log_level_t level);

#define MW_LOGP(...)      mw_log_write(MW_LOG_PROGRESS, "op",  __VA_ARGS__)
#define MW_LOGE(tag, ...) mw_log_write(MW_LOG_ERROR,    (tag), __VA_ARGS__)
#define MW_LOGI(tag, ...) mw_log_write(MW_LOG_INFO,     (tag), __VA_ARGS__)
#define MW_LOGD(tag, ...) mw_log_write(MW_LOG_DEBUG,    (tag), __VA_ARGS__)

#ifdef __cplusplus
}
#endif
#endif
