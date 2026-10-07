// Unified logging core - see log.h. Platform independent; the device installs
// a UART sink and FreeRTOS lock hooks from hal_esp32.cpp.
//
// SPDX-License-Identifier: MIT
#include "log.h"

#include <stdarg.h>
#include <stdio.h>
#include <string.h>

static struct {
    bool            inited;
    bool            debug;
    mw_log_sink_fn  sink;
    void*           sink_ctx;
    mw_log_lock_fn  lock;
    mw_log_lock_fn  unlock;
    void*           lock_ctx;

    char            ring[MW_LOG_RING][MW_LOG_LINE_MAX];
    uint8_t         level[MW_LOG_RING];
    uint8_t         head;       // next slot to write
    uint8_t         tail;       // next slot to read
    uint32_t        dropped;
} g;

static void lock_(void)   { if (g.lock)   g.lock(g.lock_ctx); }
static void unlock_(void) { if (g.unlock) g.unlock(g.lock_ctx); }

void mw_log_init(void) {
    if (g.inited) return;
    memset(&g, 0, sizeof(g));
    g.inited = true;
}

void mw_log_set_sink(mw_log_sink_fn sink, void* ctx) {
    g.sink = sink;
    g.sink_ctx = ctx;
}

void mw_log_set_lock(mw_log_lock_fn lock, mw_log_lock_fn unlock, void* ctx) {
    g.lock = lock;
    g.unlock = unlock;
    g.lock_ctx = ctx;
}

void mw_log_set_debug(bool on)  { g.debug = on; }
bool mw_log_debug_enabled(void) { return g.debug; }

char mw_log_level_char(mw_log_level_t level) {
    switch (level) {
        case MW_LOG_PROGRESS: return 'P';
        case MW_LOG_ERROR:    return 'E';
        case MW_LOG_INFO:     return 'I';
        case MW_LOG_DEBUG:    return 'D';
        default:              return '?';
    }
}

void mw_log_write(mw_log_level_t level, const char* tag, const char* fmt, ...) {
    if (!g.inited) mw_log_init();
    // Filtering happens before any formatting, so a disabled debug line costs
    // one branch and no stack.
    // task 3: PROGRESS, ERROR and INFO describe what the device is doing and
    // always reach the host; DEBUG is the extended stream of the debug mode.
    if (level == MW_LOG_DEBUG && !g.debug) return;
    if (!fmt) return;

    char line[MW_LOG_LINE_MAX];
    int  n = snprintf(line, sizeof(line), "[%s] ", tag ? tag : "-");
    if (n < 0) return;
    if ((size_t)n >= sizeof(line)) n = (int)sizeof(line) - 1;

    va_list ap;
    va_start(ap, fmt);
    int m = vsnprintf(line + n, sizeof(line) - (size_t)n, fmt, ap);
    va_end(ap);
    if (m < 0) line[n] = '\0';

    lock_();
    if (g.sink) g.sink(level, line, g.sink_ctx);

    uint8_t next = (uint8_t)((g.head + 1) % MW_LOG_RING);
    if (next == g.tail) {
        // Full: drop the OLDEST line, so the console shows what is happening
        // now rather than what happened when the host stopped reading.
        g.tail = (uint8_t)((g.tail + 1) % MW_LOG_RING);
        g.dropped++;
    }
    snprintf(g.ring[g.head], MW_LOG_LINE_MAX, "%s", line);
    g.level[g.head] = (uint8_t)level;
    g.head = next;
    unlock_();
}

bool mw_log_pop(mw_log_level_t* level, char* out, size_t cap) {
    if (!out || cap == 0) return false;
    bool got = false;
    lock_();
    if (g.tail != g.head) {
        snprintf(out, cap, "%s", g.ring[g.tail]);
        if (level) *level = (mw_log_level_t)g.level[g.tail];
        g.tail = (uint8_t)((g.tail + 1) % MW_LOG_RING);
        got = true;
    }
    unlock_();
    return got;
}

uint32_t mw_log_dropped(void) { return g.dropped; }
