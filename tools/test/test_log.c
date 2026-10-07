// Unified log (task2 items 3 and 10): level filtering, the immediate sink,
// the ring the USB link drains, and the drop-oldest policy.
//
// SPDX-License-Identifier: MIT

#include "test_framework.h"
#include "hal/log.h"

#include <string.h>

static int  s_sink_calls;
static char s_sink_last[MW_LOG_LINE_MAX];
static int  s_sink_level;
static int  s_lock_depth, s_lock_max;

static void sink(mw_log_level_t level, const char* line, void* ctx) {
    (void)ctx;
    s_sink_calls++;
    s_sink_level = (int)level;
    snprintf(s_sink_last, sizeof s_sink_last, "%s", line);
}

static void lock_fn(void* ctx)   { (void)ctx; s_lock_depth++; if (s_lock_depth > s_lock_max) s_lock_max = s_lock_depth; }
static void unlock_fn(void* ctx) { (void)ctx; s_lock_depth--; }

static void drain(void) {
    char line[MW_LOG_LINE_MAX];
    mw_log_level_t lvl;
    while (mw_log_pop(&lvl, line, sizeof line)) { }
}

MW_TEST(test_levels_and_sink) {
    mw_log_init();
    mw_log_set_sink(sink, NULL);
    mw_log_set_lock(lock_fn, unlock_fn, NULL);
    mw_log_set_debug(false);
    drain();
    s_sink_calls = 0;

    MW_LOGP("parsing %d bytes", 42);
    CHECK_EQ_INT(s_sink_calls, 1);
    CHECK_EQ_STR(s_sink_last, "[op] parsing 42 bytes");
    CHECK_EQ_INT(s_sink_level, MW_LOG_PROGRESS);

    MW_LOGE("flow", "failed: %s", "checksum");
    CHECK_EQ_INT(s_sink_calls, 2);
    CHECK_EQ_STR(s_sink_last, "[flow] failed: checksum");

    // Debug off: info lines (what the device is doing) still go out, debug
    // lines vanish before formatting.
    MW_LOGI("ui", "shown");
    CHECK_EQ_INT(s_sink_calls, 3);
    MW_LOGD("ui", "hidden %p", (void*)0);
    CHECK_EQ_INT(s_sink_calls, 3);

    mw_log_set_debug(true);
    CHECK(mw_log_debug_enabled());
    MW_LOGD("page", "created p=%d", 7);
    CHECK_EQ_INT(s_sink_calls, 4);
    CHECK_EQ_STR(s_sink_last, "[page] created p=7");
    CHECK_EQ_INT(s_sink_level, MW_LOG_DEBUG);

    // The sink ran under the lock, exactly one level deep.
    CHECK_EQ_INT(s_lock_depth, 0);
    CHECK_EQ_INT(s_lock_max, 1);

    CHECK_EQ_INT(mw_log_level_char(MW_LOG_PROGRESS), 'P');
    CHECK_EQ_INT(mw_log_level_char(MW_LOG_ERROR), 'E');
    CHECK_EQ_INT(mw_log_level_char(MW_LOG_INFO), 'I');
    CHECK_EQ_INT(mw_log_level_char(MW_LOG_DEBUG), 'D');
}

MW_TEST(test_ring_order_and_overflow) {
    char line[MW_LOG_LINE_MAX];
    mw_log_level_t lvl;

    mw_log_init();
    mw_log_set_debug(true);
    drain();
    CHECK(!mw_log_pop(&lvl, line, sizeof line));

    MW_LOGP("one");
    MW_LOGE("t", "two");
    MW_LOGD("t", "three");
    CHECK(mw_log_pop(&lvl, line, sizeof line));
    CHECK_EQ_STR(line, "[op] one");
    CHECK_EQ_INT(lvl, MW_LOG_PROGRESS);
    CHECK(mw_log_pop(&lvl, line, sizeof line));
    CHECK_EQ_STR(line, "[t] two");
    CHECK_EQ_INT(lvl, MW_LOG_ERROR);
    CHECK(mw_log_pop(&lvl, line, sizeof line));
    CHECK_EQ_STR(line, "[t] three");
    CHECK(!mw_log_pop(&lvl, line, sizeof line));

    // Fill past the ring: the OLDEST lines go, the newest stay, and the
    // ring holds MW_LOG_RING - 1 entries (one slot separates head and tail).
    const uint32_t dropped_before = mw_log_dropped();
    for (int i = 0; i < MW_LOG_RING + 10; i++) MW_LOGP("line %d", i);
    CHECK_EQ_INT(mw_log_dropped() - dropped_before, 11);
    int n = 0, first = -1, last = -1;
    while (mw_log_pop(&lvl, line, sizeof line)) {
        int v = -1;
        CHECK_EQ_INT(sscanf(line, "[op] line %d", &v), 1);
        if (first < 0) first = v;
        last = v;
        n++;
    }
    CHECK_EQ_INT(n, MW_LOG_RING - 1);
    CHECK_EQ_INT(first, 11);
    CHECK_EQ_INT(last, MW_LOG_RING + 9);
}

MW_TEST(test_long_lines_are_truncated_not_overflowed) {
    char line[MW_LOG_LINE_MAX];
    char big[400];
    mw_log_level_t lvl;
    memset(big, 'x', sizeof big - 1);
    big[sizeof big - 1] = '\0';

    mw_log_init();
    drain();
    MW_LOGP("%s", big);
    CHECK(mw_log_pop(&lvl, line, sizeof line));
    CHECK_EQ_INT(strlen(line), MW_LOG_LINE_MAX - 1);
    CHECK(strncmp(line, "[op] xxxx", 9) == 0);

    // A short output buffer is respected too.
    MW_LOGP("abcdefghij");
    char small[6];
    CHECK(mw_log_pop(&lvl, small, sizeof small));
    CHECK_EQ_STR(small, "[op] ");
}

int main(void) {
    RUN_TEST(test_levels_and_sink);
    RUN_TEST(test_ring_order_and_overflow);
    RUN_TEST(test_long_lines_are_truncated_not_overflowed);
    return mw_test_summary();
}
