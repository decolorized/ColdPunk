// ===========================================================================
//  LVGL port: display + input drivers, tick source, task split and the
//  cross-task call plumbing.
//
//  ------------------------------------------------------------------------
//  LOCKING RULE - read this before touching anything in src/ui
//  ------------------------------------------------------------------------
//  There are exactly two tasks that matter (TZ 4.1):
//
//    * the LVGL task, pinned to core 0, which calls mw_ui_tick() in a loop.
//      It is the ONLY task that may call an lv_* function or dereference an
//      lv_obj_t. Every screen builder (mw_screen_*_build, every lv_event_cb_t,
//      every lv_timer_cb_t) runs here.
//
//    * the crypto task, pinned to core 1, which runs mw_shell_run() (flows.cpp)
//      and therefore every flow of the device. It owns the secrets and must NEVER
//      touch an LVGL object - not even to read one.
//
//  The crypto task talks to the UI through four primitives implemented below:
//
//      mw_ui_async_call(fn, arg)   post a job, return immediately
//      mw_ui_sync_call(fn, arg)    post a job, return when it has run
//      mw_ui_modal_call(fn, arg)   post a job, block until some LVGL callback
//                                  calls mw_ui_modal_done(result)
//      mw_ui_modal_done(result)    called ON THE LVGL TASK to release the
//                                  blocked crypto task
//
//  mw_ui_confirm(), mw_ui_message(), mw_ui_progress(), mw_kb_run() and every
//  mw_screen_*_run() are built on top of those, which is why they are safe to
//  call from the crypto task and are the only UI entry points a flow may use.
//
//  A job runs on the LVGL task while the recursive LVGL lock is held, so a job
//  may freely create, mutate and delete objects. Nothing else may.
//
//  Consequence: do NOT call a modal helper from the LVGL task once that task
//  is running - it would need a nested lv_timer_handler(), which LVGL refuses
//  to re-enter. The only legal nested use is during boot, before the LVGL task
//  has been created (the firmware's fatal() path relies on exactly that).
// ===========================================================================

#include "theme.h"
#include "screen_common.h"
#include "ui.h"
#include "i18n.h"
#include "../hal/log.h"

#include "../hal/hal.h"
#include "../hal/touch_map.h"
#include "../config/app_config.h"
#include "../wallet/secure_storage.h"
#include "../wallet/session.h"

#include <string.h>
#include <stdint.h>
#include <stdio.h>   // debug printf

// ---------------------------------------------------------------------------
// Platform glue. Everything FreeRTOS-specific is confined to this file.
// ---------------------------------------------------------------------------
#if defined(__has_include)
#  if __has_include(<freertos/FreeRTOS.h>)
#    define MW_HAS_FREERTOS 1
#  endif
#  if __has_include("board_config.h")
#    include "board_config.h"
#  endif
#  if __has_include(<esp_heap_caps.h>)
#    define MW_HAS_ESP_HEAP 1
#  endif
#endif

#ifndef MW_HAS_FREERTOS
#  if defined(ESP_PLATFORM) || defined(ARDUINO)
#    define MW_HAS_FREERTOS 1
#  else
#    define MW_HAS_FREERTOS 0
#  endif
#endif
#ifndef MW_HAS_ESP_HEAP
#  define MW_HAS_ESP_HEAP 0
#endif

#if MW_HAS_FREERTOS
#  include <freertos/FreeRTOS.h>
#  include <freertos/task.h>
#  include <freertos/queue.h>
#  include <freertos/semphr.h>
#endif
#if MW_HAS_ESP_HEAP
#  include <esp_heap_caps.h>
#endif

#if LV_COLOR_DEPTH != 16
#warning "The HAL blit takes uint16_t pixels; build LVGL with LV_COLOR_DEPTH 16. \
Monochrome panels are dithered down inside mw_display_blit()."
#endif

// ---------------------------------------------------------------------------
// Draw buffer (TZ 4.1 / memory budget): 1/10 of the panel, PSRAM first.
// ---------------------------------------------------------------------------
#if defined(DISPLAY_WIDTH) && defined(DISPLAY_HEIGHT)
#  define MW_PANEL_PX ((uint32_t)DISPLAY_WIDTH * (uint32_t)DISPLAY_HEIGHT)
#else
#  define MW_PANEL_PX (240u * 320u)
#endif
#ifndef MW_DRAW_BUF_PX
#  define MW_DRAW_BUF_PX (MW_PANEL_PX / 10u)
#endif

static uint16_t  s_static_buf[MW_DRAW_BUF_PX];
static uint16_t* s_draw_px  = s_static_buf;   // buffer actually handed to LVGL
static uint32_t  s_draw_len = MW_DRAW_BUF_PX; // in pixels

// ---------------------------------------------------------------------------
// State
// ---------------------------------------------------------------------------
static mw_lv_disp_t*  s_disp        = NULL;
static lv_indev_t*    s_indev_touch = NULL;
static lv_indev_t*    s_indev_keys  = NULL;
static bool           s_inited      = false;
static mw_screen_id_t s_current     = MW_SCREEN_BOOT;

#if LVGL_VERSION_MAJOR < 9
static lv_disp_draw_buf_t s_lv_draw_buf;
static lv_disp_drv_t      s_lv_disp_drv;
static lv_indev_drv_t     s_lv_touch_drv;
static lv_indev_drv_t     s_lv_keys_drv;
static uint32_t           s_last_tick_ms = 0;
#endif

// status bar values, published by mw_ui_set_status()
static volatile int  s_batt      = -1;
static volatile bool s_sd        = false;
static volatile bool s_usb       = false;
static volatile bool s_status_dirty = true;

// ---------------------------------------------------------------------------
// RTOS primitives
// ---------------------------------------------------------------------------
enum { JOB_ASYNC = 0, JOB_SYNC = 1, JOB_MODAL = 2 };

typedef struct {
    mw_ui_job_fn fn;
    void*        arg;
    uint8_t      kind;
} ui_job_t;

#define MW_JOB_QUEUE_LEN 12
#define MW_MODAL_DEPTH    4

typedef struct {
    volatile bool    done;
    volatile int32_t result;
    bool             local;   // completed by a nested pump, not by a semaphore
} modal_frame_t;

static modal_frame_t s_frames[MW_MODAL_DEPTH];
static volatile int  s_frame_top = -1;

#if MW_HAS_FREERTOS
static QueueHandle_t     s_job_q       = NULL;
static SemaphoreHandle_t s_sync_sem    = NULL;
static SemaphoreHandle_t s_modal_sem   = NULL;
static SemaphoreHandle_t s_sync_mutex  = NULL;
static SemaphoreHandle_t s_modal_mutex = NULL;
static SemaphoreHandle_t s_lv_mutex    = NULL;   // recursive
static TaskHandle_t      s_ui_task     = NULL;
#else
static bool s_ui_task = false;
#endif

// ---------------------------------------------------------------------------
// Locking
// ---------------------------------------------------------------------------
void mw_ui_lock(void) {
#if MW_HAS_FREERTOS
    if (s_lv_mutex) xSemaphoreTakeRecursive(s_lv_mutex, portMAX_DELAY);
#endif
}

void mw_ui_unlock(void) {
#if MW_HAS_FREERTOS
    if (s_lv_mutex) xSemaphoreGiveRecursive(s_lv_mutex);
#endif
}

bool mw_ui_is_ui_task(void) {
#if MW_HAS_FREERTOS
    return s_ui_task != NULL && xTaskGetCurrentTaskHandle() == s_ui_task;
#else
    return true;
#endif
}

static bool ui_task_running(void) {
#if MW_HAS_FREERTOS
    return s_ui_task != NULL;
#else
    return false;
#endif
}

// Autolock state (see mw_ui_autolock_tick below). Declared here because
// mw_ui_modal_call() consults it.
static volatile bool s_autolock_armed = false;
static volatile bool s_lock_requested = false;

// The LVGL task registers itself explicitly (mw_ui_task_register). It used to
// be "whoever ticks first": when the crypto task opened its first dialog
// before the LVGL task had ticked, the crypto task ran the modal locally,
// ticked LVGL itself and was adopted as the UI task for the rest of the run
// (task 3 item 0).
static volatile bool s_ui_expected = false;

void mw_ui_task_expect(void) { s_ui_expected = true; }

void mw_ui_task_register(void) {
#if MW_HAS_FREERTOS
    s_ui_task = xTaskGetCurrentTaskHandle();
#endif
}

// A task other than the UI task that needs LVGL while the UI task is about to
// start waits for it instead of driving LVGL itself.
static void wait_for_ui_task(void) {
    if (!s_ui_expected || mw_ui_is_ui_task()) return;
    while (!ui_task_running()) mw_delay_ms(5);
}

// ---------------------------------------------------------------------------
// Display driver
// ---------------------------------------------------------------------------
#if LVGL_VERSION_MAJOR >= 9
static void mw_flush_cb(lv_display_t* disp, const lv_area_t* area, uint8_t* px_map) {
    const int16_t w = (int16_t)(area->x2 - area->x1 + 1);
    const int16_t h = (int16_t)(area->y2 - area->y1 + 1);
    mw_display_blit((int16_t)area->x1, (int16_t)area->y1, w, h,
                    (const uint16_t*)px_map);
    mw_display_wait_dma();
    lv_display_flush_ready(disp);
}
#else
static void mw_flush_cb(lv_disp_drv_t* drv, const lv_area_t* area, lv_color_t* colors) {
    const int16_t w = (int16_t)(area->x2 - area->x1 + 1);
    const int16_t h = (int16_t)(area->y2 - area->y1 + 1);
    mw_display_blit((int16_t)area->x1, (int16_t)area->y1, w, h,
                    (const uint16_t*)colors);
    mw_display_wait_dma();
    lv_disp_flush_ready(drv);
}
#endif

static void alloc_draw_buffer(const mw_hal_caps_t* caps) {
    uint32_t want = ((uint32_t)caps->width * (uint32_t)caps->height) / 10u;
    if (want < (uint32_t)caps->width) want = caps->width;     // at least one row
    // Keep whole rows so the flush areas stay rectangular and cheap.
    want = (want / caps->width) * caps->width;
    if (want == 0) want = caps->width;

#if MW_HAS_ESP_HEAP
    if (caps->has_psram) {
        void* p = heap_caps_malloc(want * sizeof(uint16_t),
                                   MALLOC_CAP_SPIRAM | MALLOC_CAP_8BIT);
        if (p) {
            s_draw_px  = (uint16_t*)p;
            s_draw_len = want;
            MW_LOGD("ui", "draw buffer: PSRAM %lu px", (unsigned long)want);
            return;
        }
    }
#endif
    // Static fallback. It is sized from board_config.h at compile time, so a
    // panel larger than the configured one simply gets a shorter partial
    // buffer - LVGL renders in more, smaller chunks.
    s_draw_px  = s_static_buf;
    s_draw_len = (want < MW_DRAW_BUF_PX) ? want : MW_DRAW_BUF_PX;
    if (s_draw_len < caps->width) s_draw_len = MW_DRAW_BUF_PX;
    MW_LOGD("ui", "draw buffer: static %lu px", (unsigned long)s_draw_len);
}

// ---------------------------------------------------------------------------
// Touch diagnostics (touch_map.h). The driver reports every read here; the
// Settings touch-test page reads the last sample back. Only the UI task
// reads the panel, so plain statics are enough.
// ---------------------------------------------------------------------------
static mw_touch_debug_t s_tdbg;
static volatile bool    s_ttrace = false;
static bool             s_tneeds_cal = false;

extern "C" void mw_touch_debug_note(int32_t raw_x, int32_t raw_y,
                                    uint16_t x, uint16_t y, bool pressed) {
    const bool edge = !s_tdbg.valid || s_tdbg.pressed != pressed;
    s_tdbg.raw_x   = raw_x;
    s_tdbg.raw_y   = raw_y;
    s_tdbg.x       = x;
    s_tdbg.y       = y;
    s_tdbg.pressed = pressed;
    s_tdbg.valid   = true;
    // Coordinates are keystrokes on keyboard/PIN pages: logged only while
    // the touch-test page has the trace on, and only on press/release.
    if (edge && s_ttrace && mw_log_debug_enabled()) {
        MW_LOGD("touch", "%s raw %d,%d -> %u,%u", pressed ? "press" : "release",
                (int)raw_x, (int)raw_y, (unsigned)x, (unsigned)y);
    }
}

extern "C" bool mw_touch_debug_last(mw_touch_debug_t* out) {
    if (!out) return false;
    *out = s_tdbg;
    return s_tdbg.valid;
}

extern "C" void mw_touch_trace(bool on)              { s_ttrace = on; }
extern "C" bool mw_touch_trace_enabled(void)         { return s_ttrace; }
extern "C" void mw_touch_set_needs_calibration(bool on) { s_tneeds_cal = on; }
extern "C" bool mw_touch_needs_calibration(void)     { return s_tneeds_cal; }

// ---------------------------------------------------------------------------
// Input: touch
// ---------------------------------------------------------------------------
static lv_coord_t s_last_x = 0, s_last_y = 0;

#if LVGL_VERSION_MAJOR >= 9
static void mw_touch_cb(lv_indev_t* indev, lv_indev_data_t* data)
#else
static void mw_touch_cb(lv_indev_drv_t* indev, lv_indev_data_t* data)
#endif
{
    MW_UNUSED(indev);
    mw_touch_state_t t;
    if (mw_touch_read(&t) && t.pressed) {
        s_last_x = (lv_coord_t)t.x;
        s_last_y = (lv_coord_t)t.y;
        data->state = LV_INDEV_STATE_PRESSED;
    } else {
        data->state = LV_INDEV_STATE_RELEASED;
    }
    data->point.x = s_last_x;
    data->point.y = s_last_y;
}

// ---------------------------------------------------------------------------
// Input: buttons / encoder
//
// Two consumers: the lv_group keypad indev (default) and a raw hook installed
// by the keyboards, which need 2-D navigation and the TZ 5.6 long-press
// timings that LVGL's keypad model does not express.
// ---------------------------------------------------------------------------
typedef struct { uint32_t key; uint8_t state; } key_evt_t;

#define MW_KEY_FIFO 16
static key_evt_t s_key_fifo[MW_KEY_FIFO];
static uint8_t   s_key_head = 0, s_key_tail = 0;

static mw_ui_btn_hook_t s_btn_hook      = NULL;
static void*            s_btn_hook_user = NULL;

static uint32_t s_btn_down_ms[MW_BTN_BACK + 1];
static uint32_t s_btn_prev_mask = 0;
static uint32_t s_btn_repeat_ms[MW_BTN_BACK + 1];

void mw_ui_set_button_hook(mw_ui_btn_hook_t hook, void* user) {
    MW_LOGD("ui", "set_button_hook: hook=%p user=%p", (void*)hook, user);
    s_btn_hook      = hook;
    s_btn_hook_user = user;
}

static void key_push(uint32_t key, uint8_t state) {
    uint8_t next = (uint8_t)((s_key_head + 1) % MW_KEY_FIFO);
    if (next == s_key_tail) return;              // drop, never block
    s_key_fifo[s_key_head].key   = key;
    s_key_fifo[s_key_head].state = state;
    s_key_head = next;
}

static uint32_t lv_key_for(mw_button_t b) {
    switch (b) {
    case MW_BTN_UP:     return LV_KEY_PREV;
    case MW_BTN_DOWN:   return LV_KEY_NEXT;
    case MW_BTN_LEFT:   return LV_KEY_LEFT;
    case MW_BTN_RIGHT:  return LV_KEY_RIGHT;
    case MW_BTN_SELECT: return LV_KEY_ENTER;
    case MW_BTN_BACK:   return LV_KEY_ESC;
    default:            return 0;
    }
}

#if LVGL_VERSION_MAJOR >= 9
static void mw_keypad_cb(lv_indev_t* indev, lv_indev_data_t* data)
#else
static void mw_keypad_cb(lv_indev_drv_t* indev, lv_indev_data_t* data)
#endif
{
    MW_UNUSED(indev);
    if (s_key_tail == s_key_head) {
        data->key   = 0;
        data->state = LV_INDEV_STATE_RELEASED;
        return;
    }
    data->key   = s_key_fifo[s_key_tail].key;
    data->state = s_key_fifo[s_key_tail].state ? LV_INDEV_STATE_PRESSED
                                               : LV_INDEV_STATE_RELEASED;
    s_key_tail  = (uint8_t)((s_key_tail + 1) % MW_KEY_FIFO);
    data->continue_reading = (s_key_tail != s_key_head);
}

// Auto-repeat while an arrow key is held, so long lists stay usable.
#define MW_BTN_REPEAT_FIRST_MS 450
#define MW_BTN_REPEAT_MS       120

static void poll_buttons(void) {
    const mw_hal_caps_t* caps = mw_hal_caps();
    if (!caps->has_buttons && !caps->has_encoder) return;

    const uint32_t now  = mw_millis();
    const uint32_t mask = mw_buttons_read();

    static uint32_t s_prev_log = 0;
    if (mask != s_prev_log) {
        MW_LOGD("ui", "buttons mask=0x%02lX", (unsigned long)mask);
        s_prev_log = mask;
    }

    for (int b = MW_BTN_UP; b <= MW_BTN_BACK; b++) {
        const uint32_t bit  = 1u << b;
        const bool was = (s_btn_prev_mask & bit) != 0;
        const bool is  = (mask & bit) != 0;

        if (is && !was) {                                   // press edge
            MW_LOGD("ui", "btn %d PRESS", b);
            // Keys routed to a hook bypass the indev: keep the autolock
            // inactivity timer honest.
#if LVGL_VERSION_MAJOR >= 9
            lv_display_trigger_activity(NULL);
#else
            lv_disp_trig_activity(NULL);
#endif
            s_btn_down_ms[b]   = now;
            s_btn_repeat_ms[b] = now + MW_BTN_REPEAT_FIRST_MS;
            if (s_btn_hook) {
                s_btn_hook((mw_button_t)b, 0, false, s_btn_hook_user);
            } else {
                uint32_t k = lv_key_for((mw_button_t)b);
                if (k) { key_push(k, 1); key_push(k, 0); }
            }
        } else if (is && was) {                             // held
            if (s_btn_hook) {
                s_btn_hook((mw_button_t)b, now - s_btn_down_ms[b], false,
                           s_btn_hook_user);
            } else if (b != MW_BTN_SELECT && b != MW_BTN_BACK &&
                       (int32_t)(now - s_btn_repeat_ms[b]) >= 0) {
                s_btn_repeat_ms[b] = now + MW_BTN_REPEAT_MS;
                uint32_t k = lv_key_for((mw_button_t)b);
                if (k) { key_push(k, 1); key_push(k, 0); }
            }
        } else if (!is && was) {                            // release edge
            MW_LOGD("ui", "btn %d RELEASE", b);
            if (s_btn_hook) {
                s_btn_hook((mw_button_t)b, now - s_btn_down_ms[b], true,
                           s_btn_hook_user);
            }
        }
    }
    s_btn_prev_mask = mask;

    // TZ 2.5 / 5.6: the optional encoder replaces Left/Right.
    if (caps->has_encoder) {
        int32_t d = mw_encoder_read();
        while (d > 0) {
            if (s_btn_hook) s_btn_hook(MW_BTN_RIGHT, 0, false, s_btn_hook_user);
            else { key_push(LV_KEY_NEXT, 1); key_push(LV_KEY_NEXT, 0); }
            d--;
        }
        while (d < 0) {
            if (s_btn_hook) s_btn_hook(MW_BTN_LEFT, 0, false, s_btn_hook_user);
            else { key_push(LV_KEY_PREV, 1); key_push(LV_KEY_PREV, 0); }
            d++;
        }
    }
}

// ---------------------------------------------------------------------------
// Group management. The keypad indev must ALWAYS point at a live group:
// lv_indev_read() dereferences the group on every poll, so a NULL group
// crashes the device on the next tick.
// ---------------------------------------------------------------------------
static lv_group_t* s_group_current = NULL;

void mw_ui_group_activate(lv_group_t* g) {
    MW_LOGD("ui", "group_activate: g=%p (indev=%p)", (void*)g, (void*)s_indev_keys);
    s_group_current = g;
    if (s_indev_keys && g) lv_indev_set_group(s_indev_keys, g);
}

lv_group_t* mw_ui_group_current(void) { return s_group_current; }

// ---------------------------------------------------------------------------
// Job plumbing
// ---------------------------------------------------------------------------
static void pump_jobs(void) {
#if MW_HAS_FREERTOS
    ui_job_t j;
    if (!s_job_q) return;
    while (xQueueReceive(s_job_q, &j, 0) == pdTRUE) {
        MW_LOGD("ui", "pump_job kind=%u fn=%p", (unsigned)j.kind, (void*)j.fn);
        if (j.fn) j.fn(j.arg);
        if (j.kind == JOB_SYNC && s_sync_sem) xSemaphoreGive(s_sync_sem);
    }
#endif
}

void mw_ui_async_call(mw_ui_job_fn fn, void* arg) {
    if (!fn) return;
    wait_for_ui_task();
    if (mw_ui_is_ui_task() || !ui_task_running()) {
        mw_ui_lock(); fn(arg); mw_ui_unlock();
        return;
    }
#if MW_HAS_FREERTOS
    ui_job_t j = { fn, arg, JOB_ASYNC };
    xQueueSend(s_job_q, &j, 0);
#endif
}

void mw_ui_sync_call(mw_ui_job_fn fn, void* arg) {
    if (!fn) return;
    wait_for_ui_task();
    MW_LOGD("ui", "sync_call fn=%p arg=%p ui_task=%d",
           (void*)fn, arg, (int)mw_ui_is_ui_task());
    if (mw_ui_is_ui_task() || !ui_task_running()) {
        mw_ui_lock(); fn(arg); mw_ui_unlock();
        return;
    }
#if MW_HAS_FREERTOS
    xSemaphoreTake(s_sync_mutex, portMAX_DELAY);
    ui_job_t j = { fn, arg, JOB_SYNC };
    xQueueSend(s_job_q, &j, portMAX_DELAY);
    xSemaphoreTake(s_sync_sem, portMAX_DELAY);
    xSemaphoreGive(s_sync_mutex);
#endif
    MW_LOGD("ui", "sync_call done fn=%p", (void*)fn);
}

int32_t mw_ui_modal_call(mw_ui_job_fn fn, void* arg) {
    if (!fn) return -1;
    wait_for_ui_task();
    // Once the lock is requested no new dialog opens for the crypto task:
    // every flow sees "cancelled" and unwinds back to the shell.
    if (s_lock_requested && !mw_ui_is_ui_task()) return -1;
    const bool local = mw_ui_is_ui_task() || !ui_task_running();
    MW_LOGD("ui", "modal_call fn=%p local=%d top=%d",
           (void*)fn, (int)local, s_frame_top);

#if MW_HAS_FREERTOS
    if (!local) xSemaphoreTake(s_modal_mutex, portMAX_DELAY);
#endif
    const int idx = s_frame_top + 1;
    if (idx >= MW_MODAL_DEPTH) {
#if MW_HAS_FREERTOS
        if (!local) xSemaphoreGive(s_modal_mutex);
#endif
        return -1;
    }
    s_frames[idx].done   = false;
    s_frames[idx].result = -1;
    s_frames[idx].local  = local;
    s_frame_top = idx;

    if (local) {
        mw_ui_lock(); fn(arg); mw_ui_unlock();
        while (!s_frames[idx].done) {
            mw_ui_tick();
            mw_delay_ms(5);
        }
    } else {
#if MW_HAS_FREERTOS
        ui_job_t j = { fn, arg, JOB_MODAL };
        xQueueSend(s_job_q, &j, portMAX_DELAY);
        while (!s_frames[idx].done) {
            xSemaphoreTake(s_modal_sem, pdMS_TO_TICKS(100));
        }
#endif
    }

    const int32_t r = s_frames[idx].result;
    MW_LOGD("ui", "modal_call done idx=%d result=%ld", idx, (long)r);
    s_frame_top = idx - 1;
#if MW_HAS_FREERTOS
    if (!local) xSemaphoreGive(s_modal_mutex);
#endif
    return r;
}

void mw_ui_modal_done(int32_t result) {
    const int idx = s_frame_top;
    MW_LOGD("ui", "modal_done idx=%d result=%ld", idx, (long)result);
    if (idx < 0 || idx >= MW_MODAL_DEPTH) return;
    if (s_frames[idx].done) {
        MW_LOGD("ui", "modal_done: ALREADY done, ignored");
        return;
    }
    // Whatever closed the modal, its cancel registration is void now.
    mw_ui_modal_clear_cancel();
    s_frames[idx].result = result;
    s_frames[idx].done   = true;
#if MW_HAS_FREERTOS
    if (!s_frames[idx].local && s_modal_sem) xSemaphoreGive(s_modal_sem);
#endif
}

// ---------------------------------------------------------------------------
// Settings cache
// ---------------------------------------------------------------------------
static mw_settings_t s_settings;
static bool          s_settings_valid = false;

const mw_settings_t* mw_ui_settings(void) {
    if (!s_settings_valid) {
        if (mw_settings_load(&s_settings) != MW_OK) {
            memset(&s_settings, 0, sizeof(s_settings));
            s_settings.keyboard     = mw_settings_default_keyboard();
            s_settings.kb_layout    = KB_LAYOUT_QWERTY;
            s_settings.brightness   = 80;
            s_settings.autolock_min = MW_AUTOLOCK_DEFAULT_MIN;
            s_settings.network      = MW_DEFAULT_NETWORK;
            s_settings.debug_log    = false;
        }
        s_settings_valid = true;
    }
    return &s_settings;
}

void mw_ui_settings_reload(void) { s_settings_valid = false; }

mw_err_t mw_ui_settings_store(const mw_settings_t* s) {
    if (!s) return MW_ERR_INVALID_ARG;
    mw_err_t e = mw_settings_save(s);
    if (e == MW_OK) {
        s_settings       = *s;
        s_settings_valid = true;
    }
    return e;
}

// ---------------------------------------------------------------------------
// Screen routing
// ---------------------------------------------------------------------------
// The root screen is only a background: every interactive screen is a page
// or an overlay run by the crypto task (task 3). It is replaced only when it
// is what the display shows - the old code deleted "the active screen",
// which, with a dialog open, was the dialog itself: the crypto task waited
// for it forever and every later menu tap went unanswered (task 3 item 0).
static lv_obj_t* s_root = NULL;

static void show_job(void* arg) {
    const mw_screen_id_t id = (mw_screen_id_t)(intptr_t)arg;
    MW_LOGD("ui", "show_job id=%d", (int)id);
    if (id != MW_SCREEN_BOOT && id != MW_SCREEN_MAIN_MENU) return;

    lv_obj_t* active = MW_SCR_ACT();
    if (s_root && active != s_root) {
        MW_LOGD("ui", "show_job: a page is open, root kept");
        return;
    }
    lv_obj_t* scr = lv_obj_create(NULL);
    lv_obj_add_style(scr, mw_style_page(), LV_PART_MAIN);
    if (id == MW_SCREEN_BOOT) mw_screen_boot_build(scr);
    else                      mw_screen_main_build(scr);
    MW_SCR_LOAD(scr);
    if (active && active != scr) MW_OBJ_DEL(active);
    s_root = scr;
    s_current = id;
}

void mw_ui_show(mw_screen_id_t id) {
    MW_LOGD("ui", "show id=%d", (int)id);
    mw_ui_sync_call(show_job, (void*)(intptr_t)id);
}

mw_screen_id_t mw_ui_current(void) { return s_current; }

// ---------------------------------------------------------------------------
// Autolock (task 3): the UI task calls mw_ui_autolock_tick() once a second.
// When the shell has armed it (device unlocked) and nothing touched the
// screen or the buttons for the configured time, the lock is requested and
// whatever dialog the crypto task waits on is closed as "cancelled"; the
// shell sees mw_ui_lock_requested() and goes back to the game.
// ---------------------------------------------------------------------------

void mw_ui_autolock_arm(bool on) { s_autolock_armed = on; if (!on) s_lock_requested = false; }
bool mw_ui_lock_requested(void)  { return s_lock_requested; }
void mw_ui_lock_request(void)    { mw_touch_trace(false); s_lock_requested = true; }

void mw_ui_autolock_tick(void) {
    if (!s_inited || !s_autolock_armed || s_lock_requested) return;
    const uint16_t minutes = mw_ui_settings()->autolock_min;
    if (minutes == 0) return;
    mw_ui_lock();
#if LVGL_VERSION_MAJOR >= 9
    const uint32_t idle = lv_display_get_inactive_time(NULL);
#else
    const uint32_t idle = lv_disp_get_inactive_time(NULL);
#endif
    if (idle >= (uint32_t)minutes * 60000u) {
        MW_LOGI("ui", "autolock after %u min without input", (unsigned)minutes);
        mw_touch_trace(false);
        s_lock_requested = true;
        mw_ui_cancel_modal();
    }
    mw_ui_unlock();
}

// ---------------------------------------------------------------------------
// Status bar values (TZ 4.2)
// ---------------------------------------------------------------------------
void mw_ui_set_status(int battery_percent, bool sd, bool usb) {
    if (battery_percent != s_batt || sd != s_sd || usb != s_usb) {
        s_batt = battery_percent;
        s_sd   = sd;
        s_usb  = usb;
        s_status_dirty = true;
    }
}

void mw_ui_status_values(int* batt, bool* sd, bool* usb) {
    if (batt) *batt = s_batt;
    if (sd)   *sd   = s_sd;
    if (usb)  *usb  = s_usb;
}

// ---------------------------------------------------------------------------
// Init / tick
// ---------------------------------------------------------------------------
mw_err_t mw_ui_init(void) {
    if (s_inited) return MW_OK;
    MW_LOGD("ui", "init");

    const mw_hal_caps_t* caps = mw_hal_caps();
    if (!caps || caps->width == 0 || caps->height == 0) return MW_ERR_NOT_SUPPORTED;

#if MW_HAS_FREERTOS
    s_job_q       = xQueueCreate(MW_JOB_QUEUE_LEN, sizeof(ui_job_t));
    s_sync_sem    = xSemaphoreCreateBinary();
    s_modal_sem   = xSemaphoreCreateBinary();
    s_sync_mutex  = xSemaphoreCreateMutex();
    s_modal_mutex = xSemaphoreCreateMutex();
    s_lv_mutex    = xSemaphoreCreateRecursiveMutex();
    if (!s_job_q || !s_sync_sem || !s_modal_sem || !s_sync_mutex ||
        !s_modal_mutex || !s_lv_mutex) {
        return MW_ERR_MEMORY;
    }
#endif

    lv_init();
    alloc_draw_buffer(caps);

#if LVGL_VERSION_MAJOR >= 9
    lv_tick_set_cb(mw_millis);

    s_disp = lv_display_create(caps->width, caps->height);
    if (!s_disp) return MW_ERR_MEMORY;
    lv_display_set_flush_cb(s_disp, mw_flush_cb);
    lv_display_set_buffers(s_disp, s_draw_px, NULL,
                           (uint32_t)(s_draw_len * sizeof(uint16_t)),
                           LV_DISPLAY_RENDER_MODE_PARTIAL);
#else
    s_last_tick_ms = mw_millis();
    lv_disp_draw_buf_init(&s_lv_draw_buf, s_draw_px, NULL, s_draw_len);
    lv_disp_drv_init(&s_lv_disp_drv);
    s_lv_disp_drv.hor_res  = (lv_coord_t)caps->width;
    s_lv_disp_drv.ver_res  = (lv_coord_t)caps->height;
    s_lv_disp_drv.flush_cb = mw_flush_cb;
    s_lv_disp_drv.draw_buf = &s_lv_draw_buf;
    s_disp = lv_disp_drv_register(&s_lv_disp_drv);
    if (!s_disp) return MW_ERR_MEMORY;
#endif

    MW_LOGD("ui", "theme_init");
    mw_theme_init(s_disp);
    MW_LOGD("ui", "theme_init done");

    // --- input devices ----------------------------------------------------
#if LVGL_VERSION_MAJOR >= 9
    if (caps->has_touch) {
        s_indev_touch = lv_indev_create();
        lv_indev_set_type(s_indev_touch, LV_INDEV_TYPE_POINTER);
        lv_indev_set_read_cb(s_indev_touch, mw_touch_cb);
        lv_indev_set_display(s_indev_touch, s_disp);
        // A tap with a few pixels of jitter must stay a tap: below this many
        // pixels of movement LVGL does not start a scroll (and so does not
        // swallow the CLICKED event of a list row).
        lv_indev_set_scroll_limit(s_indev_touch, 16);
    }
    if (caps->has_buttons || caps->has_encoder) {
        s_indev_keys = lv_indev_create();
        lv_indev_set_type(s_indev_keys, LV_INDEV_TYPE_KEYPAD);
        lv_indev_set_read_cb(s_indev_keys, mw_keypad_cb);
        lv_indev_set_display(s_indev_keys, s_disp);
    }
#else
    if (caps->has_touch) {
        lv_indev_drv_init(&s_lv_touch_drv);
        s_lv_touch_drv.type    = LV_INDEV_TYPE_POINTER;
        s_lv_touch_drv.read_cb = mw_touch_cb;
        s_lv_touch_drv.disp    = s_disp;
        s_lv_touch_drv.scroll_limit = 16;
        s_indev_touch = lv_indev_drv_register(&s_lv_touch_drv);
    }
    if (caps->has_buttons || caps->has_encoder) {
        lv_indev_drv_init(&s_lv_keys_drv);
        s_lv_keys_drv.type    = LV_INDEV_TYPE_KEYPAD;
        s_lv_keys_drv.read_cb = mw_keypad_cb;
        s_lv_keys_drv.disp    = s_disp;
        s_indev_keys = lv_indev_drv_register(&s_lv_keys_drv);
    }
#endif

    memset(s_btn_down_ms, 0, sizeof(s_btn_down_ms));
    memset(s_btn_repeat_ms, 0, sizeof(s_btn_repeat_ms));

    s_inited = true;

    MW_LOGD("ui", "init: boot screen");
    show_job((void*)(intptr_t)MW_SCREEN_BOOT);
    MW_LOGD("ui", "init done");
    return MW_OK;
}

void mw_ui_tick(void) {
    if (!s_inited) return;

    static uint32_t s_last_beat = 0;
    const uint32_t now = mw_millis();
    if (now - s_last_beat >= 1000) {
        s_last_beat = now;
        MW_LOGD("ui", "tick %lu", (unsigned long)now);
    }

#if LVGL_VERSION_MAJOR < 9
    {
        const uint32_t tnow = mw_millis();
        lv_tick_inc(tnow - s_last_tick_ms);
        s_last_tick_ms = tnow;
    }
#endif

    mw_ui_lock();
    poll_buttons();
    pump_jobs();
    if (s_status_dirty) {
        s_status_dirty = false;
        mw_ui_status_apply();
    }
    lv_timer_handler();
    mw_ui_unlock();
}

// ---------------------------------------------------------------------------
// Optional: let the port own the LVGL task (bring-up sketches).
// ---------------------------------------------------------------------------
#if MW_HAS_FREERTOS
static void ui_task_entry(void* arg) {
    MW_UNUSED(arg);
    mw_ui_task_register();
    for (;;) {
        mw_ui_tick();
        vTaskDelay(pdMS_TO_TICKS(5));
    }
}
#endif

void mw_ui_task_start(void) {
#if MW_HAS_FREERTOS
    if (s_ui_task) return;
    mw_ui_task_expect();
    xTaskCreatePinnedToCore(ui_task_entry, "ui", MW_UI_TASK_STACK, NULL,
                            MW_UI_TASK_PRIO, NULL, MW_UI_TASK_CORE);
#endif
}