// ---------------------------------------------------------------------------
//  Animated QR display and camera viewfinder (TZ 3.7, 4.2).
//
//  Display                              Scan
//  ┌────────────────────────────┐   ┌────────────────────────────┐
//  │ Экспорт keyimages.bin      │   │ Сканирование QR            │
//  │   ██▀▀██▄▄██▀▀██           │   │  ┌──────────────────────┐  │
//  │   ██▄▄██▀▀██▄▄██           │   │  │      viewfinder      │  │
//  │   ██▀▀██▄▄██▀▀██           │   │  └──────────────────────┘  │
//  │ Часть 3 из 7               │   │ ████████░░░░░░░  47%       │
//  │ [Пауза]        [Отмена]    │   │ Наведите камеру на QR-код  │
//  └────────────────────────────┘   │        [Отмена]            │
//                                   └────────────────────────────┘
//
//  In landscape the code sits on the left and the part counter and the
//  buttons stack on the right, so the code gets the full content height.
//
//  Animation runs at 12.5 FPS (80 ms), the rate TZ 3.7 specifies for UR
//  fountain frames.
//
//  Camera ownership: the scanning loop runs on the CALLER's task (the crypto
//  task) and is the only thing that ever touches mw_camera_*. It writes the
//  preview straight into the canvas buffer and asks the LVGL task to
//  invalidate it, so there is exactly one writer and one reader.
//
//  QR *decoding* (image -> string) is not part of the HAL. The backend, if the
//  firmware links one, provides mw_qr_decode_frame(); the symbol is weak, so a
//  build without a decoder still links and the screen says so.
// ---------------------------------------------------------------------------
#include "screen_common.h"
#include "../transfer/ur.h"
#include "../transfer/qr_encode.h"
#include "../hal/log.h"

#include <stdio.h>
#include <string.h>
#include <stdlib.h>

// Optional QR decoding backend (quirc, esp-code-scanner, ...).
extern "C" int mw_qr_decode_frame(const mw_camera_frame_t* frame,
                                  char* out, size_t cap) __attribute__((weak));

#define MW_QR_FRAME_MS   80          // TZ 3.7: 12.5 FPS
#define MW_UR_STR_MAX    1024        // 0.3.6: up to a version-20 symbol of text

// ===========================================================================
//  Animated QR display
// ===========================================================================
typedef struct {
    mw_page_t      page;
    mw_ur_encoder* enc;
    const char*    ur_type;      // 0.3.6: the encoder is made in the build,
    const uint8_t* data;         // once the code's side on screen is known
    size_t         len;
    lv_obj_t*      qr;
    lv_obj_t*      lbl;
    lv_timer_t*    timer;
    uint32_t       seq_len;
    uint32_t       part;
    bool           paused;
    lv_obj_t*      btn_pause;
    const char*    title;
} qrshow_ctx_t;

static qrshow_ctx_t s_show;

#if LV_USE_QRCODE
static lv_obj_t* qr_widget_create(lv_obj_t* parent, lv_coord_t size) {
#if LVGL_VERSION_MAJOR >= 9
    lv_obj_t* qr = lv_qrcode_create(parent);
    lv_qrcode_set_size(qr, size);
    lv_qrcode_set_dark_color(qr, lv_color_black());
    lv_qrcode_set_light_color(qr, lv_color_white());
    return qr;
#else
    return lv_qrcode_create(parent, size, lv_color_black(), lv_color_white());
#endif
}
#endif

// ---------------------------------------------------------------------------
// Layout shared by both QR pages.
//   portrait:  [code] / text / footer buttons
//   landscape: [code] | column with the text and the buttons (no footer)
// The code slot is created first as a placeholder, everything else is built,
// the page is laid out, and only then is the code side taken from the room
// that is really left (qr_slot_fix). The code stays black on white whatever
// the UI theme is.
// ---------------------------------------------------------------------------
#if LV_USE_QRCODE
static lv_obj_t* qr_slot_create(mw_page_t* page) {
    const mw_metrics_t* m = mw_metrics();
    lv_obj_t* body = page->body;
    lv_obj_set_flex_align(body, LV_FLEX_ALIGN_START, LV_FLEX_ALIGN_CENTER,
                          LV_FLEX_ALIGN_CENTER);
    lv_obj_t* slot = lv_obj_create(body);
    lv_obj_remove_style_all(slot);
    if (m->landscape) {
        lv_obj_set_flex_flow(body, LV_FLEX_FLOW_ROW);
        lv_obj_set_style_pad_column(body, m->gap, LV_PART_MAIN);
    }
    lv_obj_set_size(slot, 0, 0);
    lv_obj_set_style_bg_color(slot, lv_color_white(), LV_PART_MAIN);
    lv_obj_set_style_bg_opa(slot, LV_OPA_COVER, LV_PART_MAIN);
    lv_obj_set_style_pad_all(slot, m->gap, LV_PART_MAIN);
    MW_OBJ_CLEAR_FLAG(slot, LV_OBJ_FLAG_SCROLLABLE);
    return slot;
}
#endif

// Landscape: the column right of the code.
static lv_obj_t* qr_side_column(mw_page_t* page) {
    const mw_metrics_t* m = mw_metrics();
    lv_obj_t* col = lv_obj_create(page->body);
    lv_obj_remove_style_all(col);
    lv_obj_set_size(col, 0, lv_pct(100));
    lv_obj_set_flex_grow(col, 1);
    lv_obj_set_flex_flow(col, LV_FLEX_FLOW_COLUMN);
    lv_obj_set_style_pad_row(col, m->gap, LV_PART_MAIN);
    MW_OBJ_CLEAR_FLAG(col, LV_OBJ_FLAG_SCROLLABLE);
    return col;
}

// A full-width button in the landscape column.
static lv_obj_t* qr_column_button(lv_obj_t* col, const char* text, lv_event_cb_t cb) {
    lv_obj_t* b = mw_ui_button(col, text, cb, NULL);
    lv_obj_set_flex_grow(b, 0);
    lv_obj_set_width(b, lv_pct(100));
    return b;
}

static lv_obj_t* qr_spacer(lv_obj_t* parent) {
    lv_obj_t* sp = lv_obj_create(parent);
    lv_obj_remove_style_all(sp);
    lv_obj_set_size(sp, lv_pct(100), 0);
    lv_obj_set_flex_grow(sp, 1);
    MW_OBJ_CLEAR_FLAG(sp, LV_OBJ_FLAG_SCROLLABLE);
    return sp;
}

#if LV_USE_QRCODE
// Lays the page out and returns the largest code side the slot allows;
// `extra_h` is height (portrait) the caller may still give to the code.
static lv_coord_t qr_slot_measure(mw_page_t* page, lv_coord_t extra_h) {
    const mw_metrics_t* m = mw_metrics();
    lv_coord_t side;
    if (m->landscape) {
        lv_obj_update_layout(page->scr);
        const lv_coord_t bw = (lv_coord_t)lv_obj_get_content_width(page->body);
        side = (lv_coord_t)lv_obj_get_content_height(page->body);
        if (side > bw * 2 / 3) side = (lv_coord_t)(bw * 2 / 3);
    } else {
        side = (lv_coord_t)(mw_ui_free_height(page->body) + extra_h);
        const lv_coord_t bw = (lv_coord_t)lv_obj_get_content_width(page->body);
        if (side > bw) side = bw;
    }
    side = (lv_coord_t)(side - 2 * m->gap);
    if (side < 32) side = 32;
    return side;
}

static lv_obj_t* qr_slot_fix(lv_obj_t* slot, lv_coord_t side) {
    const mw_metrics_t* m = mw_metrics();
    lv_obj_set_size(slot, (lv_coord_t)(side + 2 * m->gap), (lv_coord_t)(side + 2 * m->gap));
    lv_obj_t* qr = qr_widget_create(slot, side);
    lv_obj_center(qr);
    return qr;
}
#endif


// 0.3.6: the largest UR fragment whose frame still gets >= 3 screen pixels
// per module on a code `side` px wide (LVGL renders byte mode, ECC M, whole
// pixels per module). A UR frame is "ur:<type>/<n>-<m>/" plus bytewords
// (2 letters a byte) of a ~24-byte CBOR part header, the fragment and the
// CRC. Kept between 30 and 200 bytes.
static size_t qr_fragment_for(lv_coord_t side, const char* type) {
    const int modules = side / 3;
    int version = (modules - 17) / 4;
    if (version > MW_QR_MAX_VERSION) version = MW_QR_MAX_VERSION;
    if (version < 3) version = 3;
    const size_t cap = mw_qr_byte_capacity((uint8_t)version, MW_QR_ECC_M);
    const size_t fixed = 3 + strlen(type ? type : MW_UR_TYPE_BYTES) + 1 + 12;
    size_t frag = cap > fixed + 2 * 28 ? (cap - fixed) / 2 - 28 : 30;
    if (frag < 30)  frag = 30;
    if (frag > 200) frag = 200;
    return frag;
}

static void qrshow_finish(int32_t r) {
    if (s_show.timer) { MW_TIMER_DEL(s_show.timer); s_show.timer = NULL; }
    mw_ui_page_destroy(&s_show.page);
    mw_ui_modal_done(r);
}
static void qrshow_done_cb(lv_event_t* e)   { MW_UNUSED(e); qrshow_finish(1); }
static void qrshow_cancel_cb(lv_event_t* e) { MW_UNUSED(e); qrshow_finish(0); }
static void qrshow_escape(void* user)       { MW_UNUSED(user); qrshow_finish(0); }

static void qrshow_pause_cb(lv_event_t* e) {
    MW_UNUSED(e);
    s_show.paused = !s_show.paused;
    if (s_show.btn_pause) {
        lv_obj_t* l = lv_obj_get_child(s_show.btn_pause, 0);
        if (l) lv_label_set_text(l, s_show.paused ? TX(XSTR_QR_RESUME)
                                                  : TX(XSTR_QR_PAUSE));
    }
}

static void qrshow_tick(lv_timer_t* t) {
    qrshow_ctx_t* c = (qrshow_ctx_t*)MW_TIMER_USER(t);
    if (!c || !c->enc || c->paused) return;

    static char part[MW_UR_STR_MAX];
    const size_t n = mw_ur_encoder_next(c->enc, part, sizeof(part));
    if (n == 0) return;

#if LV_USE_QRCODE
    if (c->qr) lv_qrcode_update(c->qr, part, n);
#endif
    c->part = (c->seq_len > 0) ? ((c->part % c->seq_len) + 1) : 1;
    if (c->lbl) {
        lv_label_set_text_fmt(c->lbl, TX(XSTR_QR_PART),
                              (int)c->part, (int)c->seq_len);
    }
}

static void qrshow_build(void* arg) {
    qrshow_ctx_t* c = (qrshow_ctx_t*)arg;
    const mw_metrics_t* m = mw_metrics();

    mw_ui_page_create(&c->page, c->title, true);
    mw_ui_page_set_escape(&c->page, qrshow_escape, c);

#if LV_USE_QRCODE
    lv_obj_t* slot = qr_slot_create(&c->page);
#else
    mw_ui_label(c->page.body, TX(XSTR_NO_QRCODE), mw_style_dim());
#endif

    lv_obj_t* bd;
    lv_obj_t* bc;
    if (m->landscape) {
        lv_obj_t* col = qr_side_column(&c->page);
        c->lbl = mw_ui_label(col, "", mw_style_dim());
        qr_spacer(col);
        c->btn_pause = qr_column_button(col, TX(XSTR_QR_PAUSE), qrshow_pause_cb);
        bd = qr_column_button(col, T(STR_DONE),   qrshow_done_cb);
        bc = qr_column_button(col, T(STR_CANCEL), qrshow_cancel_cb);
    } else {
        c->lbl = mw_ui_label(c->page.body, "", mw_style_dim());
        lv_obj_t* f  = mw_ui_page_footer(&c->page);
        c->btn_pause = mw_ui_button(f, TX(XSTR_QR_PAUSE), qrshow_pause_cb, NULL);
        bd = mw_ui_button(f, T(STR_DONE),   qrshow_done_cb,   NULL);
        bc = mw_ui_button(f, T(STR_CANCEL), qrshow_cancel_cb, NULL);
    }
    mw_ui_focus_add(&c->page, c->btn_pause);
    mw_ui_focus_add(&c->page, bd);
    mw_ui_focus_add(&c->page, bc);
    lv_group_focus_obj(bd);

#if LV_USE_QRCODE
    c->qr = qr_slot_fix(slot, qr_slot_measure(&c->page, 0));
#endif

    c->timer = lv_timer_create(qrshow_tick, MW_QR_FRAME_MS, c);
    qrshow_tick(c->timer);              // paint the first frame immediately
}

bool mw_screen_qr_show_run(const char* title, const char* ur_type,
                           const uint8_t* data, size_t len) {
    if (!data || len == 0) return false;

    memset(&s_show, 0, sizeof(s_show));
    s_show.title   = title ? title : TX(XSTR_SHOW_QR);
    s_show.ur_type = ur_type ? ur_type : MW_UR_TYPE_BYTES;
    s_show.data    = data;
    s_show.len     = len;
    // The code's side: about the panel's short edge less the title, status
    // and button rows (portrait) or the button column (landscape).
    const mw_metrics_t* m = mw_metrics();
    const lv_coord_t short_edge = m->w < m->h ? m->w : m->h;
    const lv_coord_t side = m->landscape ? (lv_coord_t)(short_edge - 2 * m->row_h)
                                         : (lv_coord_t)(short_edge - 2 * m->pad);
    const size_t frag = qr_fragment_for(side, s_show.ur_type);
    s_show.enc = mw_ur_encoder_new(s_show.ur_type, data, len, frag);
    if (!s_show.enc) {
        mw_ui_message(T(STR_ERR_GENERIC), T(STR_ERR_GENERIC));
        return false;
    }
    s_show.seq_len = mw_ur_encoder_seq_len(s_show.enc);
    MW_LOGI("qr", "showing %s: %u bytes, %u parts of %u bytes", s_show.ur_type,
            (unsigned)len, (unsigned)s_show.seq_len, (unsigned)frag);

    const int32_t r = mw_ui_modal_call(qrshow_build, &s_show);

    mw_ur_encoder_free(s_show.enc);
    s_show.enc = NULL;
    return r == 1;
}

// ===========================================================================
//  Static QR (task2 item 5): one code, no animation, the text underneath.
// ===========================================================================
typedef struct {
    mw_page_t   page;
    const char* title;
    const char* text;
    bool        done;
} qrstatic_ctx_t;

static qrstatic_ctx_t s_static;

static void qrstatic_finish(int32_t r) {
    if (s_static.done) return;
    s_static.done = true;
    mw_ui_page_destroy(&s_static.page);
    mw_ui_modal_done(r);
}
static void qrstatic_close_cb(lv_event_t* e) { MW_UNUSED(e); qrstatic_finish(1); }
static void qrstatic_escape(void* user)     { MW_UNUSED(user); qrstatic_finish(1); }

// Below this side a code with a full address gets hard to scan; the portrait
// page then gives the text one line less to keep the code at least this big.
#define MW_QR_STATIC_GOOD_SIDE 200

static void qrstatic_build(void* arg) {
    qrstatic_ctx_t* c = (qrstatic_ctx_t*)arg;
    const mw_metrics_t* m = mw_metrics();
    c->done = false;

    mw_ui_page_create(&c->page, c->title, false);
    mw_ui_page_set_escape(&c->page, qrstatic_escape, c);

#if LV_USE_QRCODE
    lv_obj_t* slot = qr_slot_create(&c->page);
#else
    mw_ui_label(c->page.body, TX(XSTR_NO_QRCODE), mw_style_dim());
#endif

    // The text itself, scrollable, so the user can compare it character by
    // character with the online wallet. Portrait reserves two lines for it.
    lv_obj_t* parent = m->landscape ? qr_side_column(&c->page) : c->page.body;
    const lv_coord_t lh = (lv_coord_t)lv_font_get_line_height(m->font_mono);
    lv_obj_t* box = lv_obj_create(parent);
    lv_obj_remove_style_all(box);
    lv_obj_set_width(box, lv_pct(100));
    if (m->landscape) {
        lv_obj_set_height(box, 0);
        lv_obj_set_flex_grow(box, 1);
    } else {
        lv_obj_set_height(box, (lv_coord_t)(2 * lh));
    }
    lv_obj_add_flag(box, LV_OBJ_FLAG_SCROLLABLE);
    lv_obj_set_scroll_dir(box, LV_DIR_VER);
    MW_OBJ_CLEAR_FLAG(box, LV_OBJ_FLAG_CLICKABLE);
    mw_ui_label(box, c->text, mw_style_mono());

    lv_obj_t* b;
    if (m->landscape) {
        b = qr_column_button(parent, TX(XSTR_CLOSE), qrstatic_close_cb);
    } else {
        lv_obj_t* f = mw_ui_page_footer(&c->page);
        b = mw_ui_button(f, TX(XSTR_CLOSE), qrstatic_close_cb, NULL);
    }
    mw_ui_focus_add(&c->page, b);
    lv_group_focus_obj(b);

#if LV_USE_QRCODE
    lv_coord_t side = qr_slot_measure(&c->page, 0);
    if (!m->landscape && side < MW_QR_STATIC_GOOD_SIDE) {
        lv_coord_t alt = qr_slot_measure(&c->page, lh);
        if (alt > MW_QR_STATIC_GOOD_SIDE) alt = MW_QR_STATIC_GOOD_SIDE;
        if (alt > side) side = alt;
    }
    lv_obj_t* qr = qr_slot_fix(slot, side);
    lv_qrcode_update(qr, c->text, (uint32_t)strlen(c->text));
#endif
    if (!m->landscape) {
        lv_obj_set_height(box, 0);
        lv_obj_set_flex_grow(box, 1);
    }
}

bool mw_screen_qr_static_run(const char* title, const char* text) {
    if (!text || !text[0]) return false;
    memset(&s_static, 0, sizeof(s_static));
    s_static.title = title ? title : TX(XSTR_SHOW_QR);
    s_static.text  = text;
    return mw_ui_modal_call(qrstatic_build, &s_static) == 1;
}

// ===========================================================================
//  Camera viewfinder + UR assembly
// ===========================================================================
#define MW_VIEWFINDER_W 160
#define MW_VIEWFINDER_H 120

typedef struct {
    mw_page_t page;
    const char* title;
    lv_obj_t* canvas;
    lv_obj_t* bar;
    lv_obj_t* lbl;
    char      status[64];
    uint16_t* frame_buf;
    uint16_t  vw, vh;
    volatile bool cancelled;
    int       permille;
} qrscan_ctx_t;

static qrscan_ctx_t s_scan;

static void qrscan_cancel_cb(lv_event_t* e) {
    MW_UNUSED(e);
    s_scan.cancelled = true;
}
static void qrscan_escape(void* user) {
    MW_UNUSED(user);
    s_scan.cancelled = true;
}

static void qrscan_open_job(void* arg) {
    qrscan_ctx_t* c = (qrscan_ctx_t*)arg;
    const mw_metrics_t* m = mw_metrics();

    mw_ui_page_create(&c->page, c->title, true);
    mw_ui_page_set_escape(&c->page, qrscan_escape, c);

    if (c->frame_buf) {
        c->canvas = lv_canvas_create(c->page.body);
#if LVGL_VERSION_MAJOR >= 9
        lv_canvas_set_buffer(c->canvas, c->frame_buf, c->vw, c->vh,
                             LV_COLOR_FORMAT_RGB565);
#else
        lv_canvas_set_buffer(c->canvas, c->frame_buf, c->vw, c->vh,
                             LV_IMG_CF_TRUE_COLOR);
#endif
        lv_obj_set_style_border_width(c->canvas, 1, LV_PART_MAIN);
        lv_obj_set_style_border_color(c->canvas, mw_palette()->accent,
                                      LV_PART_MAIN);
    } else {
        // No preview buffer: draw an empty viewfinder frame instead.
        lv_obj_t* box = lv_obj_create(c->page.body);
        lv_obj_remove_style_all(box);
        lv_obj_set_size(box, (lv_coord_t)(m->w - 2 * m->pad),
                        (lv_coord_t)((m->w - 2 * m->pad) * 3 / 4));
        lv_obj_set_style_border_width(box, 1, LV_PART_MAIN);
        lv_obj_set_style_border_color(box, mw_palette()->accent, LV_PART_MAIN);
        MW_OBJ_CLEAR_FLAG(box, LV_OBJ_FLAG_SCROLLABLE);
    }

    c->bar = mw_ui_bar(c->page.body);
    c->lbl = mw_ui_label(c->page.body, TX(XSTR_SCAN_HINT), mw_style_dim());

    lv_obj_t* f = mw_ui_page_footer(&c->page);
    lv_obj_t* b = mw_ui_button(f, T(STR_CANCEL), qrscan_cancel_cb, NULL);
    lv_obj_set_flex_grow(b, 1);
    mw_ui_focus_add(&c->page, b);
    lv_group_focus_obj(b);
}

static void qrscan_paint_job(void* arg) {
    qrscan_ctx_t* c = (qrscan_ctx_t*)arg;
    if (c->canvas) lv_obj_invalidate(c->canvas);
    if (c->bar)    lv_bar_set_value(c->bar, c->permille, LV_ANIM_OFF);
    if (c->lbl && c->status[0]) lv_label_set_text(c->lbl, c->status);
}

static void qrscan_close_job(void* arg) {
    qrscan_ctx_t* c = (qrscan_ctx_t*)arg;
    c->canvas = NULL;
    mw_ui_page_destroy(&c->page);
}

bool mw_screen_qr_scan_run(const char* title, uint8_t* buf, size_t cap,
                           size_t* len_out, char* type_out, size_t type_cap) {
    if (!buf || cap == 0) return false;
    if (len_out) *len_out = 0;
    if (type_out && type_cap) type_out[0] = '\0';

    const mw_hal_caps_t* caps = mw_hal_caps();
    if (!caps->has_camera) {
        mw_ui_message(TX(XSTR_SCAN_TITLE), TX(XSTR_NO_CAMERA));
        return false;
    }

    int (*decode)(const mw_camera_frame_t*, char*, size_t) = mw_qr_decode_frame;
    if (!decode) {
        mw_ui_message(TX(XSTR_SCAN_TITLE), TX(XSTR_NO_QRCODE));
        return false;
    }
    if (mw_camera_init() != MW_OK) {
        mw_ui_message(TX(XSTR_SCAN_TITLE), TX(XSTR_NO_CAMERA));
        return false;
    }

    memset(&s_scan, 0, sizeof(s_scan));
    s_scan.title = title ? title : TX(XSTR_SCAN_TITLE);
    s_scan.vw = MW_VIEWFINDER_W;
    s_scan.vh = MW_VIEWFINDER_H;
    if (s_scan.vw > caps->width)  s_scan.vw = caps->width;
    if (s_scan.vh > caps->height) s_scan.vh = caps->height;
    s_scan.frame_buf = (uint16_t*)malloc((size_t)s_scan.vw * s_scan.vh *
                                         sizeof(uint16_t) + 16);

    mw_ui_sync_call(qrscan_open_job, &s_scan);

    mw_ur_decoder* dec = mw_ur_decoder_new(buf, cap);
    bool ok = false;
    static char part[MW_UR_STR_MAX];         // off the caller's stack
    uint32_t frames = 0, read = 0;

    while (!s_scan.cancelled && dec) {
        mw_camera_frame_t frame;
        if (mw_camera_capture(&frame) == MW_OK) {
            frames++;
            if (decode(&frame, part, sizeof(part)) == 1) {
                read++;
                if (mw_ur_decoder_receive(dec, part) != MW_OK && read == 1)
                    MW_LOGD("qr", "first code read is not a UR part");
            }
        }
        if (s_scan.frame_buf) {
            mw_camera_preview(s_scan.frame_buf, s_scan.vw, s_scan.vh);
        }
        s_scan.permille = mw_ur_decoder_progress_permille(dec);
        if (read) {
            snprintf(s_scan.status, sizeof(s_scan.status), TX(XSTR_SCAN_PROGRESS),
                     s_scan.permille / 10);
        }
        mw_ui_async_call(qrscan_paint_job, &s_scan);

        if (mw_ur_decoder_complete(dec)) {
            const uint8_t* data = NULL;
            size_t         len  = 0;
            char           type[33];
            const mw_err_t re = mw_ur_decoder_result(dec, &data, &len, type, sizeof(type));
            if (re == MW_OK && data && len <= cap) {
                // The result sits inside `buf` behind the CBOR byte-string
                // head: move it to the start, where the caller expects it.
                if (data != buf) memmove(buf, data, len);
                if (len_out) *len_out = len;
                if (type_out && type_cap) snprintf(type_out, type_cap, "%s", type);
                ok = true;
            } else {
                MW_LOGE("qr", "animated QR assembled but its checksum is wrong (%s)",
                        mw_err_str(re));
            }
            break;
        }
        mw_delay_ms(10);
    }
    MW_LOGI("qr", "scan %s: %u frames, %u codes read", ok ? "complete" : "stopped",
            (unsigned)frames, (unsigned)read);

    mw_ui_sync_call(qrscan_close_job, &s_scan);

    if (dec) mw_ur_decoder_free(dec);
    mw_qr_scan_release();                     // the decoder's 67 KB working set
    mw_camera_deinit();
    if (s_scan.frame_buf) { free(s_scan.frame_buf); s_scan.frame_buf = NULL; }
    return ok;
}
