// ---------------------------------------------------------------------------
//  Transaction review and confirmation (TZ 4.2, 12.3).
//
//  One scrolling column between the title and the Cancel / Sign footer:
//  the totals (change amount or "Change: none", the dummy-output line), one
//  row per recipient (own addresses marked "this wallet M/m"), then the
//  change row ("Change -> this wallet M/m" with the shortened address, built
//  from the device-derived keys). Every address row opens the full
//  address; the change and own rows add which account / index of this wallet
//  they belong to. Focus starts on Cancel, never on Sign.
// ---------------------------------------------------------------------------
#include "screen_common.h"
#include "../monero/address.h"

#include <stdio.h>
#include <string.h>

typedef struct {
    mw_page_t               page;
    const mw_tx_summary_t*  sum;
    uint64_t                unlock_time;
    lv_obj_t*               last_row;      // строка, с которой открыли оверлей
    int                     focus_id;      // id of that row, -1 = none
} tx_ctx_t;

static tx_ctx_t  s_tx;
static mw_page_t s_addr_ovl;
static bool      s_tx_done = false;

// Focus / row id of the change row (recipient rows use 0..n_recipients-1).
#define TX_ROW_CHANGE MW_MAX_DESTINATIONS

// ---------------------------------------------------------------------------
// Full-address overlay (TZ 12.3 "с прокруткой")
// ---------------------------------------------------------------------------
static void addr_ovl_reset(void) {
    s_addr_ovl.scr        = NULL;
    s_addr_ovl.prev       = NULL;
    s_addr_ovl.group      = NULL;
    s_addr_ovl.prev_group = NULL;
}

static void addr_ovl_del_cb(lv_event_t* e) {
    MW_UNUSED(e);
    s_addr_ovl.scr = NULL;
}

static void addr_ovl_close(void) {
    mw_ui_page_destroy(&s_addr_ovl);
    addr_ovl_reset();
    if (s_tx.page.group && s_tx.last_row) {
        lv_group_focus_obj(s_tx.last_row);
    } else if (s_tx.page.group) {
        mw_ui_group_activate(s_tx.page.group);
    }
}

static void addr_close_cb(lv_event_t* e) { MW_UNUSED(e); addr_ovl_close(); }
static void addr_escape(void* user)      { MW_UNUSED(user); addr_ovl_close(); }

// title, amount, an optional "belongs to this wallet" note, the full address.
static void addr_overlay_open(const char* title, uint64_t amount, const char* note,
                              const char* addr) {
    if (s_addr_ovl.scr) {
        mw_ui_page_destroy(&s_addr_ovl);
        addr_ovl_reset();
    }
    mw_ui_overlay_create(&s_addr_ovl, title);
    mw_ui_page_set_escape(&s_addr_ovl, addr_escape, NULL);
    lv_obj_add_event_cb(s_addr_ovl.scr, addr_ovl_del_cb, LV_EVENT_DELETE, NULL);

    char amt[40];
    mw_format_amount(amount, amt, sizeof(amt));
    char line[64];
    snprintf(line, sizeof(line), "%s: %s", T(STR_TX_AMOUNT), amt);
    mw_ui_label(s_addr_ovl.body, line, NULL);
    if (note) mw_ui_label(s_addr_ovl.body, note, NULL);

    mw_ui_label(s_addr_ovl.body, TX(XSTR_TX_FULL_ADDR), mw_style_dim());

    lv_obj_t* box = lv_obj_create(s_addr_ovl.body);
    lv_obj_remove_style_all(box);
    lv_obj_add_style(box, mw_style_card(), LV_PART_MAIN);
    lv_obj_set_width(box, lv_pct(100));
    lv_obj_set_flex_grow(box, 1);
    lv_obj_add_flag(box, LV_OBJ_FLAG_SCROLLABLE);
    lv_obj_set_scroll_dir(box, LV_DIR_VER);
    mw_ui_label(box, addr, mw_style_mono());

    lv_obj_t* f = mw_ui_page_footer(&s_addr_ovl);
    lv_obj_t* b = mw_ui_button(f, TX(XSTR_CLOSE), addr_close_cb, NULL);
    lv_obj_set_flex_grow(b, 1);
    mw_ui_focus_add(&s_addr_ovl, box);
    mw_ui_focus_add(&s_addr_ovl, b);
    lv_group_focus_obj(box);
}

static void addr_row_cb(lv_event_t* e) {
    const int idx = (int)(intptr_t)lv_event_get_user_data(e);
    const mw_tx_summary_t* s = s_tx.sum;
    if (!s) return;
    const bool change = (idx == TX_ROW_CHANGE);
    if (!change && (idx < 0 || idx >= s->n_recipients)) return;
    if (change && !s->has_change) return;

    // Save the row we opened the overlay from, so closing it returns the
    // cursor here instead of the first row.
    mw_ui_focus_remember(MW_FOCUS_TX, idx);
    s_tx.last_row = MW_EVT_OBJ(e);
    s_tx.focus_id = idx;

    char title[48];
    char note[96];
    const char* note_p = NULL;
    if (change) {
        snprintf(title, sizeof(title), "%s", TX(XSTR_TX_CHANGE_ADDR));
        snprintf(note, sizeof(note), TX(XSTR_TX_OWNED_BY), (unsigned)s->change_major,
                 (unsigned)s->change_minor);
        addr_overlay_open(title, s->change, note, s->change_addr);
        return;
    }
    snprintf(title, sizeof(title), TX(XSTR_TX_RECIPIENT), idx + 1, (int)s->n_recipients);
    if (s->recipient_own[idx]) {
        snprintf(note, sizeof(note), TX(XSTR_TX_OWNED_BY), (unsigned)s->recipient_major[idx],
                 (unsigned)s->recipient_minor[idx]);
        note_p = note;
    }
    addr_overlay_open(title, s->amounts[idx], note_p, s->recipients[idx]);
}

// ---------------------------------------------------------------------------
static void tx_finish(int32_t r) {
    if (s_tx_done) return;
    s_tx_done = true;

    if (s_addr_ovl.scr) {
        mw_ui_page_destroy(&s_addr_ovl);
        addr_ovl_reset();
    }
    mw_ui_page_destroy(&s_tx.page);
    s_tx.page.scr        = NULL;
    s_tx.page.prev       = NULL;
    s_tx.page.group      = NULL;
    s_tx.page.prev_group = NULL;
    s_tx.last_row        = NULL;

    mw_ui_modal_done(r);
}

static void tx_sign_cb(lv_event_t* e)   { MW_UNUSED(e); tx_finish(1); }
static void tx_cancel_cb(lv_event_t* e) { MW_UNUSED(e); tx_finish(0); }
static void tx_escape(void* user)       { MW_UNUSED(user); tx_finish(0); }

static void kv_row(lv_obj_t* parent, const char* key, const char* value) {
    const mw_metrics_t* m = mw_metrics();
    lv_obj_t* row = lv_obj_create(parent);
    lv_obj_remove_style_all(row);
    lv_obj_set_width(row, lv_pct(100));
    lv_obj_set_height(row, LV_SIZE_CONTENT);
    lv_obj_set_flex_flow(row, LV_FLEX_FLOW_ROW);
    lv_obj_set_flex_align(row, LV_FLEX_ALIGN_SPACE_BETWEEN,
                          LV_FLEX_ALIGN_CENTER, LV_FLEX_ALIGN_CENTER);
    lv_obj_set_style_pad_column(row, m->gap, LV_PART_MAIN);
    MW_OBJ_CLEAR_FLAG(row, LV_OBJ_FLAG_SCROLLABLE);

    lv_obj_t* k = lv_label_create(row);
    lv_obj_add_style(k, mw_style_dim(), LV_PART_MAIN);
    lv_label_set_text(k, key);

    lv_obj_t* v = lv_label_create(row);
    lv_obj_add_style(v, mw_style_mono(), LV_PART_MAIN);
    lv_label_set_text(v, value);
}

// A tappable address row: icon, wrapped multi-line text.
static lv_obj_t* addr_row(tx_ctx_t* c, lv_obj_t* list, const char* icon, const char* text,
                          int id) {
    const mw_metrics_t* m = mw_metrics();
    lv_obj_t* row = mw_ui_list_row(list, icon, text, addr_row_cb, (void*)(intptr_t)id);
    if (row) {
        lv_obj_set_style_min_height(row, (lv_coord_t)(m->row_h * 3 / 2), LV_PART_MAIN);
        lv_obj_t* lbl = lv_obj_get_child(row, -1);
        if (lbl) {
            lv_label_set_long_mode(lbl, LV_LABEL_LONG_WRAP);
            lv_obj_set_flex_grow(lbl, 1);
        }
        mw_ui_focus_add(&c->page, row);
    }
    return row;
}

static void tx_build(void* arg) {
    tx_ctx_t* c = (tx_ctx_t*)arg;
    const mw_tx_summary_t* s = c->sum;
    const mw_metrics_t* m = mw_metrics();

    mw_ui_page_create(&c->page, T(STR_TX_SIGN), true);
    mw_ui_page_set_escape(&c->page, tx_escape, c);

    // Everything scrolls in one column; the footer stays put.
    lv_obj_t* list = mw_ui_list(c->page.body);
    lv_obj_set_style_pad_row(list, m->mono ? 0 : 4, LV_PART_MAIN);

    char buf[64];

    mw_format_amount(s->total_out, buf, sizeof(buf));
    kv_row(list, TX(XSTR_TX_TOTAL), buf);

    mw_format_amount(s->fee, buf, sizeof(buf));
    kv_row(list, T(STR_TX_FEE), buf);

    if (s->has_change) {
        mw_format_amount(s->change, buf, sizeof(buf));
        kv_row(list, TX(XSTR_TX_CHANGE), buf);
    } else {
        kv_row(list, TX(XSTR_TX_CHANGE), TX(XSTR_TX_CHANGE_NONE));
    }

    snprintf(buf, sizeof(buf), "%d / %d", (int)s->n_inputs, (int)s->n_outputs);
    kv_row(list, TX(XSTR_TX_IN_OUT), buf);

    if (s->n_dummy > 0) {
        snprintf(buf, sizeof(buf), TX(XSTR_TX_DUMMY), (unsigned)s->n_dummy);
        lv_obj_t* d = mw_ui_label(list, buf, mw_style_dim());
        if (d) lv_obj_set_width(d, lv_pct(100));
    }

    if (c->unlock_time != 0) {
        snprintf(buf, sizeof(buf), "%lu", (unsigned long)c->unlock_time);
        kv_row(list, TX(XSTR_TX_UNLOCK_TIME), buf);
    }

    const int head = m->compact ? 5 : 8;
    const int tail = m->compact ? 4 : 6;

    // A new review starts on Cancel; a rebuild returns to the row last opened.
    const int focus_target = c->focus_id;
    lv_obj_t* focus_row = NULL;

    char shortaddr[MW_ADDRESS_STR_MAX];
    char amt[40];
    char mark[48];
    char line[MW_ADDRESS_STR_MAX + 128];

    // --- every destination (TZ 12.3) ---------------------------------------
    for (int i = 0; i < (int)s->n_recipients && i < MW_MAX_DESTINATIONS; i++) {
        mw_address_shorten(s->recipients[i], shortaddr, sizeof(shortaddr), head, tail);
        mw_format_amount(s->amounts[i], amt, sizeof(amt));
        if (s->recipient_own[i]) {
            snprintf(mark, sizeof(mark), TX(XSTR_TX_OWN_MARK),
                     (unsigned)s->recipient_major[i], (unsigned)s->recipient_minor[i]);
            snprintf(line, sizeof(line), "%d/%d  %s\n%s\n%s", i + 1, (int)s->n_recipients,
                     shortaddr, mark, amt);
        } else {
            snprintf(line, sizeof(line), "%d/%d  %s\n%s", i + 1, (int)s->n_recipients,
                     shortaddr, amt);
        }
        lv_obj_t* row = addr_row(c, list,
                                 s->recipient_own[i] ? LV_SYMBOL_HOME : LV_SYMBOL_EYE_OPEN,
                                 line, i);
        if (i == focus_target && row) focus_row = row;
    }

    // --- the change, re-derived by the device ------------------------------
    if (s->has_change) {
        mw_address_shorten(s->change_addr, shortaddr, sizeof(shortaddr), head, tail);
        mw_format_amount(s->change, amt, sizeof(amt));
        snprintf(mark, sizeof(mark), TX(XSTR_TX_CHANGE_ROW), (unsigned)s->change_major,
                 (unsigned)s->change_minor);
        snprintf(line, sizeof(line), "%s\n%s\n%s", mark, shortaddr, amt);
        lv_obj_t* row = addr_row(c, list, LV_SYMBOL_HOME, line, TX_ROW_CHANGE);
        if (focus_target == TX_ROW_CHANGE && row) focus_row = row;
    }

    // --- confirm ----------------------------------------------------------
    lv_obj_t* f  = mw_ui_page_footer(&c->page);
    lv_obj_t* bc = mw_ui_button(f, T(STR_CANCEL),  tx_cancel_cb, NULL);
    lv_obj_t* bs = mw_ui_button(f, T(STR_TX_SIGN), tx_sign_cb,   NULL);
    lv_obj_set_flex_grow(bc, 1);
    lv_obj_set_flex_grow(bs, 1);
    lv_obj_set_style_bg_color(bs, mw_palette()->accent, LV_PART_MAIN);
    mw_ui_focus_add(&c->page, bc);
    mw_ui_focus_add(&c->page, bs);

    if (focus_row) {
        lv_group_focus_obj(focus_row);
        lv_obj_scroll_to_view(focus_row, LV_ANIM_OFF);
        c->last_row = focus_row;
    } else {
        lv_group_focus_obj(bc);          // никогда не пре-селектим "Подписать"
    }
}

bool mw_screen_tx_run(const mw_tx_summary_t* s, uint64_t unlock_time) {
    if (!s) return false;
    memset(&s_tx, 0, sizeof(s_tx));
    memset(&s_addr_ovl, 0, sizeof(s_addr_ovl));
    s_tx_done = false;
    s_tx.sum         = s;
    s_tx.unlock_time = unlock_time;
    s_tx.last_row    = NULL;
    s_tx.focus_id    = -1;
    return mw_ui_modal_call(tx_build, &s_tx) == 1;
}
