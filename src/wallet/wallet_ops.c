// Wallet operations on exchange files - see wallet_ops.h.
#include "wallet_ops.h"
#include "ki_cache.h"

#include "../monero/address.h"
#include "../monero/key_image.h"
#include "../monero/keys.h"
#include "../crypto/memzero.h"
#include "../hal/log.h"

#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

// ------------------------------------------------------------- plumbing
static void* default_alloc(size_t n) { return malloc(n); }
static void  default_free(void* p, size_t n) { if (p) { mw_memzero(p, n); free(p); } }

static mw_ops_alloc_t g_alloc = { default_alloc, default_free };

void mw_ops_set_allocator(const mw_ops_alloc_t* a)
{
    if (a && a->alloc && a->free) g_alloc = *a;
    else { g_alloc.alloc = default_alloc; g_alloc.free = default_free; }
}

static mw_err_t fail(mw_ops_error_t* er, mw_err_t err, const char* fmt, ...)
#if defined(__GNUC__)
    __attribute__((format(printf, 3, 4)))
#endif
    ;

static mw_err_t fail(mw_ops_error_t* er, mw_err_t err, const char* fmt, ...)
{
    if (er) {
        er->err = err;
        va_list ap;
        va_start(ap, fmt);
        vsnprintf(er->text, sizeof(er->text), fmt, ap);
        va_end(ap);
    }
    return err;
}

static void progress(const mw_ops_cb_t* cb, const char* stage, uint32_t done,
                     uint32_t total)
{
    if (cb && cb->progress) cb->progress(cb->user, stage, done, total);
}

size_t mw_ops_seal_offset(const mw_file_kind_t* kind)
{
    return kind->magic_len + (kind->has_version ? 1u : 0u) + MW_IV_LEN;
}

// Opens an envelope in place and turns the failure into a sentence.
static mw_err_t open_file(const mw_file_kind_t* kind, const char* what,
                          const mw_account_keys_t* keys, const mw_chacha_key* key,
                          uint8_t* file, size_t file_len, size_t* plain_len,
                          mw_ops_error_t* er)
{
    const mw_err_t e = mw_file_open_k(kind, file, file_len, keys, key, file, file_len,
                                      plain_len);
    switch (e) {
    case MW_OK:
        return MW_OK;
    case MW_ERR_MAGIC:
        return fail(er, e, "not a %s file", what);
    case MW_ERR_VERSION:
        return fail(er, e, "%s: unsupported file version", what);
    case MW_ERR_SIGNATURE:
    case MW_ERR_SUBGROUP:
        return fail(er, MW_ERR_SIGNATURE,
                    "%s was made by a different wallet: its signature does not "
                    "verify with this wallet's view key (wrong wallet or "
                    "passphrase variant?)", what);
    case MW_ERR_FORMAT:
        return fail(er, e, "%s: file truncated (%u bytes)", what, (unsigned)file_len);
    default:
        return fail(er, e, "%s: cannot open (%s)", what, mw_err_str(e));
    }
}

static mw_err_t diag_fail(mw_ops_error_t* er, mw_err_t e, const mw_ff_diag_t* d,
                          const char* fallback)
{
    if (d && d->what[0]) return fail(er, e, "%s", d->what);
    return fail(er, e, "%s (%s)", fallback, mw_err_str(e));
}

// ------------------------------------------------ outputs -> key images
mw_err_t mw_ops_outputs_inspect(const mw_account_keys_t* keys,
                                uint8_t* file, size_t file_len, size_t* plain_len,
                                mw_ki_export_info_t* info, mw_ops_error_t* er)
{
    mw_ff_diag_t d;
    mw_outputs_iter_t it;
    mw_err_t e;

    memset(&d, 0, sizeof d);
    if (!keys || !file || !plain_len || !info) return MW_ERR_INVALID_ARG;
    memset(info, 0, sizeof *info);
    if (keys->view_only)
        return fail(er, MW_ERR_NOT_SUPPORTED,
                    "a view-only wallet cannot compute key images");

    e = open_file(&MW_FILE_OUTPUTS, "Monero output export", keys, NULL, file, file_len,
                  plain_len, er);
    if (e != MW_OK) return e;

    e = mw_outputs_begin(&it, file, *plain_len, keys, &d);
    if (e != MW_OK) return diag_fail(er, e, &d, "outputs: bad header");

    for (;;) {
        mw_exported_output_t o;
        bool done = false;
        e = mw_outputs_next(&it, &o, &done, &d);
        if (e != MW_OK) return diag_fail(er, e, &d, "outputs: bad record");
        if (done) break;
        MW_LOGD("ops", "output %llu: tx index %u, subaddress %u/%u, additional keys %u%s",
                (unsigned long long)(it.offset + it.next - 1), (unsigned)o.internal_output_index,
                (unsigned)o.subaddr_major, (unsigned)o.subaddr_minor,
                (unsigned)o.additional_count, o.rct ? "" : ", pre-RingCT");
        if (mw_ki_cache_find_pub(&o.one_time_pubkey)) info->known++;
    }
    info->offset = it.offset;
    info->total = it.total;
    info->count = it.count;
    MW_LOGD("ops", "outputs file: offset %llu, hot wallet transfers %llu, records %llu",
            (unsigned long long)it.offset, (unsigned long long)it.total,
            (unsigned long long)it.count);
    return MW_OK;
}

// Key image cache inserts. A full cache (MW_KI_CACHE_MAX) never evicts - a
// forgotten key image would make a spent output look unknown - so the
// entries that did not fit are counted and reported instead of dropped in
// silence (audit round 1).
static uint32_t g_cache_overflow;

static void cache_put(const mw_ki_entry_t* ce)
{
    if (mw_ki_cache_put(ce) == MW_ERR_TOO_MANY) g_cache_overflow++;
}

static void cache_overflow_report(const char* what)
{
    if (g_cache_overflow == 0) return;
    MW_LOGE("ops", "%s: key image cache full (%u entries), %u key image(s) not recorded; "
                   "transactions spending those outputs will be refused",
            what, (unsigned)MW_KI_CACHE_MAX, (unsigned)g_cache_overflow);
}

uint32_t mw_ops_cache_overflow(void) { return g_cache_overflow; }

mw_err_t mw_ops_outputs_to_keyimages(const mw_account_keys_t* keys,
                                     const uint8_t* plain, size_t plain_len,
                                     uint8_t* out, size_t out_cap, size_t* out_len,
                                     const mw_ops_cb_t* cb, mw_ops_error_t* er)
{
    mw_ff_diag_t d;
    mw_outputs_iter_t it;
    mw_err_t e;

    memset(&d, 0, sizeof d);
    if (!keys || !plain || !out || !out_len) return MW_ERR_INVALID_ARG;
    *out_len = 0;
    g_cache_overflow = 0;

    e = mw_outputs_begin(&it, plain, plain_len, keys, &d);
    if (e != MW_OK) return diag_fail(er, e, &d, "outputs: bad header");

    const size_t off = mw_ops_seal_offset(&MW_FILE_KEYIMAGES);
    const size_t pt_len = 4u + 64u + (size_t)it.count * 96u;
    if (off + pt_len + MW_SIG_LEN > out_cap)
        return fail(er, MW_ERR_TOO_MANY, "key image file of %u bytes does not fit",
                    (unsigned)(off + pt_len + MW_SIG_LEN));

    // The plaintext is written where mw_file_seal() encrypts it in place.
    uint8_t* pt = out + off;
    const uint32_t offset32 = (uint32_t)it.offset;
    pt[0] = (uint8_t)offset32;         pt[1] = (uint8_t)(offset32 >> 8);
    pt[2] = (uint8_t)(offset32 >> 16); pt[3] = (uint8_t)(offset32 >> 24);
    memcpy(pt + 4, keys->pub.spend.b, 32);
    memcpy(pt + 36, keys->pub.view.b, 32);
    uint8_t* rec = pt + 68;

    const uint32_t total = (uint32_t)it.count;
    for (uint32_t i = 0; ; ++i) {
        mw_exported_output_t o;
        mw_exported_key_image_t ki;
        bool done = false;
        e = mw_outputs_next(&it, &o, &done, &d);
        if (e != MW_OK) return diag_fail(er, e, &d, "outputs: bad record");
        if (done) break;

        e = mw_key_image_from_output(keys, &o, &ki);
        if (e != MW_OK) {
            mw_memzero(out, off + pt_len);
            return fail(er, e == MW_ERR_KEY_MISMATCH ? MW_ERR_KEY_MISMATCH : e,
                        "output #%u (global index %llu, subaddress %u/%u) does not "
                        "belong to this wallet: %s", (unsigned)(it.offset + i),
                        (unsigned long long)o.global_output_index,
                        (unsigned)o.subaddr_major, (unsigned)o.subaddr_minor,
                        mw_err_str(e));
        }
        memcpy(rec, ki.image.b, 32);
        memcpy(rec + 32, ki.sig.c.b, 32);
        memcpy(rec + 64, ki.sig.r.b, 32);
        rec += 96;

        mw_ki_entry_t ce;
        memset(&ce, 0, sizeof ce);
        ce.out_pub = o.one_time_pubkey;
        ce.image = ki.image;
        ce.major = o.subaddr_major;
        ce.minor = o.subaddr_minor;
        ce.flags = MW_KI_F_EXPORTED;
        cache_put(&ce);                       // no-op when the cache is closed

        if ((i & 7u) == 0 || i + 1 == total) progress(cb, "key images", i + 1, total);
    }

    size_t sealed = 0;
    e = mw_file_seal(&MW_FILE_KEYIMAGES, pt, pt_len, keys, out, out_cap, &sealed);
    if (e != MW_OK) return fail(er, e, "cannot seal the key image file (%s)", mw_err_str(e));
    *out_len = sealed;
    (void)mw_ki_cache_save();
    cache_overflow_report("key image export");
    return MW_OK;
}

// ------------------------------------------------ unsigned -> signed
static void amount_str(uint64_t v, char* out, size_t cap)
{
    mw_format_amount(v, out, cap);
}

// Pre-sets the subaddress of every input the cache knows (saves the search).
static void preset_subaddresses(mw_transaction_t* tx)
{
    for (uint8_t j = 0; j < tx->n_inputs; ++j) {
        mw_tx_source_t* src = &tx->sources[j];
        const mw_ki_entry_t* ce = mw_ki_cache_find_pub(&src->ring[src->real_output_index].dest);
        if (ce) {
            src->subaddr_known = true;
            src->subaddr_major = ce->major;
            src->subaddr_minor = ce->minor;
        }
    }
}

// Offers the own subaddresses the key image cache knows to the destination
// check (extra own candidates and the bounds of its search window).
static void preset_own_hints(mw_transaction_t* tx)
{
    tx->n_own_hints = (uint8_t)mw_ki_cache_known_indices(
        tx->subaddr_account, tx->own_hint_major, tx->own_hint_minor, MW_MAX_OWN_HINTS,
        &tx->own_max_major, &tx->own_max_minor_acct, &tx->own_max_minor_main);
}

static mw_err_t load_tx(mw_sign_session_t* s, uint32_t i, mw_ops_error_t* er)
{
    mw_ff_diag_t d;
    memset(&d, 0, sizeof d);
    mw_err_t e = mw_unsigned_set_load_tx(&s->set, i, &s->tx, &d);
    if (e != MW_OK) return diag_fail(er, e, &d, "unsigned set: bad transaction");
    preset_subaddresses(&s->tx);
    preset_own_hints(&s->tx);
    return MW_OK;
}

// Turns a refusal of mw_tx_check_destinations() into a sentence (indices and
// amounts only, never keys or addresses).
static mw_err_t explain_check(mw_ops_error_t* er, mw_err_t e, uint32_t i,
                              const mw_transaction_t* tx)
{
    const mw_tx_check_info_t* c = &tx->check;
    const unsigned t = (unsigned)(i + 1), o = (unsigned)c->dest + 1u;
    char a1[32], a2[32];
    switch (c->reason) {
    case MW_TXR_BAD_POINT:
        if (c->dest == 0xFF)
            return fail(er, e, "tx %u: the change address is not a valid public key; refused",
                        t);
        return fail(er, e, "tx %u output %u: the address is not a valid public key; refused",
                    t, o);
    case MW_TXR_INPUTS:
        return fail(er, e, "tx %u input %u: not matched to a subaddress of this wallet; "
                           "refused", t, o);
    case MW_TXR_ACCOUNT:
        return fail(er, e, "tx %u input %u is in account %u but the file spends from "
                           "account %u - one account per transaction; refused", t, o,
                    (unsigned)c->major, (unsigned)tx->subaddr_account);
    case MW_TXR_HYBRID_OUR_VIEW:
        return fail(er, e, "tx %u output %u: hybrid address (this wallet's view key + a "
                           "foreign spend key) - the output would be spendable by whoever "
                           "made the file; refused", t, o);
    case MW_TXR_HYBRID_OUR_SPEND:
        return fail(er, e, "tx %u output %u: hybrid address (this wallet's spend key + a "
                           "foreign view key) - the output would be lost; refused", t, o);
    case MW_TXR_HYBRID_VIEW_LINKED:
        return fail(er, e, "tx %u output %u: possible hybrid address tied to this wallet's "
                           "view key, not a known subaddress (%u checked). If it is yours, "
                           "export outputs first; refused", t, o, (unsigned)c->searched);
    case MW_TXR_OWN_FLAG:
        return fail(er, e, "tx %u output %u: own address %u/%u with a wrong subaddress "
                           "flag - the wallet would not see the output; refused", t, o,
                    (unsigned)c->major, (unsigned)c->minor);
    case MW_TXR_CHANGE_NOT_OURS:
        return fail(er, e, "tx %u: the change address is not an address of this wallet - "
                           "possible change address substitution, refused (change must go "
                           "to %u/0)", t, (unsigned)c->major);
    case MW_TXR_CHANGE_INDEX:
        return fail(er, e, "tx %u: change to own address %u/%u instead of %u/0 - possible "
                           "change address substitution, refused", t, (unsigned)c->major,
                    (unsigned)c->minor, (unsigned)tx->subaddr_account);
    case MW_TXR_CHANGE_FLAG:
        return fail(er, e, "tx %u: change address %u/0 with a wrong subaddress flag; refused",
                    t, (unsigned)c->major);
    case MW_TXR_CHANGE_UNPAID:
        amount_str(c->claimed, a1, sizeof a1);
        amount_str(c->paid, a2, sizeof a2);
        return fail(er, e, "tx %u: claimed change %s XMR but the change address is paid "
                           "%s XMR; refused", t, a1, a2);
    default:
        return fail(er, e, "tx %u: destination check failed (%s)", t, mw_err_str(e));
    }
}

// What the review will show, for the host log: indices and amounts only.
static void log_summary(uint32_t i, const mw_transaction_t* tx, const mw_tx_summary_t* sum)
{
    char amt[32];
    for (uint8_t k = 0; k < tx->n_destinations; ++k) {
        const mw_tx_destination_t* d = &tx->destinations[k];
        if (d->kind == MW_DEST_OWN)
            MW_LOGI("ops", "tx %u output %u: own address %u/%u", (unsigned)(i + 1),
                    (unsigned)(k + 1), (unsigned)d->own_major, (unsigned)d->own_minor);
    }
    if (sum->has_change) {
        amount_str(sum->change, amt, sizeof amt);
        MW_LOGI("ops", "tx %u: change %s XMR -> this wallet %u/%u (re-derived)",
                (unsigned)(i + 1), amt, (unsigned)sum->change_major,
                (unsigned)sum->change_minor);
    } else {
        MW_LOGI("ops", "tx %u: no change", (unsigned)(i + 1));
    }
    if (sum->n_dummy)
        MW_LOGI("ops", "tx %u: %u dummy output(s)", (unsigned)(i + 1), (unsigned)sum->n_dummy);
    if (sum->high_fee) {
        amount_str(sum->fee, amt, sizeof amt);
        MW_LOGI("ops", "tx %u: high fee %s XMR", (unsigned)(i + 1), amt);
    }
}

mw_err_t mw_ops_unsigned_inspect(const mw_account_keys_t* keys, mw_network_t net,
                                 uint8_t* file, size_t file_len,
                                 mw_sign_session_t* s, bool require_known_ki,
                                 mw_tx_review_t* review, mw_ops_error_t* er)
{
    mw_ff_diag_t d;
    size_t plen = 0;
    mw_err_t e;

    memset(&d, 0, sizeof d);
    if (!keys || !file || !s || !review) return MW_ERR_INVALID_ARG;
    memset(review, 0, sizeof *review);
    if (keys->view_only)
        return fail(er, MW_ERR_NOT_SUPPORTED, "a view-only wallet cannot sign");

    // The envelope key is kept to seal the signed set (saves a second
    // cn_slow_hash).
    mw_file_key(keys, &s->file_key);
    s->has_file_key = true;
    e = open_file(&MW_FILE_UNSIGNED_TX, "Monero unsigned tx set", keys, &s->file_key,
                  file, file_len, &plen, er);
    if (e != MW_OK) {
        mw_memzero(&s->file_key, sizeof s->file_key);
        s->has_file_key = false;
        return e;
    }

    e = mw_unsigned_set_parse(file, plen, &s->set, &d);
    if (e != MW_OK) return diag_fail(er, e, &d, "unsigned set: malformed");

    review->n_txes = s->set.n_txes;
    review->new_transfers = s->set.nt_count;
    MW_LOGD("ops", "unsigned set v%u: %u transaction(s), %llu key images requested",
            (unsigned)s->set.version, (unsigned)s->set.n_txes,
            (unsigned long long)s->set.nt_count);

    uint32_t account = 0;
    for (uint32_t i = 0; i < s->set.n_txes; ++i) {
        e = load_tx(s, i, er);
        if (e != MW_OK) return e;
        mw_transaction_t* tx = &s->tx;
        if (i == 0) {
            account = tx->subaddr_account;
        } else if (tx->subaddr_account != account) {
            return fail(er, MW_ERR_KEY_MISMATCH, "tx %u spends from account %u, tx 1 from "
                        "account %u - one account per set; refused", (unsigned)(i + 1),
                        (unsigned)tx->subaddr_account, (unsigned)account);
        }
        MW_LOGD("ops", "tx %u: %u inputs (ring %u), %u outputs, fee %llu, change_dts %s, "
                "view tags %d, extra %u bytes, account %u, %u subaddress hints, %u known",
                (unsigned)(i + 1), (unsigned)tx->n_inputs, (unsigned)tx->sources[0].ring_size,
                (unsigned)tx->n_destinations, (unsigned long long)tx->fee,
                tx->has_change_addr ? "yes" : "no", (int)tx->use_view_tags,
                (unsigned)tx->extra_in_len, (unsigned)tx->subaddr_account,
                (unsigned)tx->n_subaddr_hints, (unsigned)tx->n_own_hints);

        for (uint8_t j = 0; j < tx->n_inputs; ++j) {
            mw_keyimage_t ki;
            char amt[32];
            amount_str(tx->sources[j].amount, amt, sizeof amt);
            e = mw_sign_input_key_image(keys, tx, j, &ki);
            if (e != MW_OK) {
                return fail(er, e, "tx %u input %u (%s XMR) does not belong to this "
                                   "wallet: %s", (unsigned)(i + 1), (unsigned)(j + 1),
                            amt, mw_err_str(e));
            }
            const mw_ki_entry_t* ce = mw_ki_cache_find_image(&ki);
            if (!ce && require_known_ki && mw_ki_cache_count() >= MW_KI_CACHE_MAX) {
                return fail(er, MW_ERR_TOO_MANY,
                            "tx %u input %u (%s XMR): key image unknown and the "
                            "device's key image cache of this wallet is full (%u "
                            "outputs) - it cannot track more outputs",
                            (unsigned)(i + 1), (unsigned)(j + 1), amt,
                            (unsigned)MW_KI_CACHE_MAX);
            }
            if (!ce && require_known_ki) {
                return fail(er, MW_ERR_NOT_SUPPORTED,
                            "tx %u input %u (%s XMR): key image not synchronised - "
                            "in Feather export ALL outputs, process them on the "
                            "device, import the key images, then create the "
                            "transaction again", (unsigned)(i + 1),
                            (unsigned)(j + 1), amt);
            }
            if (ce && (ce->flags & MW_KI_F_SPENT)) review->spent_before++;
            MW_LOGD("ops", "tx %u input %u: %s XMR, subaddress %u/%u, key image %s",
                    (unsigned)(i + 1), (unsigned)(j + 1), amt,
                    (unsigned)tx->sources[j].subaddr_major, (unsigned)tx->sources[j].subaddr_minor,
                    !ce ? "unknown" : (ce->flags & MW_KI_F_SPENT) ? "known, spent before" : "known");
        }

        e = mw_tx_check_destinations(keys, tx, NULL);
        if (e != MW_OK) return explain_check(er, e, i, tx);

        e = mw_tx_summarize(tx, net, &review->sum[i]);
        if (e != MW_OK)
            return fail(er, e, "tx %u: cannot summarise (%s)", (unsigned)(i + 1),
                        mw_err_str(e));
        log_summary(i, tx, &review->sum[i]);
        review->total_in += review->sum[i].total_in;
        review->total_out += review->sum[i].total_out;
        review->total_change += review->sum[i].change;
        review->total_fee += review->sum[i].fee;
        review->n_inputs += tx->n_inputs;
    }
    return MW_OK;
}

// Scratch for one signing session.
typedef struct {
    uint8_t*      blob[MW_MAX_TXES_PER_SET];
    size_t        blob_len[MW_MAX_TXES_PER_SET];
    mw_keyimage_t vin[MW_MAX_TXES_PER_SET][MW_MAX_INPUTS];
    uint8_t       n_vin[MW_MAX_TXES_PER_SET];
    uint64_t      fee[MW_MAX_TXES_PER_SET];
    mw_ki_pair_t* kis;
    uint32_t      n_kis;
    uint32_t      cap_kis;
    uint8_t*      rct;
} sign_scratch_t;

#define MW_OPS_BLOB_CAP  (72u * 1024u)
#define MW_OPS_RCT_CAP   (64u * 1024u)

typedef struct {
    const mw_ops_cb_t* cb;
    char               label[32];
} sign_cb_ctx_t;

static void sign_cb(mw_sign_stage_t stage, int permille, void* user)
{
    sign_cb_ctx_t* c = (sign_cb_ctx_t*)user;
    static const char* names[] = { "parse", "inputs", "outputs", "bulletproof+",
                                   "CLSAG", "serialize", "done" };
    char label[48];
    snprintf(label, sizeof label, "%s: %s", c->label,
             ((unsigned)stage <= MW_SIGN_STAGE_DONE) ? names[stage] : "?");
    progress(c->cb, label, (uint32_t)(permille < 0 ? 0 : permille), 1000);
}

static void scratch_free(sign_scratch_t* sc)
{
    for (int i = 0; i < MW_MAX_TXES_PER_SET; ++i)
        if (sc->blob[i]) g_alloc.free(sc->blob[i], MW_OPS_BLOB_CAP);
    if (sc->kis) g_alloc.free(sc->kis, (size_t)sc->cap_kis * sizeof(mw_ki_pair_t));
    if (sc->rct) g_alloc.free(sc->rct, MW_OPS_RCT_CAP);
    mw_memzero(sc, sizeof *sc);
}

mw_err_t mw_ops_unsigned_sign(const mw_account_keys_t* keys, mw_sign_session_t* s,
                              uint8_t* out, size_t out_cap, size_t* out_len,
                              const mw_ops_cb_t* cb, mw_ops_error_t* er)
{
    static sign_scratch_t sc;          // ~9 KiB of key images: off the stack
    mw_err_t e = MW_OK;

    if (!keys || !s || !out || !out_len || !s->set.data) return MW_ERR_INVALID_ARG;
    *out_len = 0;
    memset(&sc, 0, sizeof sc);
    g_cache_overflow = 0;

    const uint32_t n = s->set.n_txes;
    sc.cap_kis = n * MW_MAX_OUTPUTS + (uint32_t)s->set.nt_count;
    sc.kis = (mw_ki_pair_t*)g_alloc.alloc((size_t)(sc.cap_kis ? sc.cap_kis : 1) *
                                          sizeof(mw_ki_pair_t));
    sc.rct = (uint8_t*)g_alloc.alloc(MW_OPS_RCT_CAP);
    for (uint32_t i = 0; i < n; ++i) sc.blob[i] = (uint8_t*)g_alloc.alloc(MW_OPS_BLOB_CAP);
    if (!sc.kis || !sc.rct) { scratch_free(&sc); return fail(er, MW_ERR_MEMORY, "out of memory"); }
    for (uint32_t i = 0; i < n; ++i)
        if (!sc.blob[i]) { scratch_free(&sc); return fail(er, MW_ERR_MEMORY, "out of memory"); }

    // ---- sign every transaction ------------------------------------------
    for (uint32_t i = 0; i < n; ++i) {
        e = load_tx(s, i, er);
        if (e != MW_OK) goto done;
        mw_transaction_t* tx = &s->tx;

        sign_cb_ctx_t cctx;
        cctx.cb = cb;
        snprintf(cctx.label, sizeof cctx.label, "tx %u/%u", (unsigned)(i + 1), (unsigned)n);
        e = mw_sign_transaction(keys, tx, &s->sd, sign_cb, &cctx);
        if (e != MW_OK) {
            if (tx->check.reason != MW_TXR_NONE) explain_check(er, e, i, tx);
            else fail(er, e, "tx %u: signing failed (%s)", (unsigned)(i + 1), mw_err_str(e));
            goto done;
        }

        const size_t rct_len = mw_serialize_rct(tx, &s->sd, sc.rct, MW_OPS_RCT_CAP);
        if (rct_len == 0) {
            e = fail(er, MW_ERR_MEMORY, "tx %u: signature does not serialise",
                     (unsigned)(i + 1));
            goto done;
        }
        e = mw_build_signed_tx(tx, sc.rct, rct_len, sc.blob[i], MW_OPS_BLOB_CAP,
                               &sc.blob_len[i]);
        if (e != MW_OK) {
            fail(er, e, "tx %u: transaction does not serialise (%s)", (unsigned)(i + 1),
                 mw_err_str(e));
            goto done;
        }
        MW_LOGD("ops", "tx %u signed: %u bytes", (unsigned)(i + 1), (unsigned)sc.blob_len[i]);
        sc.fee[i] = tx->fee;
        sc.n_vin[i] = tx->n_inputs;
        for (uint8_t j = 0; j < tx->n_inputs; ++j) {
            const mw_tx_source_t* src = &tx->sources[j];
            sc.vin[i][j] = src->key_image;
            // Remember the input as spent by this device.
            mw_ki_entry_t ce;
            memset(&ce, 0, sizeof ce);
            ce.out_pub = src->ring[src->real_output_index].dest;
            ce.image = src->key_image;
            ce.major = src->subaddr_major;
            ce.minor = src->subaddr_minor;
            ce.flags = MW_KI_F_SPENT;
            cache_put(&ce);
        }
        for (uint8_t k = 0; k < tx->n_outputs; ++k) {
            if (!tx->out_ki_valid[k] || sc.n_kis >= sc.cap_kis) continue;
            sc.kis[sc.n_kis].out_pub = tx->outputs[k].out_pubkey;
            sc.kis[sc.n_kis].image = tx->out_ki[k];
            sc.n_kis++;
            mw_ki_entry_t ce;
            memset(&ce, 0, sizeof ce);
            ce.out_pub = tx->outputs[k].out_pubkey;
            ce.image = tx->out_ki[k];
            ce.major = tx->change_major;
            ce.minor = tx->change_minor;
            ce.flags = MW_KI_F_CHANGE;
            cache_put(&ce);
        }
        mw_memzero(&s->sd, sizeof s->sd);
    }

    // ---- key images the online wallet asked for (new_transfers) ----------
    {
        mw_outputs_iter_t it;
        mw_ff_diag_t d;
        memset(&d, 0, sizeof d);
        mw_unsigned_set_new_transfers(&s->set, &it);
        const uint32_t total = (uint32_t)it.count;
        for (uint32_t i = 0; ; ++i) {
            mw_exported_output_t o;
            mw_exported_key_image_t ki;
            bool done = false;
            e = mw_outputs_next(&it, &o, &done, &d);
            if (e != MW_OK) { diag_fail(er, e, &d, "requested transfers: bad record"); goto done; }
            if (done) break;
            e = mw_key_image_from_output(keys, &o, &ki);
            if (e != MW_OK) {
                fail(er, e, "requested output #%u (global index %llu) does not belong "
                            "to this wallet: %s", (unsigned)(it.offset + i),
                     (unsigned long long)o.global_output_index, mw_err_str(e));
                goto done;
            }
            if (sc.n_kis < sc.cap_kis) {
                sc.kis[sc.n_kis].out_pub = o.one_time_pubkey;
                sc.kis[sc.n_kis].image = ki.image;
                sc.n_kis++;
            }
            mw_ki_entry_t ce;
            memset(&ce, 0, sizeof ce);
            ce.out_pub = o.one_time_pubkey;
            ce.image = ki.image;
            ce.major = o.subaddr_major;
            ce.minor = o.subaddr_minor;
            ce.flags = MW_KI_F_EXPORTED;
            cache_put(&ce);
            if ((i & 7u) == 0 || i + 1 == total) progress(cb, "requested key images", i + 1, total);
        }
    }

    // ---- the signed set, sealed in place ----------------------------------
    {
        mw_signed_ptx_t ptx[MW_MAX_TXES_PER_SET];
        for (uint32_t i = 0; i < n; ++i) {
            ptx[i].tx_blob = sc.blob[i];
            ptx[i].tx_blob_len = sc.blob_len[i];
            ptx[i].fee = sc.fee[i];
            ptx[i].vin_key_images = sc.vin[i];
            ptx[i].n_vin = sc.n_vin[i];
        }
        const size_t off = mw_ops_seal_offset(&MW_FILE_SIGNED_TX);
        size_t need = 0;
        mw_build_signed_set(&s->set, ptx, n, sc.kis, sc.n_kis, NULL, 0, &need);
        if (off + need + MW_SIG_LEN > out_cap) {
            e = fail(er, MW_ERR_TOO_MANY, "signed set of %u bytes does not fit",
                     (unsigned)(off + need + MW_SIG_LEN));
            goto done;
        }
        size_t pt_len = 0;
        e = mw_build_signed_set(&s->set, ptx, n, sc.kis, sc.n_kis, out + off,
                                out_cap - off - MW_SIG_LEN, &pt_len);
        if (e != MW_OK) {
            fail(er, e, "cannot build the signed set (%s)", mw_err_str(e));
            goto done;
        }
        size_t sealed = 0;
        progress(cb, "sealing", 0, 1);
        e = mw_file_seal_k(&MW_FILE_SIGNED_TX, out + off, pt_len, keys,
                           s->has_file_key ? &s->file_key : NULL, out, out_cap, &sealed);
        if (e != MW_OK) {
            fail(er, e, "cannot seal the signed set (%s)", mw_err_str(e));
            goto done;
        }
        *out_len = sealed;
        MW_LOGD("ops", "signed set: %u bytes, %u key images for the online wallet",
                (unsigned)sealed, (unsigned)sc.n_kis);
    }
    (void)mw_ki_cache_save();
    cache_overflow_report("signing");

done:
    if (e != MW_OK) mw_memzero(out, out_cap < 4096 ? out_cap : 4096);
    mw_memzero(&s->sd, sizeof s->sd);
    // The last transaction's tx secret key, input/output masks and one-time
    // key material: in the signed set now, not needed in RAM any more.
    mw_memzero(&s->tx, sizeof s->tx);
    mw_memzero(&s->file_key, sizeof s->file_key);
    s->has_file_key = false;
    scratch_free(&sc);
    return e;
}

// ------------------------------------------------------------ export
static size_t json_escape(const char* in, char* out, size_t cap)
{
    size_t n = 0;
    for (const unsigned char* p = (const unsigned char*)in; *p && n + 7 < cap; ++p) {
        if (*p == '"' || *p == '\\') { out[n++] = '\\'; out[n++] = (char)*p; }
        else if (*p < 0x20) n += (size_t)snprintf(out + n, cap - n, "\\u%04x", *p);
        else out[n++] = (char)*p;
    }
    out[n] = '\0';
    return n;
}

mw_err_t mw_ops_wallet_export(const mw_account_keys_t* keys, mw_network_t net,
                              const char* wallet_name, uint32_t restore_height,
                              bool with_view_key, char* out, size_t cap,
                              size_t* len)
{
    mw_address_t addr;
    char a[MW_ADDRESS_STR_MAX];
    char name[3 * 32 + 8];
    static const char* nets[] = { "mainnet", "testnet", "stagenet" };

    if (!keys || !out || !len || cap < 64) return MW_ERR_INVALID_ARG;
    mw_err_t e = mw_address_from_keys(keys, net, &addr);
    if (e == MW_OK) e = mw_address_encode(&addr, a, sizeof a);
    if (e != MW_OK) return e;
    json_escape(wallet_name ? wallet_name : "", name, sizeof name);

    int n = snprintf(out, cap,
                     "{\n  \"version\": 1,\n  \"wallet\": \"%s\",\n  \"network\": \"%s\",\n"
                     "  \"address\": \"%s\",\n  \"restore_height\": %lu",
                     name, ((unsigned)net <= 2u) ? nets[net] : "mainnet", a,
                     (unsigned long)restore_height);
    if (n < 0 || (size_t)n >= cap) return MW_ERR_TOO_MANY;
    if (with_view_key) {
        static const char hexd[] = "0123456789abcdef";
        char hex[65];
        for (int i = 0; i < 32; ++i) {
            hex[2 * i] = hexd[keys->sec.view.b[i] >> 4];
            hex[2 * i + 1] = hexd[keys->sec.view.b[i] & 0x0f];
        }
        hex[64] = '\0';
        const int m = snprintf(out + n, cap - (size_t)n, ",\n  \"view_key\": \"%s\"", hex);
        mw_memzero(hex, sizeof hex);
        if (m < 0 || (size_t)(n + m) >= cap) { mw_memzero(out, cap); return MW_ERR_TOO_MANY; }
        n += m;
    }
    const int m = snprintf(out + n, cap - (size_t)n, "\n}\n");
    if (m < 0 || (size_t)(n + m) >= cap) { mw_memzero(out, cap); return MW_ERR_TOO_MANY; }
    *len = (size_t)(n + m);
    return MW_OK;
}
