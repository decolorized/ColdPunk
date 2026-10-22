// Key image cache - see ki_cache.h.
//
// v9.2: one sealed container per user ("account"), next to its directory:
//
//     file      := iv(16) || tag(16) || AES-GCM(plain), label "mw.kic.v1"
//     plain     := header(32) || sections || zero padding
//     header    := "MWKS" || version(1) || 0(3) || generation(u32) ||
//                  payload length(u32) || section count(u32) || 0(12)
//     section   := wallet id(u32) || variant(1) || kind(1) || 0(2) ||
//                  account(32) || count(u32) || count * entry
//     account   := keccak256("mw.ki.account" || spend_pub || view_pub)
//     kind 0    key images; entry := out_pub(32) || image(32) || major(u32) ||
//               minor(u32) || flags(1) || amount(u64) || bal(1) ||
//               tx_pub(32) || global index(u64) || transfer index + 1(u32) ||
//               key image signature(64)
//               (version 3, 0.3.5 before "all saved key images": without
//               the transfer index and the signature;
//               version 2, 0.3..0.3.4: without tx_pub and the index;
//               version 1, before 0.3: without amount and bal either)
//     kind 1    signed transactions (v0.3); entry := seq(u32) || sent(u64) ||
//               fee(u64) || change(u64) || recipients(1) || own only(1) ||
//               0(2) || address start(16)
//   Version 1 and 2 containers are read and written back as version 3.
//
// The file is named "c" + the 24 hex digits of the user's directory name
// (wallet_store.h) and is at least 64 KiB; it grows in 64 KiB steps when the
// caches need more, so the number of key images is limited only by flash and
// RAM (a container larger than 64 KiB tells a flash dump that this slot is
// a user that holds many outputs - the price of never refusing one). Every
// slot of the device has one: the decoys' are random.
//
// Rollback (audit round 1): every save bumps the generation and records it
// in the user's sealed directory (mw_wallet_store_ki_gen). A container whose
// generation is BELOW the recorded one is an old copy put back - it would
// hide SPENT flags - and is refused: the caches start empty (the next key
// image export rebuilds them) and mw_ki_cache_rolled_back() reports it. This
// stops a file swap, not an attacker who puts back the whole flash image.
//
// Older formats are imported once (mw_ki_cache_import_old): per-wallet
// files "ki_<id>_<v>.bin" with NVS generations "kig<id><v>" (before v9) and
// "k<24 hex>" (v9.1), both "MWKI" records sealed under "mw.ki.v1.<id>.<v>".
#include "ki_cache.h"
#include "file_store.h"
#include "secure_storage.h"
#include "wallet_store.h"

#include "../crypto/hash.h"
#include "../crypto/memzero.h"
#include "../crypto/random.h"
#include "../hal/log.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#if defined(__has_include)
#  if __has_include(<esp_heap_caps.h>)
#    include <esp_heap_caps.h>
#    define MW_KI_PSRAM 1
#  endif
#endif

#define KS_MAGIC      "MWKS"
#define KS_VERSION    4
#define KS_LABEL      "mw.kic.v1"
#define KS_HDR        32
#define KS_SEC_HDR    (4 + 1 + 3 + 32 + 4)
#define KI_ENTRY      (32 + 32 + 4 + 4 + 1)       // version 1, and the old files
#define KI_ENTRY2     (KI_ENTRY + 8 + 1)
#define KI_ENTRY3     (KI_ENTRY2 + 32 + 8)
#define KI_ENTRY4     (KI_ENTRY3 + 4 + 64)
#define TX_ENTRY      48
#define SEC_KI        0
#define SEC_TX        1
#define KS_SEAL_HDR   32

// The per-wallet record of older firmware ("MWKI").
#define KI_MAGIC      "MWKI"
#define KI_VERSION    1
#define KI_HDR        (4 + 1 + 3 + 32 + 4)

// Platform blob API (secure_storage.cpp / secure_storage_host.c).
mw_err_t mw_store_blob_read(const char* key, void* out, size_t cap, size_t* len_out);
mw_err_t mw_store_blob_erase(const char* key);

static struct {
    bool           open;
    bool           rolled_back;  // the container was older than the directory says
    uint32_t       wallet_id;
    uint8_t        variant;
    uint8_t        account[32];
    uint32_t       count;
    uint32_t       cap;          // entries allocated in e
    bool           dirty;
    mw_ki_entry_t* e;
    mw_ki_tx_t*    tx;           // MW_KI_TX_MAX when allocated
    uint32_t       ntx;
} g;

static bool balance_on(void)
{
    return !(mw_wallet_store_opts() & MW_ACC_OPT_NO_BALANCE);
}

static void* ki_alloc(size_t n)
{
    if (n == 0) n = 1;
#if defined(MW_KI_PSRAM)
    void* p = heap_caps_malloc(n, MALLOC_CAP_SPIRAM | MALLOC_CAP_8BIT);
    if (p) return p;
#endif
    return malloc(n);
}

static void ki_free(void* p, size_t n)
{
    if (!p) return;
    mw_memzero(p, n ? n : 1);
    free(p);
}

static void put_u32(uint8_t* p, uint32_t v)
{
    p[0] = (uint8_t)v; p[1] = (uint8_t)(v >> 8);
    p[2] = (uint8_t)(v >> 16); p[3] = (uint8_t)(v >> 24);
}

static uint32_t get_u32(const uint8_t* p)
{
    return (uint32_t)p[0] | ((uint32_t)p[1] << 8) | ((uint32_t)p[2] << 16) |
           ((uint32_t)p[3] << 24);
}

static void account_hash(const mw_account_keys_t* keys, uint8_t out[32])
{
    uint8_t buf[13 + 64];
    memcpy(buf, "mw.ki.account", 13);
    memcpy(buf + 13, keys->pub.spend.b, 32);
    memcpy(buf + 45, keys->pub.view.b, 32);
    mw_keccak256(buf, sizeof(buf), out);
}

static void put_entry(uint8_t* p, const mw_ki_entry_t* e)
{
    memcpy(p, e->out_pub.b, 32);
    memcpy(p + 32, e->image.b, 32);
    put_u32(p + 64, e->major);
    put_u32(p + 68, e->minor);
    p[72] = e->flags;
}

static void get_entry(const uint8_t* p, mw_ki_entry_t* e)
{
    memset(e, 0, sizeof *e);
    memcpy(e->out_pub.b, p, 32);
    memcpy(e->image.b, p + 32, 32);
    e->major = get_u32(p + 64);
    e->minor = get_u32(p + 68);
    e->flags = p[72];
}

static void put_u64(uint8_t* p, uint64_t v)
{
    put_u32(p, (uint32_t)v);
    put_u32(p + 4, (uint32_t)(v >> 32));
}
static uint64_t get_u64(const uint8_t* p)
{
    return (uint64_t)get_u32(p) | ((uint64_t)get_u32(p + 4) << 32);
}

// Version 2 entries.
static void put_entry2(uint8_t* p, const mw_ki_entry_t* e)
{
    put_entry(p, e);
    put_u64(p + 73, e->amount);
    p[81] = e->bal;
}
static void get_entry2(const uint8_t* p, mw_ki_entry_t* e)
{
    get_entry(p, e);
    e->amount = get_u64(p + 73);
    e->bal = p[81];
}

// Version 3 entries (0.3.5).
static void put_entry3(uint8_t* p, const mw_ki_entry_t* e)
{
    put_entry2(p, e);
    memcpy(p + 82, e->tx_pub.b, 32);
    put_u64(p + 114, e->gidx);
}
static void put_entry4(uint8_t* p, const mw_ki_entry_t* e)
{
    put_entry3(p, e);
    put_u32(p + 122, e->tidx1);
    memcpy(p + 126, e->sig, 64);
}
static void get_entry3(const uint8_t* p, mw_ki_entry_t* e)
{
    get_entry2(p, e);
    memcpy(e->tx_pub.b, p + 82, 32);
    e->gidx = get_u64(p + 114);
}
static void get_entry4(const uint8_t* p, mw_ki_entry_t* e)
{
    get_entry3(p, e);
    e->tidx1 = get_u32(p + 122);
    memcpy(e->sig, p + 126, 64);
}
static void get_entry_v(uint8_t version, const uint8_t* p, mw_ki_entry_t* e)
{
    if (version == 1)      get_entry(p, e);
    else if (version == 2) get_entry2(p, e);
    else if (version == 3) get_entry3(p, e);
    else                   get_entry4(p, e);
}

static void put_tx(uint8_t* p, const mw_ki_tx_t* t)
{
    memset(p, 0, TX_ENTRY);
    put_u32(p, t->seq);
    put_u64(p + 4, t->sent);
    put_u64(p + 12, t->fee);
    put_u64(p + 20, t->change);
    p[28] = t->n_recipients;
    p[29] = t->own_only;
    for (size_t i = 0; i < MW_KI_TX_ADDR && t->addr[i]; i++) p[32 + i] = (uint8_t)t->addr[i];
}
static void get_tx(const uint8_t* p, mw_ki_tx_t* t)
{
    memset(t, 0, sizeof *t);
    t->seq = get_u32(p);
    t->sent = get_u64(p + 4);
    t->fee = get_u64(p + 12);
    t->change = get_u64(p + 20);
    t->n_recipients = p[28];
    t->own_only = p[29];
    memcpy(t->addr, p + 32, MW_KI_TX_ADDR);
    t->addr[MW_KI_TX_ADDR] = 0;
}

// Room for `need` entries in g.e (grows by doubling, in PSRAM when there is).
static bool grow(uint32_t need)
{
    if (need <= g.cap) return true;
    uint32_t cap = g.cap ? g.cap : 256;
    while (cap < need) {
        if (cap > 0x7FFFFFFFu / 2) return false;
        cap *= 2;
    }
    const size_t bytes = (size_t)cap * sizeof(mw_ki_entry_t);
    if (bytes / sizeof(mw_ki_entry_t) != cap) return false;
    mw_ki_entry_t* n = (mw_ki_entry_t*)ki_alloc(bytes);
    if (!n) return false;
    memset(n, 0, bytes);
    if (g.e) {
        memcpy(n, g.e, (size_t)g.count * sizeof(mw_ki_entry_t));
        ki_free(g.e, (size_t)g.cap * sizeof(mw_ki_entry_t));
    }
    g.e = n;
    g.cap = cap;
    return true;
}

// ---------------------------------------------------------------------------
// The container
// ---------------------------------------------------------------------------
void mw_ki_store_file_name(char* out, size_t cap)
{
    char hex[MW_SLOT_HEX + 1];
    if (!out || !cap) return;
    out[0] = '\0';
    if (cap < MW_SLOT_HEX + 2 || mw_wallet_store_slot_hex(hex) != MW_OK) return;
    snprintf(out, cap, "c%s", hex);
}

static size_t file_size_for(size_t payload)
{
    const size_t need = KS_SEAL_HDR + KS_HDR + payload;
    const size_t sz = (need + MW_KI_STORE_STEP - 1) / MW_KI_STORE_STEP * MW_KI_STORE_STEP;
    return sz < MW_KI_STORE_STEP ? MW_KI_STORE_STEP : sz;
}

typedef struct {
    uint8_t* plain;          // decrypted container (NULL: none)
    size_t   plain_len;      // bytes allocated / sealed
    uint8_t  version;        // 1 or 2
    uint32_t gen;
    uint32_t payload;        // section bytes after the header
    uint32_t sections;
} store_t;

static void store_free(store_t* s)
{
    ki_free(s->plain, s->plain_len);
    memset(s, 0, sizeof *s);
}

// Reads and opens a container (under the installed key). A missing file is
// an empty store (MW_OK); one that does not open or parse is MW_ERR_DECRYPT /
// MW_ERR_FORMAT with an empty store; MW_ERR_IO / MW_ERR_MEMORY are faults
// (the file may be fine).
static mw_err_t store_read(const char* name, store_t* s)
{
    size_t size = 0, got = 0;
    memset(s, 0, sizeof *s);
    if (!name[0]) return MW_ERR_NOT_SUPPORTED;
    if (mw_fstore_size(name, &size) != MW_OK) return MW_OK;
    if (size < KS_SEAL_HDR + KS_HDR) return MW_ERR_FORMAT;
    const size_t pl = size - KS_SEAL_HDR;
    uint8_t* file = (uint8_t*)ki_alloc(size);
    uint8_t* plain = (uint8_t*)ki_alloc(pl);
    if (!file || !plain) {
        ki_free(file, size);
        ki_free(plain, pl);
        return MW_ERR_MEMORY;
    }
    mw_err_t e = mw_fstore_read(name, file, size, &got);
    if (e != MW_OK || got != size) e = MW_ERR_IO;     // a read fault: not "damaged"
    if (e == MW_OK) e = mw_unseal(KS_LABEL, file + KS_SEAL_HDR, pl, file, file + 16, plain, pl);
    ki_free(file, size);
    if (e == MW_OK && (memcmp(plain, KS_MAGIC, 4) != 0 || plain[4] < 1 || plain[4] > KS_VERSION))
        e = MW_ERR_FORMAT;
    if (e == MW_OK) {
        s->version = plain[4];
        s->gen = get_u32(plain + 8);
        s->payload = get_u32(plain + 12);
        s->sections = get_u32(plain + 16);
        if ((size_t)s->payload > pl - KS_HDR) e = MW_ERR_FORMAT;
    }
    if (e != MW_OK) {
        ki_free(plain, pl);
        memset(s, 0, sizeof *s);
        return e;
    }
    s->plain = plain;
    s->plain_len = pl;
    return MW_OK;
}

// Entry size of a section of `kind` in a container of `version`; 0 for a
// kind this firmware does not know.
static size_t entry_len(uint8_t version, uint8_t kind)
{
    if (kind == SEC_KI) return version == 1 ? KI_ENTRY : version == 2 ? KI_ENTRY2 :
                                version == 3 ? KI_ENTRY3 : KI_ENTRY4;
    if (kind == SEC_TX && version >= 2) return TX_ENTRY;
    return 0;
}

// Walks the sections: calls fn for each until it returns false. false when
// a section does not fit (damaged payload).
typedef bool (*sec_fn)(const uint8_t* sec, uint32_t id, uint8_t variant, uint8_t kind,
                       uint32_t count, size_t sec_len, uint8_t version, void* ctx);
static bool store_walk(const store_t* s, sec_fn fn, void* ctx)
{
    if (!s->plain) return true;
    size_t off = KS_HDR;
    const size_t end = KS_HDR + (size_t)s->payload;
    for (uint32_t i = 0; i < s->sections; i++) {
        if (off + KS_SEC_HDR > end) return false;
        const uint8_t* sec = s->plain + off;
        const uint8_t kind = s->version == 1 ? SEC_KI : sec[5];
        const size_t el = entry_len(s->version, kind);
        if (!el) return false;
        const uint32_t count = get_u32(sec + 40);
        if (count > (end - off - KS_SEC_HDR) / el) return false;
        const size_t len = KS_SEC_HDR + (size_t)count * el;
        if (!fn(sec, get_u32(sec), sec[4], kind, count, len, s->version, ctx)) break;
        off += len;
    }
    return true;
}

typedef struct {
    uint32_t id;
    uint8_t  variant;        // 0xFF: both variants of id
    bool     active;
} skip_t;

typedef struct {
    uint8_t* out;
    size_t   off;
    uint32_t sections;
    skip_t   skip;
    bool     measure;        // only count the bytes
    bool     strip;          // drop amounts and transaction lists (estimate off)
} copy_ctx_t;

// Copies a section into a version-3 container (older ones are widened; with
// `strip` the amounts go and transaction lists are left out).
static bool copy_sec(const uint8_t* sec, uint32_t id, uint8_t variant, uint8_t kind,
                     uint32_t count, size_t len, uint8_t version, void* ctx)
{
    copy_ctx_t* c = (copy_ctx_t*)ctx;
    if (c->skip.active && id == c->skip.id &&
        (c->skip.variant == 0xFF || c->skip.variant == variant)) return true;
    if (kind == SEC_TX && c->strip) return true;
    if (kind == SEC_KI && (version != KS_VERSION || c->strip)) {
        const size_t el = entry_len(version, SEC_KI);
        const size_t out_len = KS_SEC_HDR + (size_t)count * KI_ENTRY4;
        if (!c->measure) {
            uint8_t* o = c->out + c->off;
            memcpy(o, sec, KS_SEC_HDR);
            o[5] = SEC_KI;
            o[6] = o[7] = 0;
            for (uint32_t i = 0; i < count; i++) {
                mw_ki_entry_t e;
                get_entry_v(version, sec + KS_SEC_HDR + i * el, &e);
                if (c->strip) { e.amount = 0; e.bal = 0; }
                put_entry4(o + KS_SEC_HDR + i * KI_ENTRY4, &e);
                mw_memzero(&e, sizeof e);
            }
        }
        c->off += out_len;
        c->sections++;
        return true;
    }
    if (!c->measure) memcpy(c->out + c->off, sec, len);
    c->off += len;
    c->sections++;
    return true;
}

// Writes a container: the sections of `old` except those `skip` names, then
// the open cache when `add`.
static mw_err_t store_write_x(const char* name, const store_t* old, skip_t skip, bool add,
                              uint32_t gen, bool strip)
{
    copy_ctx_t m = { NULL, KS_HDR, 0, skip, true, strip };
    if (!name[0]) return MW_ERR_NOT_SUPPORTED;
    if (!store_walk(old, copy_sec, &m)) {
        // A damaged payload: what follows the damage is lost, the rest kept.
        MW_LOGE("kicache", "key image cache container damaged: partly dropped");
    }
    size_t payload = m.off - KS_HDR;
    if (add && g.count) payload += KS_SEC_HDR + (size_t)g.count * KI_ENTRY4;
    if (add && g.ntx) payload += KS_SEC_HDR + (size_t)g.ntx * TX_ENTRY;
    const size_t size = file_size_for(payload);
    const size_t pl = size - KS_SEAL_HDR;
    {
        // Growing must leave MW_KI_STORE_RESERVE free, so that the other
        // accounts' directories and containers can always be rewritten.
        size_t cur = 0, avail = 0;
        if (mw_fstore_size(name, &cur) != MW_OK) cur = 0;
        if (size > cur && mw_fstore_free_bytes(&avail) == MW_OK &&
            avail < size + MW_KI_STORE_RESERVE) {
            MW_LOGE("kicache", "storage full: the key image cache cannot grow to %u KiB",
                    (unsigned)(size / 1024u));
            return MW_ERR_TOO_MANY;
        }
    }
    uint8_t* plain = (uint8_t*)ki_alloc(pl);
    uint8_t* file = (uint8_t*)ki_alloc(size);
    if (!plain || !file) {
        ki_free(plain, pl);
        ki_free(file, size);
        return MW_ERR_MEMORY;
    }
    memset(plain, 0, pl);
    copy_ctx_t c = { plain, KS_HDR, 0, skip, false, strip };
    (void)store_walk(old, copy_sec, &c);
    if (add && g.count) {
        uint8_t* p = plain + c.off;
        put_u32(p, g.wallet_id);
        p[4] = g.variant;
        p[5] = SEC_KI;
        memcpy(p + 8, g.account, 32);
        put_u32(p + 40, g.count);
        p += KS_SEC_HDR;
        for (uint32_t i = 0; i < g.count; i++, p += KI_ENTRY4) put_entry4(p, &g.e[i]);
        c.off += KS_SEC_HDR + (size_t)g.count * KI_ENTRY4;
        c.sections++;
    }
    if (add && g.ntx) {
        uint8_t* p = plain + c.off;
        put_u32(p, g.wallet_id);
        p[4] = g.variant;
        p[5] = SEC_TX;
        memcpy(p + 8, g.account, 32);
        put_u32(p + 40, g.ntx);
        p += KS_SEC_HDR;
        for (uint32_t i = 0; i < g.ntx; i++, p += TX_ENTRY) put_tx(p, &g.tx[i]);
        c.off += KS_SEC_HDR + (size_t)g.ntx * TX_ENTRY;
        c.sections++;
    }
    memcpy(plain, KS_MAGIC, 4);
    plain[4] = KS_VERSION;
    put_u32(plain + 8, gen);
    put_u32(plain + 12, (uint32_t)(c.off - KS_HDR));
    put_u32(plain + 16, c.sections);
    mw_err_t e = mw_seal(KS_LABEL, plain, pl, file, file + 16, file + KS_SEAL_HDR, pl);
    if (e == MW_OK) e = mw_fstore_write(name, file, size);
    ki_free(plain, pl);
    ki_free(file, size);
    return e;
}

static mw_err_t store_write(const char* name, const store_t* old, skip_t skip, bool add,
                            uint32_t gen)
{
    return store_write_x(name, old, skip, add, gen, false);
}

// Rewrites the container of the installed key with a new generation:
// `skip` dropped, the open cache added when `add`. A container that is an
// old copy, or does not open, keeps none of its sections.
static mw_err_t store_update_x(skip_t skip, bool add, bool strip)
{
    char name[MW_FSTORE_NAME_MAX + 1];
    store_t s;
    mw_ki_store_file_name(name, sizeof name);
    if (!name[0]) return MW_ERR_NOT_SUPPORTED;
    mw_err_t e = store_read(name, &s);
    if (e == MW_ERR_MEMORY || e == MW_ERR_IO) return e;   // a fault: keep the file
    const uint32_t want = mw_wallet_store_ki_gen();
    if (e != MW_OK || s.gen < want) store_free(&s);
    uint32_t gen = (s.gen > want ? s.gen : want) + 1u;
    if (gen == 0) gen = 0xFFFFFFFFu;
    e = store_write_x(name, &s, skip, add, gen, strip);
    store_free(&s);
    // File first, then the directory: a cut in between leaves the container
    // one generation ahead, which loads fine.
    if (e == MW_OK) e = mw_wallet_store_ki_gen_set(gen);
    return e;
}

static mw_err_t store_update(skip_t skip, bool add)
{
    return store_update_x(skip, add, false);
}

mw_err_t mw_ki_store_create_gen(uint32_t gen)
{
    char name[MW_FSTORE_NAME_MAX + 1];
    size_t len = 0;
    store_t empty;
    skip_t none = { 0, 0, false };
    mw_ki_store_file_name(name, sizeof name);
    if (!name[0]) return MW_ERR_NOT_SUPPORTED;
    if (mw_fstore_size(name, &len) == MW_OK) return MW_OK;
    memset(&empty, 0, sizeof empty);
    return store_write(name, &empty, none, false, gen);
}

mw_err_t mw_ki_store_create(void)
{
    return mw_ki_store_create_gen(mw_wallet_store_ki_gen());
}

mw_err_t mw_ki_store_remove(void)
{
    char name[MW_FSTORE_NAME_MAX + 1];
    mw_ki_cache_close();
    mw_ki_store_file_name(name, sizeof name);
    if (!name[0]) return MW_ERR_NOT_SUPPORTED;
    return mw_fstore_remove(name);
}

mw_err_t mw_ki_store_move(const uint8_t old_key[32], const uint8_t new_key[32])
{
    char from[MW_FSTORE_NAME_MAX + 1], to[MW_FSTORE_NAME_MAX + 1];
    store_t s;
    skip_t none = { 0, 0, false };
    size_t len = 0;
    if (!old_key || !new_key) return MW_ERR_INVALID_ARG;
    mw_ki_cache_close();
    (void)mw_secure_user_key_set(old_key);
    mw_ki_store_file_name(from, sizeof from);
    mw_err_t e = store_read(from, &s);
    (void)mw_secure_user_key_set(new_key);
    mw_ki_store_file_name(to, sizeof to);
    if (!from[0] || !to[0] || strcmp(from, to) == 0) { store_free(&s); return MW_OK; }
    if (e == MW_ERR_MEMORY || e == MW_ERR_IO) { store_free(&s); return e; }  // retried later
    const bool had = s.plain != NULL;
    if (had) {
        e = store_write(to, &s, none, false, s.gen);
    } else if (e != MW_OK) {
        MW_LOGE("kicache", "key image caches not moved (%s): dropped", mw_err_str(e));
        e = MW_OK;
    }
    store_free(&s);
    if (e != MW_OK) return e;                // the old one stays; retried later
    e = mw_ki_store_create_gen(0);           // an empty one when nothing was moved
    if (e == MW_OK && mw_fstore_size(from, &len) == MW_OK) e = mw_fstore_remove(from);
    return e;
}

size_t mw_ki_store_size(void)
{
    char name[MW_FSTORE_NAME_MAX + 1];
    size_t len = 0;
    mw_ki_store_file_name(name, sizeof name);
    if (!name[0] || mw_fstore_size(name, &len) != MW_OK) return 0;
    return len;
}

// ---------------------------------------------------------------------------
// The open cache
// ---------------------------------------------------------------------------
typedef struct {
    uint32_t id;
    uint8_t  variant;
} find_ctx_t;

static bool tx_alloc(void)
{
    if (!g.tx) g.tx = (mw_ki_tx_t*)ki_alloc(sizeof(mw_ki_tx_t) * MW_KI_TX_MAX);
    if (g.tx && g.ntx == 0) memset(g.tx, 0, sizeof(mw_ki_tx_t) * MW_KI_TX_MAX);
    return g.tx != NULL;
}

static bool load_sec(const uint8_t* sec, uint32_t id, uint8_t variant, uint8_t kind,
                     uint32_t count, size_t len, uint8_t version, void* ctx)
{
    find_ctx_t* f = (find_ctx_t*)ctx;
    (void)len;
    if (id != f->id || variant != f->variant) return true;
    if (memcmp(sec + 8, g.account, 32) != 0) return true;     // another account: ignored
    const uint8_t* p = sec + KS_SEC_HDR;
    if (kind == SEC_TX) {
        if (!tx_alloc()) return true;
        const uint32_t skip = count > MW_KI_TX_MAX ? count - MW_KI_TX_MAX : 0;
        p += (size_t)skip * TX_ENTRY;
        g.ntx = 0;
        for (uint32_t i = skip; i < count; i++, p += TX_ENTRY) get_tx(p, &g.tx[g.ntx++]);
        return true;
    }
    if (!grow(count)) {
        MW_LOGE("kicache", "no memory for %lu cached key images", (unsigned long)count);
        return true;
    }
    const size_t el = entry_len(version, SEC_KI);
    for (uint32_t i = 0; i < count; i++, p += el) get_entry_v(version, p, &g.e[i]);
    g.count = count;
    return true;
}

mw_err_t mw_ki_cache_open(uint32_t wallet_id, uint8_t variant,
                          const mw_account_keys_t* keys)
{
    char name[MW_FSTORE_NAME_MAX + 1];
    store_t s;
    if (keys == NULL || variant > 1) return MW_ERR_INVALID_ARG;
    mw_ki_cache_close();
    if (!grow(256)) return MW_ERR_MEMORY;
    g.wallet_id = wallet_id;
    g.variant = variant;
    g.count = 0;
    g.dirty = false;
    account_hash(keys, g.account);
    g.open = true;

    mw_ki_store_file_name(name, sizeof name);
    if (store_read(name, &s) == MW_OK && s.plain) {
        const uint32_t want = mw_wallet_store_ki_gen();
        if (s.gen < want) {
            g.rolled_back = true;
            MW_LOGE("kicache", "key image caches are an OLD copy (generation %lu, "
                    "expected %lu): ignored, re-export the outputs",
                    (unsigned long)s.gen, (unsigned long)want);
        } else {
            find_ctx_t f = { wallet_id, variant };
            if (!store_walk(&s, load_sec, &f))
                MW_LOGE("kicache", "key image cache container damaged");
        }
    }
    store_free(&s);
    return MW_OK;
}

void mw_ki_cache_close(void)
{
    if (g.e) ki_free(g.e, (size_t)g.cap * sizeof(mw_ki_entry_t));
    if (g.tx) ki_free(g.tx, sizeof(mw_ki_tx_t) * MW_KI_TX_MAX);
    mw_memzero(&g, sizeof(g));
}

bool     mw_ki_cache_is_open(void) { return g.open; }
uint32_t mw_ki_cache_count(void)   { return g.open ? g.count : 0; }
bool     mw_ki_cache_rolled_back(void) { return g.open && g.rolled_back; }

const mw_ki_entry_t* mw_ki_cache_find_pub(const mw_pubkey_t* out_pub)
{
    if (!g.open || !out_pub) return NULL;
    for (uint32_t i = 0; i < g.count; i++)
        if (memcmp(g.e[i].out_pub.b, out_pub->b, 32) == 0) return &g.e[i];
    return NULL;
}

const mw_ki_entry_t* mw_ki_cache_find_image(const mw_keyimage_t* image)
{
    if (!g.open || !image) return NULL;
    for (uint32_t i = 0; i < g.count; i++)
        if (memcmp(g.e[i].image.b, image->b, 32) == 0) return &g.e[i];
    return NULL;
}

uint32_t mw_ki_cache_known_indices(uint32_t acct, uint32_t* majors, uint32_t* minors,
                                   uint32_t cap, uint32_t* max_major,
                                   uint32_t* max_minor_acct, uint32_t* max_minor_main)
{
    uint32_t n = 0, top = 0, top_acct = 0, top_main = 0;
    if (g.open) {
        for (uint32_t i = 0; i < g.count; i++) {
            const mw_ki_entry_t* e = &g.e[i];
            if (e->major > top) top = e->major;
            if (e->major == acct && e->minor > top_acct) top_acct = e->minor;
            if (e->major == 0 && e->minor > top_main) top_main = e->minor;
        }
        // Pass 0: outside the search window; pass 1: the rest.
        for (int pass = 0; pass < 2 && majors && minors; pass++) {
            for (uint32_t i = 0; i < g.count && n < cap; i++) {
                const mw_ki_entry_t* e = &g.e[i];
                if (e->major == 0 && e->minor == 0) continue;
                const bool in_window = e->minor == 0 || e->major == acct || e->major == 0;
                if (in_window != (pass == 1)) continue;
                bool dup = false;
                for (uint32_t j = 0; j < n && !dup; j++)
                    dup = majors[j] == e->major && minors[j] == e->minor;
                if (dup) continue;
                majors[n] = e->major;
                minors[n] = e->minor;
                n++;
            }
        }
    }
    if (max_major) *max_major = top;
    if (max_minor_acct) *max_minor_acct = top_acct;
    if (max_minor_main) *max_minor_main = top_main;
    return n;
}

// RAM only, between snapshot_begin() and snapshot_end(): not listed yet.
#define KI_B_UNSEEN 0x80

void mw_ki_cache_snapshot_begin(void)
{
    if (!g.open) return;
    for (uint32_t i = 0; i < g.count; i++) g.e[i].bal |= KI_B_UNSEEN;
}

uint32_t mw_ki_cache_snapshot_end(void)
{
    uint32_t n = 0;
    if (!g.open) return 0;
    for (uint32_t i = 0; i < g.count; i++) {
        mw_ki_entry_t* x = &g.e[i];
        if (!(x->bal & KI_B_UNSEEN)) continue;
        x->bal &= (uint8_t)~KI_B_UNSEEN;
        if (!(x->bal & MW_KI_B_AMOUNT) && !(x->flags & MW_KI_F_SPENT) &&
            !(x->bal & (MW_KI_B_SPENT | MW_KI_B_STALE))) {
            x->bal |= MW_KI_B_STALE;
            g.dirty = true;
            n++;
        }
    }
    return n;
}

// A transfer index belongs to one output: an output now listed at `tidx1`
// takes it from any other entry (the online wallet was rescanned, or it is
// another wallet that numbers its transfers differently).
static void tidx_release(uint32_t tidx1, uint32_t keep)
{
    for (uint32_t i = 0; i < g.count; i++) {
        if (i != keep && g.e[i].tidx1 == tidx1) {
            g.e[i].tidx1 = 0;
            mw_memzero(g.e[i].sig, 64);
        }
    }
}

mw_err_t mw_ki_cache_put(const mw_ki_entry_t* in)
{
    if (!g.open) return MW_ERR_NOT_SUPPORTED;
    if (!in) return MW_ERR_INVALID_ARG;
    mw_ki_entry_t e = *in;
    if (!balance_on()) { e.amount = 0; e.bal = 0; }
    for (uint32_t i = 0; i < g.count; i++) {
        mw_ki_entry_t* x = &g.e[i];
        if (memcmp(x->out_pub.b, e.out_pub.b, 32) == 0) {
            x->bal &= (uint8_t)~KI_B_UNSEEN;             // listed by a snapshot
            if (!mw_ct_is_zero(e.tx_pub.b, 32) &&
                (memcmp(x->tx_pub.b, e.tx_pub.b, 32) != 0 || x->gidx != e.gidx)) {
                x->tx_pub = e.tx_pub;
                x->gidx = e.gidx;
                g.dirty = true;
            }
            if (e.tidx1 && (x->tidx1 != e.tidx1 || memcmp(x->sig, e.sig, 64) != 0)) {
                if (x->tidx1 != e.tidx1) tidx_release(e.tidx1, i);   // only on a change
                x->tidx1 = e.tidx1;
                memcpy(x->sig, e.sig, 64);
                g.dirty = true;
            }
            if (memcmp(x->image.b, e.image.b, 32) != 0 || x->major != e.major ||
                x->minor != e.minor) {
                x->image = e.image;                  // recomputed: trust the new one
                x->major = e.major;
                x->minor = e.minor;
                g.dirty = true;
            }
            if ((x->flags | e.flags) != x->flags) {
                x->flags |= e.flags;
                g.dirty = true;
            }
            if (e.bal & MW_KI_B_AMOUNT) {
                if (x->amount != e.amount || x->bal != e.bal) {
                    x->amount = e.amount;
                    x->bal = e.bal;
                    g.dirty = true;
                }
            } else if ((x->bal | (e.bal & MW_KI_B_SPENT)) != x->bal) {
                x->bal |= (uint8_t)(e.bal & MW_KI_B_SPENT);
                g.dirty = true;
            }
            return MW_OK;
        }
    }
    if (g.count == 0xFFFFFFFFu || !grow(g.count + 1)) return MW_ERR_MEMORY;
    if (e.tidx1) tidx_release(e.tidx1, g.count);
    g.e[g.count++] = e;
    g.dirty = true;
    return MW_OK;
}

uint32_t mw_ki_cache_run_before(uint32_t offset, uint32_t max, uint8_t* out,
                                uint32_t* start)
{
    if (start) *start = offset;
    if (!g.open || offset == 0 || max == 0) return 0;
    // A run can be no longer than the cache: map only the window
    // [offset - w, offset), index -> entry, in one pass.
    uint32_t w = max < offset ? max : offset;
    if (w > g.count) w = g.count;
    if (w == 0) return 0;
    const uint32_t base = offset - w;
    const size_t bytes = (size_t)w * sizeof(uint32_t);
    uint32_t* pos = (uint32_t*)ki_alloc(bytes);
    if (!pos) return 0;
    memset(pos, 0xFF, bytes);
    for (uint32_t i = 0; i < g.count; i++) {
        const uint32_t t = g.e[i].tidx1;
        if (t > base && t <= offset && !mw_ct_is_zero(g.e[i].sig, 64)) pos[t - 1 - base] = i;
    }
    uint32_t n = 0;
    while (n < w && pos[w - 1 - n] != 0xFFFFFFFFu) n++;
    const uint32_t first = offset - n;
    if (out) {
        for (uint32_t k = 0; k < n; k++) {
            const mw_ki_entry_t* x = &g.e[pos[w - n + k]];
            memcpy(out + (size_t)k * 96, x->image.b, 32);
            memcpy(out + (size_t)k * 96 + 32, x->sig, 64);
        }
    }
    ki_free(pos, bytes);
    if (start) *start = first;
    return n;
}

mw_err_t mw_ki_cache_balance(uint64_t* total, uint32_t* outputs, uint32_t* unknown)
{
    uint64_t t = 0;
    uint32_t n = 0, u = 0;
    if (!g.open) return MW_ERR_NOT_SUPPORTED;
    for (uint32_t i = 0; i < g.count; i++) {
        const mw_ki_entry_t* x = &g.e[i];
        if (!(x->bal & MW_KI_B_AMOUNT)) {
            if (!(x->flags & MW_KI_F_SPENT) && !(x->bal & (MW_KI_B_SPENT | MW_KI_B_STALE))) u++;
            continue;
        }
        if (x->bal & MW_KI_B_SPENT) continue;
        t += x->amount;
        n++;
    }
    if (total) *total = t;
    if (outputs) *outputs = n;
    if (unknown) *unknown = u;
    return MW_OK;
}

uint32_t mw_ki_cache_tx_count(void) { return g.open ? g.ntx : 0; }

bool mw_ki_cache_get(uint32_t i, mw_ki_entry_t* out)
{
    if (!g.open || !out || i >= g.count) return false;
    *out = g.e[i];
    out->bal &= (uint8_t)~KI_B_UNSEEN;
    return true;
}

bool mw_ki_cache_tx_get(uint32_t i, mw_ki_tx_t* out)
{
    if (!g.open || !out || i >= g.ntx) return false;
    *out = g.tx[i];
    return true;
}

mw_err_t mw_ki_cache_tx_add(const mw_ki_tx_t* t)
{
    if (!t) return MW_ERR_INVALID_ARG;
    if (!g.open) return MW_ERR_NOT_SUPPORTED;
    if (!balance_on()) return MW_OK;
    if (!tx_alloc()) return MW_ERR_MEMORY;
    if (g.ntx == MW_KI_TX_MAX) {
        memmove(g.tx, g.tx + 1, sizeof(mw_ki_tx_t) * (MW_KI_TX_MAX - 1));
        g.ntx--;
    }
    mw_ki_tx_t* n = &g.tx[g.ntx];
    *n = *t;
    n->seq = g.ntx ? g.tx[g.ntx - 1].seq + 1u : 1u;
    n->addr[MW_KI_TX_ADDR] = 0;
    g.ntx++;
    g.dirty = true;
    return MW_OK;
}

mw_err_t mw_ki_cache_balance_forget_all(void)
{
    char name[MW_FSTORE_NAME_MAX + 1];
    size_t len = 0;
    skip_t none = { 0, 0, false };
    if (g.open) {
        for (uint32_t i = 0; i < g.count; i++) { g.e[i].amount = 0; g.e[i].bal = 0; }
        if (g.tx) mw_memzero(g.tx, sizeof(mw_ki_tx_t) * MW_KI_TX_MAX);
        g.ntx = 0;
    }
    mw_ki_store_file_name(name, sizeof name);
    if (!name[0]) return MW_ERR_NOT_SUPPORTED;
    if (mw_fstore_size(name, &len) != MW_OK) return MW_OK;
    // The open cache is written by its own save(); the file loses every
    // amount and list here, the open wallet's included.
    return store_update_x(none, false, true);
}

void mw_ki_cache_mark_spent(const mw_keyimage_t* image)
{
    if (!g.open || !image) return;
    for (uint32_t i = 0; i < g.count; i++) {
        if (memcmp(g.e[i].image.b, image->b, 32) == 0 &&
            !(g.e[i].flags & MW_KI_F_SPENT)) {
            g.e[i].flags |= MW_KI_F_SPENT;
            g.dirty = true;
        }
    }
}

bool mw_ki_cache_dirty(void) { return g.open && g.dirty; }

mw_err_t mw_ki_cache_save(void)
{
    if (!g.open) return MW_ERR_NOT_SUPPORTED;
    if (!g.dirty) return MW_OK;
    skip_t mine = { g.wallet_id, g.variant, true };
    mw_err_t e = store_update(mine, true);
    if (e == MW_OK) { g.dirty = false; g.rolled_back = false; }
    return e;
}

mw_err_t mw_ki_cache_erase_wallet(uint32_t wallet_id)
{
    char name[MW_FSTORE_NAME_MAX + 1];
    size_t len = 0;
    skip_t both = { wallet_id, 0xFF, true };
    if (g.open && g.wallet_id == wallet_id) mw_ki_cache_close();
    mw_ki_store_file_name(name, sizeof name);
    if (!name[0]) return MW_ERR_NOT_SUPPORTED;
    if (mw_fstore_size(name, &len) != MW_OK) return MW_OK;
    return store_update(both, false);           // only drop, never add here
}

// ---------------------------------------------------------------------------
// Older formats
// ---------------------------------------------------------------------------
static void old_seal_label(uint32_t id, uint8_t variant, char* out, size_t cap)
{
    snprintf(out, cap, "mw.ki.v1.%08lx.%u", (unsigned long)id, (unsigned)variant);
}

// v9.1 name: "k" + 24 hex of HMAC(user key, "mw.ki.file" || id || variant).
static void v1_file_name(uint32_t id, uint8_t variant, char* out, size_t cap)
{
    static const char hx[] = "0123456789abcdef";
    uint8_t d[5] = { (uint8_t)id, (uint8_t)(id >> 8), (uint8_t)(id >> 16),
                     (uint8_t)(id >> 24), variant };
    uint8_t mac[32];
    out[0] = '\0';
    if (cap < 26 || mw_secure_user_mac("mw.ki.file", d, sizeof d, mac) != MW_OK) return;
    out[0] = 'k';
    for (int i = 0; i < 12; i++) {
        out[1 + 2 * i] = hx[mac[i] >> 4];
        out[2 + 2 * i] = hx[mac[i] & 15];
    }
    out[25] = '\0';
    mw_memzero(mac, sizeof mac);
}

static void legacy_file_name(uint32_t id, uint8_t variant, char* out, size_t cap)
{
    snprintf(out, cap, "ki_%08lx_%u.bin", (unsigned long)id, (unsigned)variant);
}

// Reads one per-wallet record into the (closed) cache state g.
//   MW_OK          it opened
//   MW_ERR_DECRYPT it does not open (dropped)
//   other          a fault: kept for a retry
static mw_err_t old_read(const char* name, uint32_t id, uint8_t variant)
{
    char label[40];
    size_t size = 0, got = 0;
    if (mw_fstore_size(name, &size) != MW_OK) return MW_ERR_IO;
    if (size < KS_SEAL_HDR + KI_HDR) return MW_ERR_DECRYPT;
    uint8_t* file = (uint8_t*)ki_alloc(size);
    uint8_t* plain = (uint8_t*)ki_alloc(size);
    mw_err_t ok = MW_ERR_DECRYPT;
    if (!file || !plain) ok = MW_ERR_MEMORY;
    else if (mw_fstore_read(name, file, size, &got) != MW_OK || got != size) ok = MW_ERR_IO;
    else {
        const size_t ct = size - KS_SEAL_HDR;
        old_seal_label(id, variant, label, sizeof label);
        if (mw_unseal(label, file + KS_SEAL_HDR, ct, file, file + 16, plain, ct) == MW_OK &&
            memcmp(plain, KI_MAGIC, 4) == 0 && plain[4] == KI_VERSION) {
            const uint32_t n = get_u32(plain + 40);
            if (n <= (ct - KI_HDR) / KI_ENTRY && KI_HDR + (size_t)n * KI_ENTRY == ct) {
                if (!grow(n ? n : 1)) {
                    ok = MW_ERR_MEMORY;
                } else {
                    memcpy(g.account, plain + 8, 32);
                    const uint8_t* p = plain + KI_HDR;
                    for (uint32_t i = 0; i < n; i++, p += KI_ENTRY) get_entry(p, &g.e[i]);
                    g.count = n;
                    ok = MW_OK;
                }
            }
        }
    }
    ki_free(file, size);
    ki_free(plain, size);
    return ok;
}

void mw_ki_cache_import_old(uint32_t wallet_id)
{
    for (uint8_t v = 0; v < 2; v++) {
        char names[2][MW_FSTORE_NAME_MAX + 1];
        legacy_file_name(wallet_id, v, names[0], sizeof names[0]);
        v1_file_name(wallet_id, v, names[1], sizeof names[1]);
        for (int k = 0; k < 2; k++) {
            size_t len = 0;
            if (!names[k][0] || mw_fstore_size(names[k], &len) != MW_OK) continue;
            mw_ki_cache_close();
            const mw_err_t r = old_read(names[k], wallet_id, v);
            if (r != MW_OK && r != MW_ERR_DECRYPT) {      // a fault: retried later
                mw_ki_cache_close();
                continue;
            }
            if (r == MW_OK && g.count) {
                g.open = true;
                g.wallet_id = wallet_id;
                g.variant = v;
                g.dirty = true;
                skip_t mine = { wallet_id, v, true };
                if (store_update(mine, true) != MW_OK) {
                    MW_LOGE("kicache", "old key image cache of wallet %lu not imported",
                            (unsigned long)wallet_id);
                    mw_ki_cache_close();
                    continue;                     // the old file stays for a retry
                }
            }
            mw_ki_cache_close();
            (void)mw_fstore_remove(names[k]);
        }
        char gk[16];
        snprintf(gk, sizeof gk, "kig%08lx%u", (unsigned long)wallet_id, (unsigned)v);
        (void)mw_store_blob_erase(gk);
    }
}

bool mw_ki_cache_old_left(uint32_t wallet_id)
{
    for (uint8_t v = 0; v < 2; v++) {
        char name[MW_FSTORE_NAME_MAX + 1];
        size_t len = 0;
        v1_file_name(wallet_id, v, name, sizeof name);
        if (name[0] && mw_fstore_size(name, &len) == MW_OK) return true;
        legacy_file_name(wallet_id, v, name, sizeof name);
        if (mw_fstore_size(name, &len) == MW_OK) return true;
    }
    return false;
}

void mw_ki_cache_drop_old(uint32_t wallet_id)
{
    for (uint8_t v = 0; v < 2; v++) {
        char name[MW_FSTORE_NAME_MAX + 1];
        size_t len = 0;
        v1_file_name(wallet_id, v, name, sizeof name);
        if (name[0] && mw_fstore_size(name, &len) == MW_OK) (void)mw_fstore_remove(name);
        legacy_file_name(wallet_id, v, name, sizeof name);
        if (mw_fstore_size(name, &len) == MW_OK) (void)mw_fstore_remove(name);
    }
}

#ifdef MW_HOST_BUILD
// Host tests: writes the account's container in version 1 (before 0.3) with
// one section of `n` entries.
mw_err_t mw_host_ki_write_v1_container(uint32_t id, uint8_t variant,
                                       const mw_account_keys_t* keys,
                                       const mw_ki_entry_t* e, uint32_t n);
mw_err_t mw_host_ki_write_v1_container(uint32_t id, uint8_t variant,
                                       const mw_account_keys_t* keys,
                                       const mw_ki_entry_t* e, uint32_t n)
{
    char name[MW_FSTORE_NAME_MAX + 1];
    const size_t payload = KS_SEC_HDR + (size_t)n * KI_ENTRY;
    const size_t size = file_size_for(payload);
    const size_t pl = size - KS_SEAL_HDR;
    uint8_t* plain = (uint8_t*)ki_alloc(pl);
    uint8_t* file = (uint8_t*)ki_alloc(size);
    if (!plain || !file) return MW_ERR_MEMORY;
    memset(plain, 0, pl);
    memcpy(plain, KS_MAGIC, 4);
    plain[4] = 1;
    const uint32_t gen = mw_wallet_store_ki_gen() + 1u;
    put_u32(plain + 8, gen);
    put_u32(plain + 12, (uint32_t)payload);
    put_u32(plain + 16, 1);
    uint8_t* p = plain + KS_HDR;
    put_u32(p, id);
    p[4] = variant;
    account_hash(keys, p + 8);
    put_u32(p + 40, n);
    for (uint32_t i = 0; i < n; i++) put_entry(p + KS_SEC_HDR + i * KI_ENTRY, &e[i]);
    mw_ki_store_file_name(name, sizeof name);
    mw_err_t r = mw_seal(KS_LABEL, plain, pl, file, file + 16, file + KS_SEAL_HDR, pl);
    if (r == MW_OK) r = mw_fstore_write(name, file, size);
    if (r == MW_OK) r = mw_wallet_store_ki_gen_set(gen);
    ki_free(plain, pl);
    ki_free(file, size);
    return r;
}

// Host tests: writes a per-wallet record the way older firmware did - the
// v9.1 name, or with `legacy` the name used before v9.
mw_err_t mw_host_ki_write_old(uint32_t id, uint8_t variant, const mw_account_keys_t* keys,
                              const mw_ki_entry_t* e, uint32_t n, bool legacy);
mw_err_t mw_host_ki_write_old(uint32_t id, uint8_t variant, const mw_account_keys_t* keys,
                              const mw_ki_entry_t* e, uint32_t n, bool legacy)
{
    char name[MW_FSTORE_NAME_MAX + 1], label[40];
    const size_t pt = KI_HDR + (size_t)n * KI_ENTRY;
    uint8_t* plain = (uint8_t*)ki_alloc(pt);
    uint8_t* file = (uint8_t*)ki_alloc(KS_SEAL_HDR + pt);
    if (!plain || !file) return MW_ERR_MEMORY;
    memset(plain, 0, pt);
    memcpy(plain, KI_MAGIC, 4);
    plain[4] = KI_VERSION;
    plain[5] = 1;
    account_hash(keys, plain + 8);
    put_u32(plain + 40, n);
    for (uint32_t i = 0; i < n; i++) put_entry(plain + KI_HDR + i * KI_ENTRY, &e[i]);
    old_seal_label(id, variant, label, sizeof label);
    mw_err_t r = mw_seal(label, plain, pt, file, file + 16, file + KS_SEAL_HDR, pt);
    if (legacy) legacy_file_name(id, variant, name, sizeof name);
    else        v1_file_name(id, variant, name, sizeof name);
    if (r == MW_OK) r = mw_fstore_write(name, file, KS_SEAL_HDR + pt);
    ki_free(plain, pt);
    ki_free(file, KS_SEAL_HDR + pt);
    return r;
}
#endif
