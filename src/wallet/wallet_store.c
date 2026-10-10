// Multi-wallet storage (TZ 7) on top of the eFuse-backed sealing layer (TZ 8.1).
//
// What is stored where
//   * The wallet directory (ids, names, restore heights, flags and the SEALED
//     seed blobs) lives in one NVS blob / one host file, serialised explicitly
//     so the layout is versioned and endian-independent.
//   * Every seed is additionally sealed with AES-256-GCM under a key derived
//     from the read-protected eFuse HMAC key, with a per-wallet label.  NVS
//     encryption alone is not enough: it protects the flash image, the seal
//     additionally binds the record to the wallet id and to this chip.
//   * The plaintext seed exists only inside one function call and is wiped on
//     every path out of it (TZ 8.1).
//
// The sealed plaintext is always exactly 64 bytes, so
// wallet_entry_t.encrypted_seed[64] is always full and the ciphertext leaks
// neither the payload length nor the wallet kind.  The layout is implied by
// wallet_type - only polyseed, whose payload really varies, carries a length:
//
//   0 legacy      [0..31]  32-byte seed            [32..63] random padding
//   1 polyseed    [0]      record version (2)
//                 [1]      payload length (22..35)
//                 [2..]    packed polyseed context, see below
//                          (the rest stays random padding)
//   2 raw keys    [0..31]  spend secret            [32..63] random padding
//   3 view-only   [0..31]  view secret             [32..63] PUBLIC spend key
//
// A view-only wallet is the private view key plus the public spend key: both
// are needed before an address can even be displayed, and together they fill
// the record exactly, which is why the length prefix is type-implied rather
// than universal.
//
// POLYSEED RECORD VERSION 2 (funds-loss fix).  Version 1 put the bare secret
// length in plain[0] and then only the 19 secret bytes: the birthday and the
// feature bits were thrown away, even though mw_polyseed_keygen() salts the
// PBKDF2 with both.  Loading such a record derived the wallet that the same
// phrase with birthday 0 would produce - a foreign address for every real
// phrase, whose coins are unrecoverable from that phrase.  Version 2 seals the
// whole mw_polyseed_pack() context (birthday || features || secret) instead.
// A v1 record is recognised by plain[0] being a length (19..32) and is REFUSED
// with MW_ERR_VERSION; it must never be silently reinterpreted as v2, because
// that would swap the birthday into the secret and lose the wallet a second
// time.

#include "wallet_store.h"
#include "secure_storage.h"
#include "ki_cache.h"
#include "../monero/keys.h"
#include "../monero/mnemonic.h"
#include "../crypto/hash.h"
#include "../crypto/memzero.h"
#include "../crypto/random.h"
#include "file_store.h"
#include "../hal/log.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#if defined(__has_include)
#  if __has_include(<esp_heap_caps.h>)
#    include <esp_heap_caps.h>
#    define MW_WS_ESP_HEAP 1
#  endif
#endif

// ---------------------------------------------------------------------------
// Platform blob API.  Implemented by secure_storage.cpp (NVS, device) and by
// secure_storage_host.c (a file, host tests).  Declared here rather than in a
// header because secure_storage.h is a frozen contract.
// ---------------------------------------------------------------------------
mw_err_t mw_store_blob_write(const char* key, const void* data, size_t len);
mw_err_t mw_store_blob_read(const char* key, void* out, size_t cap, size_t* len_out);
mw_err_t mw_store_blob_erase(const char* key);

#define MW_WALLETS_BLOB_KEY  "wallets"
#define MW_WALLETS_MAGIC_0   'M'
#define MW_WALLETS_MAGIC_1   'W'
#define MW_WALLETS_MAGIC_2   'W'
#define MW_WALLETS_MAGIC_3   'S'
#define MW_WALLETS_VERSION   2

// wallet_entry_t.wallet_type.  The header documents 0 and 1; 2 and 3 extend it
// for the TZ 4.2 "import spend/view key" path, which has no seed at all.
#define MW_WT_LEGACY         0u   // 32-byte Monero legacy seed
#define MW_WT_POLYSEED       1u   // 19..32-byte polyseed secret
#define MW_WT_RAW_KEYS       2u   // raw spend secret; view = Hs(spend)
#define MW_WT_RAW_VIEW_ONLY  3u   // raw view secret only; cannot sign

#define MW_SEAL_PLAIN_LEN    64          // == sizeof(wallet_entry_t.encrypted_seed)

// Polyseed sealed-record format version, stored in plain[0].
#define MW_POLYSEED_REC_VERSION  2
// A v1 record held the raw secret length here instead of a version.
#define MW_POLYSEED_V1_LEN_MIN   MW_POLYSEED_SECRET_SIZE   // 19
#define MW_POLYSEED_V1_LEN_MAX   32
// [version][length] then the packed context.
#define MW_POLYSEED_REC_HDR      2

// The NVS directory of firmware before v9 (read once, then migrated).
#define LEGACY_MAX_WALLETS 10
#define REC_LEN   144
#define HDR_LEN   16
#define BLOB_LEN  (HDR_LEN + LEGACY_MAX_WALLETS * REC_LEN)

// v9: one sealed directory file per user (see wallet_store.h).
//   file      = iv[16] || tag[16] || AES-GCM(DIR_PT_LEN)
//   plaintext = header[64] || MAX_WALLETS records of DIR_REC bytes
//   header    [0..3] "MWUD" [4] version [5] count [6] flags
//             [8..11] active id [12..15] next id [16..47] the other key of an
//             interrupted password change
//   record    the 140 bytes of the NVS record, then ki_gen[0], ki_gen[1]
// The file has the same size whatever it holds, like the decoys.
#define DIR_PREFIX     "u"
#define DIR_TAG        "mw.user.dir.v1"
#define DIR_LABEL      "mw.dir.v1"
#define DIR_VERSION    1
#define DIR_HDR        64
#define DIR_REC        152
#define DIR_PT_LEN     (DIR_HDR + MAX_WALLETS * DIR_REC)
#define DIR_FILE_LEN   (32 + DIR_PT_LEN)
#define DIR_F_FROM     0x01   // this is the NEW directory; other key = old key
#define DIR_F_SUPER    0x02   // this is the OLD directory; other key = new key
#define DIR_F_PRIMARY  0x04   // the first user's (the record's verifier)


// ---------------------------------------------------------------------------
// Module state
// ---------------------------------------------------------------------------
static wallet_store_t g_store;
static uint32_t       g_next_id = 1;
static bool           g_loaded  = false;
// The loaded directory's flags and the other key of an interrupted change.
static uint8_t        g_dir_flags;
static uint8_t        g_dir_other[32];

// ---------------------------------------------------------------------------
// Little-endian helpers
// ---------------------------------------------------------------------------
static void put_u32(uint8_t* p, uint32_t v)
{
    p[0] = (uint8_t)v;         p[1] = (uint8_t)(v >> 8);
    p[2] = (uint8_t)(v >> 16); p[3] = (uint8_t)(v >> 24);
}
static uint32_t get_u32(const uint8_t* p)
{
    return (uint32_t)p[0] | ((uint32_t)p[1] << 8) |
           ((uint32_t)p[2] << 16) | ((uint32_t)p[3] << 24);
}

// ---------------------------------------------------------------------------
// Names (TZ 7.2)
// ---------------------------------------------------------------------------

// Rejects empty names, names that are only whitespace, and control characters.
// Bytes >= 0x80 are allowed so UTF-8 names (Cyrillic, TZ 4.1) work; 0x7f (DEL)
// and everything below 0x20 are refused.
static mw_err_t name_valid(const char* name)
{
    size_t i;
    bool has_visible = false;
    if (!name) return MW_ERR_INVALID_ARG;
    for (i = 0; name[i] != '\0'; i++) {
        unsigned char c = (unsigned char)name[i];
        if (c < 0x20u || c == 0x7fu) return MW_ERR_INVALID_ARG;
        if (c != ' ') has_visible = true;
    }
    if (i == 0 || i >= WALLET_NAME_LEN) return MW_ERR_INVALID_ARG;  // needs a NUL
    if (!has_visible) return MW_ERR_INVALID_ARG;
    return MW_OK;
}

static int find_index(uint32_t id)
{
    uint32_t i;
    if (id == 0) return -1;
    for (i = 0; i < g_store.count && i < MAX_WALLETS; i++)
        if (g_store.wallets[i].id == id) return (int)i;
    return -1;
}

// `skip_index` < 0 checks every entry.
static bool name_taken(const char* name, int skip_index)
{
    uint32_t i;
    for (i = 0; i < g_store.count && i < MAX_WALLETS; i++) {
        if ((int)i == skip_index) continue;
        if (strncmp(g_store.wallets[i].name, name, WALLET_NAME_LEN) == 0) return true;
    }
    return false;
}

// Per-wallet sealing label.  Binding the key to the id means a swapped or
// renumbered record fails the GCM tag check instead of decrypting to the wrong
// wallet's seed.
static void seed_label(uint32_t id, char* out, size_t cap)
{
    snprintf(out, cap, "mw.seed.v1.%08lx", (unsigned long)id);
}

// ---------------------------------------------------------------------------
// Serialisation
// ---------------------------------------------------------------------------
// ---- the NVS directory of firmware before v9 (read-only now) ------------
static mw_err_t legacy_deserialize(wallet_store_t* s, uint32_t* next_id,
                                   const uint8_t* blob, size_t len)
{
    uint32_t i, count;
    if (len != BLOB_LEN) return MW_ERR_FORMAT;
    if (blob[0] != MW_WALLETS_MAGIC_0 || blob[1] != MW_WALLETS_MAGIC_1 ||
        blob[2] != MW_WALLETS_MAGIC_2 || blob[3] != MW_WALLETS_MAGIC_3)
        return MW_ERR_MAGIC;
    if (blob[4] != MW_WALLETS_VERSION) return MW_ERR_VERSION;

    count = blob[5];
    if (count > LEGACY_MAX_WALLETS) return MW_ERR_FORMAT;

    memset(s, 0, sizeof *s);
    s->count            = count;
    s->active_wallet_id = get_u32(blob + 8);
    *next_id            = get_u32(blob + 12);
    if (*next_id == 0) *next_id = 1;

    for (i = 0; i < count; i++) {
        wallet_entry_t* w = &s->wallets[i];
        const uint8_t* r = blob + HDR_LEN + i * REC_LEN;
        w->id = get_u32(r);
        memcpy(w->name, r + 4, WALLET_NAME_LEN);
        w->name[WALLET_NAME_LEN - 1] = '\0';
        memcpy(w->encrypted_seed, r + 36,  64);
        memcpy(w->seed_iv,        r + 100, 16);
        memcpy(w->seed_tag,       r + 116, 16);
        w->restore_height = get_u32(r + 132);
        w->wallet_type    = r[136];
        w->is_view_only   = (r[137] != 0);
        w->is_hidden      = (r[138] != 0);
        w->pp_state       = (r[139] <= MW_PP_SET) ? r[139] : MW_PP_UNKNOWN;
        if (w->id == 0) return MW_ERR_FORMAT;
        if (w->id >= *next_id) *next_id = w->id + 1;
    }
    return MW_OK;
}

#ifdef MW_HOST_BUILD
// Host tests: writes a directory the way firmware before v9 did.
mw_err_t mw_host_wallet_store_write_legacy(const wallet_store_t* s, uint32_t next_id);
mw_err_t mw_host_wallet_store_write_legacy(const wallet_store_t* s, uint32_t next_id)
{
    uint8_t blob[BLOB_LEN];
    uint32_t i;
    if (!s || s->count > LEGACY_MAX_WALLETS) return MW_ERR_INVALID_ARG;
    memset(blob, 0, sizeof blob);
    blob[0] = MW_WALLETS_MAGIC_0; blob[1] = MW_WALLETS_MAGIC_1;
    blob[2] = MW_WALLETS_MAGIC_2; blob[3] = MW_WALLETS_MAGIC_3;
    blob[4] = MW_WALLETS_VERSION;
    blob[5] = (uint8_t)s->count;
    put_u32(blob + 8,  s->active_wallet_id);
    put_u32(blob + 12, next_id);
    for (i = 0; i < s->count; i++) {
        const wallet_entry_t* w = &s->wallets[i];
        uint8_t* r = blob + HDR_LEN + i * REC_LEN;
        put_u32(r, w->id);
        memcpy(r + 4,   w->name, WALLET_NAME_LEN);
        memcpy(r + 36,  w->encrypted_seed, 64);
        memcpy(r + 100, w->seed_iv, 16);
        memcpy(r + 116, w->seed_tag, 16);
        put_u32(r + 132, w->restore_height);
        r[136] = w->wallet_type;
        r[137] = w->is_view_only ? 1u : 0u;
        r[138] = w->is_hidden    ? 1u : 0u;
        r[139] = w->pp_state;
    }
    return mw_store_blob_write(MW_WALLETS_BLOB_KEY, blob, sizeof blob);
}
#endif

// ---- v9 user directory files ---------------------------------------------
// The plaintext of a directory may hold the other key of a password change:
// internal RAM when there is room, not PSRAM.
static void* dir_alloc(size_t n)
{
#if defined(MW_WS_ESP_HEAP)
    void* p = heap_caps_malloc(n, MALLOC_CAP_INTERNAL | MALLOC_CAP_8BIT);
    if (p) return p;
#endif
    return malloc(n);
}
static void  dir_free(void* p, size_t n) { if (p) { mw_memzero(p, n); free(p); } }

static void hex_name(const uint8_t* b, size_t nbytes, const char* prefix, char* out,
                     size_t cap)
{
    static const char hx[] = "0123456789abcdef";
    size_t o = (size_t)snprintf(out, cap, "%s", prefix);
    for (size_t i = 0; i < nbytes && o + 2 < cap; i++) {
        out[o++] = hx[b[i] >> 4];
        out[o++] = hx[b[i] & 15];
    }
    out[o] = '\0';
}

// Directory file name of the installed user key.
static mw_err_t dir_name(char out[MW_FSTORE_NAME_MAX + 1])
{
    uint8_t mac[32];
    mw_err_t e = mw_secure_user_mac(DIR_TAG, NULL, 0, mac);
    if (e == MW_OK) hex_name(mac, 12, DIR_PREFIX, out, MW_FSTORE_NAME_MAX + 1);
    mw_memzero(mac, sizeof mac);
    return e;
}

static void dir_serialize(const wallet_store_t* s, uint32_t next_id, uint8_t flags,
                          const uint8_t other[32], uint8_t* pt)
{
    uint32_t i;
    memset(pt, 0, DIR_PT_LEN);
    memcpy(pt, "MWUD", 4);
    pt[4] = DIR_VERSION;
    pt[5] = (uint8_t)s->count;
    pt[6] = flags;
    put_u32(pt + 8, s->active_wallet_id);
    put_u32(pt + 12, next_id);
    if (flags & (DIR_F_FROM | DIR_F_SUPER)) memcpy(pt + 16, other, 32);
    for (i = 0; i < s->count && i < MAX_WALLETS; i++) {
        const wallet_entry_t* w = &s->wallets[i];
        uint8_t* r = pt + DIR_HDR + i * DIR_REC;
        put_u32(r, w->id);
        memcpy(r + 4,   w->name, WALLET_NAME_LEN);
        memcpy(r + 36,  w->encrypted_seed, 64);
        memcpy(r + 100, w->seed_iv, 16);
        memcpy(r + 116, w->seed_tag, 16);
        put_u32(r + 132, w->restore_height);
        r[136] = w->wallet_type;
        r[137] = w->is_view_only ? 1u : 0u;
        r[138] = w->is_hidden    ? 1u : 0u;
        r[139] = w->pp_state;
        put_u32(r + 140, w->ki_gen[0]);
        put_u32(r + 144, w->ki_gen[1]);
    }
}

static mw_err_t dir_deserialize(wallet_store_t* s, uint32_t* next_id, uint8_t* flags,
                                uint8_t other[32], const uint8_t* pt)
{
    uint32_t i, count;
    if (memcmp(pt, "MWUD", 4) != 0) return MW_ERR_MAGIC;
    if (pt[4] != DIR_VERSION) return MW_ERR_VERSION;
    count = pt[5];
    if (count > MAX_WALLETS) return MW_ERR_FORMAT;
    memset(s, 0, sizeof *s);
    s->count = count;
    *flags = pt[6];
    s->active_wallet_id = get_u32(pt + 8);
    *next_id = get_u32(pt + 12);
    if (*next_id == 0) *next_id = 1;
    memcpy(other, pt + 16, 32);
    for (i = 0; i < count; i++) {
        wallet_entry_t* w = &s->wallets[i];
        const uint8_t* r = pt + DIR_HDR + i * DIR_REC;
        w->id = get_u32(r);
        memcpy(w->name, r + 4, WALLET_NAME_LEN);
        w->name[WALLET_NAME_LEN - 1] = '\0';
        memcpy(w->encrypted_seed, r + 36,  64);
        memcpy(w->seed_iv,        r + 100, 16);
        memcpy(w->seed_tag,       r + 116, 16);
        w->restore_height = get_u32(r + 132);
        w->wallet_type    = r[136];
        w->is_view_only   = (r[137] != 0);
        w->is_hidden      = (r[138] != 0);
        w->pp_state       = (r[139] <= MW_PP_SET) ? r[139] : MW_PP_UNKNOWN;
        w->ki_gen[0]      = get_u32(r + 140);
        w->ki_gen[1]      = get_u32(r + 144);
        if (w->id == 0) return MW_ERR_FORMAT;
        if (w->id >= *next_id) *next_id = w->id + 1;
    }
    return MW_OK;
}

// Seals and writes `s` as the directory of the installed user key.
static mw_err_t dir_write(const wallet_store_t* s, uint32_t next_id, uint8_t flags,
                          const uint8_t other[32])
{
    char name[MW_FSTORE_NAME_MAX + 1];
    mw_err_t e = dir_name(name);
    if (e != MW_OK) return e;
    uint8_t* pt = (uint8_t*)dir_alloc(DIR_PT_LEN);
    uint8_t* f  = (uint8_t*)dir_alloc(DIR_FILE_LEN);
    if (!pt || !f) {
        dir_free(pt, DIR_PT_LEN);
        dir_free(f, DIR_FILE_LEN);
        return MW_ERR_MEMORY;
    }
    dir_serialize(s, next_id, flags, other, pt);
    e = mw_seal(DIR_LABEL, pt, DIR_PT_LEN, f, f + 16, f + 32, DIR_PT_LEN);
    if (e == MW_OK) e = mw_fstore_write(name, f, DIR_FILE_LEN);
    dir_free(pt, DIR_PT_LEN);
    dir_free(f, DIR_FILE_LEN);
    return e;
}

// Reads the directory of the installed user key.
//   MW_ERR_IO       there is no such file
//   MW_ERR_DECRYPT  a file of that name does not open (damaged)
//   MW_ERR_FORMAT   it exists but could not be read (never "no file")
static mw_err_t dir_read(wallet_store_t* s, uint32_t* next_id, uint8_t* flags,
                         uint8_t other[32])
{
    char name[MW_FSTORE_NAME_MAX + 1];
    size_t len = 0;
    mw_err_t e = dir_name(name);
    if (e != MW_OK) return e;
    if (mw_fstore_size(name, &len) != MW_OK) return MW_ERR_IO;
    if (len != DIR_FILE_LEN) return MW_ERR_FORMAT;
    uint8_t* pt = (uint8_t*)dir_alloc(DIR_PT_LEN);
    uint8_t* f  = (uint8_t*)dir_alloc(DIR_FILE_LEN);
    if (!pt || !f) {
        dir_free(pt, DIR_PT_LEN);
        dir_free(f, DIR_FILE_LEN);
        return MW_ERR_MEMORY;
    }
    e = mw_fstore_read(name, f, DIR_FILE_LEN, &len);
    if (e != MW_OK) e = MW_ERR_FORMAT;            // it exists: a read fault
    if (e == MW_OK && len != DIR_FILE_LEN) e = MW_ERR_FORMAT;
    if (e == MW_OK) e = mw_unseal(DIR_LABEL, f + 32, DIR_PT_LEN, f, f + 16, pt, DIR_PT_LEN);
    if (e == MW_OK) e = dir_deserialize(s, next_id, flags, other, pt);
    dir_free(pt, DIR_PT_LEN);
    dir_free(f, DIR_FILE_LEN);
    return e;
}

static mw_err_t dir_remove(void)
{
    char name[MW_FSTORE_NAME_MAX + 1];
    mw_err_t e = dir_name(name);
    if (e == MW_OK) e = mw_fstore_remove(name);
    return e;
}

static mw_err_t persist(void)
{
    return dir_write(&g_store, g_next_id, g_dir_flags, g_dir_other);
}

static mw_err_t ensure_loaded(void)
{
    mw_err_t e;
    if (g_loaded) return MW_OK;
    if (!mw_secure_user_key_present()) return MW_ERR_NOT_SUPPORTED;

    memset(&g_store, 0, sizeof g_store);
    g_next_id = 1;
    g_dir_flags = 0;
    mw_memzero(g_dir_other, sizeof g_dir_other);
    e = dir_read(&g_store, &g_next_id, &g_dir_flags, g_dir_other);
    if (e == MW_ERR_IO) {
        // No directory yet: an empty one, written by the first change.
        memset(&g_store, 0, sizeof g_store);
        g_next_id = 1;
        g_dir_flags = 0;
        e = MW_OK;
    }
    if (e != MW_OK) {
        // Damaged or newer-format directory: refuse to interpret it rather
        // than silently dropping wallets.
        memset(&g_store, 0, sizeof g_store);
        mw_memzero(g_dir_other, sizeof g_dir_other);
        g_dir_flags = 0;
        return MW_ERR_FORMAT;
    }
    g_loaded = true;
    return MW_OK;
}

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

mw_err_t mw_wallet_store_init(void)
{
    mw_err_t err;
    mw_wallet_store_close();
    if (!mw_secure_user_key_present()) return MW_OK;   // loaded at login
    err = ensure_loaded();
    if (err != MW_OK) return err;
    // Materialise an empty directory so later saves are updates.
    return persist();
}

void mw_wallet_store_close(void)
{
    mw_memzero(&g_store, sizeof g_store);
    mw_memzero(g_dir_other, sizeof g_dir_other);
    g_dir_flags = 0;
    g_next_id = 1;
    g_loaded = false;
}

mw_err_t mw_wallet_store_load(wallet_store_t* out)
{
    mw_err_t err;
    if (!out) return MW_ERR_INVALID_ARG;
    err = ensure_loaded();
    if (err != MW_OK) return err;
    memcpy(out, &g_store, sizeof *out);
    return MW_OK;
}

mw_err_t mw_wallet_store_save(const wallet_store_t* store)
{
    if (!store) return MW_ERR_INVALID_ARG;
    if (store->count > MAX_WALLETS) return MW_ERR_TOO_MANY;
    mw_err_t err = ensure_loaded();
    if (err != MW_OK) return err;
    memcpy(&g_store, store, sizeof g_store);
    for (uint32_t i = 0; i < g_store.count; i++)
        if (g_store.wallets[i].id >= g_next_id) g_next_id = g_store.wallets[i].id + 1;
    return persist();
}

// How long the logical payload may be for a given wallet_type.
static mw_err_t payload_len_ok(uint8_t wallet_type, size_t len)
{
    switch (wallet_type) {
        case MW_WT_LEGACY:
            return (len == 32) ? MW_OK : MW_ERR_INVALID_ARG;
        case MW_WT_POLYSEED:
            // The packed context, never a bare secret: a 19-byte payload is
            // shorter than the minimum and is therefore refused outright.
            return (len >= MW_POLYSEED_BLOB_MIN && len <= MW_POLYSEED_BLOB_MAX)
                       ? MW_OK : MW_ERR_INVALID_ARG;
        case MW_WT_RAW_KEYS:
            return (len == 32) ? MW_OK : MW_ERR_INVALID_ARG;
        case MW_WT_RAW_VIEW_ONLY:
            // view secret || public spend key
            return (len == 64) ? MW_OK : MW_ERR_INVALID_ARG;
        default:
            return MW_ERR_INVALID_ARG;
    }
}

// Lays the logical payload out inside the fixed 64-byte sealed record.
// `plain` must already be filled with random bytes; whatever the payload does
// not occupy stays random padding.
static mw_err_t plain_from_payload(uint8_t wallet_type, const uint8_t* payload,
                                   size_t payload_len, uint8_t plain[MW_SEAL_PLAIN_LEN])
{
    mw_err_t err = payload_len_ok(wallet_type, payload_len);
    if (err != MW_OK) return err;

    if (wallet_type == MW_WT_POLYSEED) {
        plain[0] = MW_POLYSEED_REC_VERSION;
        plain[1] = (uint8_t)payload_len;
        memcpy(plain + MW_POLYSEED_REC_HDR, payload, payload_len);
    } else {
        memcpy(plain, payload, payload_len);
    }
    return MW_OK;
}

// The inverse: points `pp` at the payload inside `plain` and reports its length.
// Returns MW_ERR_FORMAT when the record authenticated but does not parse -
// i.e. the wallet_type and the sealed bytes disagree.
static mw_err_t payload_from_plain(uint8_t wallet_type,
                                   const uint8_t plain[MW_SEAL_PLAIN_LEN],
                                   const uint8_t** pp, size_t* plen)
{
    size_t len;

    switch (wallet_type) {
        case MW_WT_LEGACY:
        case MW_WT_RAW_KEYS:
            len = 32;  *pp = plain;     break;
        case MW_WT_POLYSEED:
            if (plain[0] != MW_POLYSEED_REC_VERSION) {
                // A v1 record stored the bare secret length here and carried
                // no birthday/features at all.  Refusing is the only safe
                // answer: reinterpreting those bytes as a v2 context would
                // hand back a different, unrecoverable wallet.
                if (plain[0] >= MW_POLYSEED_V1_LEN_MIN &&
                    plain[0] <= MW_POLYSEED_V1_LEN_MAX) {
                    return MW_ERR_VERSION;
                }
                return MW_ERR_FORMAT;
            }
            len = plain[1]; *pp = plain + MW_POLYSEED_REC_HDR; break;
        case MW_WT_RAW_VIEW_ONLY:
            len = 64;  *pp = plain;     break;
        default:
            return MW_ERR_FORMAT;
    }
    if (payload_len_ok(wallet_type, len) != MW_OK) return MW_ERR_FORMAT;
    *plen = len;
    return MW_OK;
}

// Shared body of mw_wallet_create() and mw_wallet_create_from_keys(): validate,
// seal `payload` under a per-wallet label and append the record.  One cleanup
// path, so the padded plaintext is wiped however this returns.
// Passphrase check (task 3 item 5), sealed inside the record at
// [MW_PP_REC_OFF..63]: marker, version, then 14 bytes of
// keccak256("mw.pp.check.v1" || spend_pub || view_pub) of the passphrase
// wallet. Only the seed wallets carry it; their payloads end before byte 48
// (legacy 32, polyseed at most 2 + 35).
#define MW_PP_REC_OFF     48
#define MW_PP_REC_MARKER  0xA5
#define MW_PP_REC_VERSION 1
#define MW_PP_CHECK_LEN   14

static void pp_check_of(const mw_account_keys_t* keys, uint8_t out[MW_PP_CHECK_LEN])
{
    uint8_t buf[14 + 64], h[32];
    memcpy(buf, "mw.pp.check.v1", 14);
    memcpy(buf + 14, keys->pub.spend.b, 32);
    memcpy(buf + 46, keys->pub.view.b, 32);
    mw_keccak256(buf, sizeof buf, h);
    memcpy(out, h, MW_PP_CHECK_LEN);
    mw_memzero(h, sizeof h);
}

static mw_err_t create_entry(const char* name, uint8_t wallet_type, bool view_only,
                             const uint8_t* payload, size_t payload_len,
                             uint32_t restore_height, const uint8_t* pp_check,
                             uint32_t* id_out)
{
    uint8_t  plain[MW_SEAL_PLAIN_LEN];
    char     label[40];
    wallet_entry_t* w;
    mw_err_t err;
    uint32_t id;

    memset(plain, 0, sizeof plain);

    if (!payload || !id_out)                { err = MW_ERR_INVALID_ARG; goto done; }
    if ((err = name_valid(name)) != MW_OK)  { goto done; }
    if ((err = payload_len_ok(wallet_type, payload_len)) != MW_OK) { goto done; }
    if ((err = ensure_loaded()) != MW_OK)   { goto done; }
    if (g_store.count >= MAX_WALLETS)       { err = MW_ERR_TOO_MANY; goto done; }
    if (name_taken(name, -1))               { err = MW_ERR_INVALID_ARG; goto done; }
    // Sealing is impossible before the eFuse key exists (TZ 8.1).
    if (mw_secure_key_status() != MW_OK)    { err = MW_ERR_NOT_SUPPORTED; goto done; }

    id = g_next_id;

    // Random first, then the payload on top: whatever is left stays padding.
    mw_random_bytes(plain, sizeof plain);
    if ((err = plain_from_payload(wallet_type, payload, payload_len, plain)) != MW_OK)
        goto done;
    if (pp_check) {
        if (wallet_type != MW_WT_LEGACY && wallet_type != MW_WT_POLYSEED) {
            err = MW_ERR_INVALID_ARG;            // raw keys have no passphrase
            goto done;
        }
        plain[MW_PP_REC_OFF]     = MW_PP_REC_MARKER;
        plain[MW_PP_REC_OFF + 1] = MW_PP_REC_VERSION;
        memcpy(plain + MW_PP_REC_OFF + 2, pp_check, MW_PP_CHECK_LEN);
    }

    w = &g_store.wallets[g_store.count];
    memset(w, 0, sizeof *w);
    seed_label(id, label, sizeof label);
    err = mw_seal(label, plain, sizeof plain, w->seed_iv, w->seed_tag,
                  w->encrypted_seed, sizeof w->encrypted_seed);
    if (err != MW_OK) { memset(w, 0, sizeof *w); goto done; }

    w->id             = id;
    snprintf(w->name, WALLET_NAME_LEN, "%s", name);
    w->restore_height = restore_height;
    w->wallet_type    = wallet_type;
    w->is_view_only   = view_only;
    w->is_hidden      = false;
    w->pp_state       = pp_check ? MW_PP_SET : MW_PP_NONE;

    g_store.count++;
    g_next_id = id + 1;
    if (g_store.active_wallet_id == 0) g_store.active_wallet_id = id;

    err = persist();
    if (err != MW_OK) {
        memset(w, 0, sizeof *w);
        g_store.count--;
        goto done;
    }
    *id_out = id;

done:
    mw_memzero(plain, sizeof plain);
    return err;
}

mw_err_t mw_wallet_create(const char* name, mw_seed_type_t type,
                          const uint8_t* seed_material, size_t seed_len,
                          uint32_t restore_height, uint32_t* id_out)
{
    uint8_t wt;
    if (type == MW_SEED_MONERO_LEGACY)  wt = MW_WT_LEGACY;
    else if (type == MW_SEED_POLYSEED)  wt = MW_WT_POLYSEED;
    else                                return MW_ERR_INVALID_ARG;
    return create_entry(name, wt, false, seed_material, seed_len,
                        restore_height, NULL, id_out);
}

mw_err_t mw_wallet_create_pp(const char* name, mw_seed_type_t type,
                             const uint8_t* seed_material, size_t seed_len,
                             uint32_t restore_height,
                             const mw_account_keys_t* pp_keys, uint32_t* id_out)
{
    uint8_t wt;
    uint8_t check[MW_PP_CHECK_LEN];
    mw_err_t err;
    if (type == MW_SEED_MONERO_LEGACY)  wt = MW_WT_LEGACY;
    else if (type == MW_SEED_POLYSEED)  wt = MW_WT_POLYSEED;
    else                                return MW_ERR_INVALID_ARG;
    if (pp_keys) pp_check_of(pp_keys, check);
    err = create_entry(name, wt, false, seed_material, seed_len, restore_height,
                       pp_keys ? check : NULL, id_out);
    mw_memzero(check, sizeof check);
    return err;
}

uint8_t mw_wallet_pp_state(uint32_t id)
{
    const wallet_entry_t* w = mw_wallet_get(id);
    if (!w) return MW_PP_NONE;
    if (w->wallet_type != MW_WT_LEGACY && w->wallet_type != MW_WT_POLYSEED)
        return MW_PP_NONE;
    return w->pp_state;
}

// TZ 4.2: import from raw keys.  There is no seed here, so nothing is folded
// in from a passphrase - the imported scalars are final.
//
//   spend != NULL : full wallet.  Only the spend secret is sealed; the view
//                   secret is Hs(spend) and is recomputed on every load.  A
//                   supplied `view` must match it, and a supplied `spend_pub`
//                   must equal spend*G, otherwise MW_ERR_KEY_MISMATCH.
//   spend == NULL : view-only.  `view` AND `spend_pub` are both required - the
//                   public spend key is what makes the account's address
//                   computable, and without it the wallet is useless.  Both
//                   are sealed together.
//
// A view-only wallet can neither sign nor compute key images (both need the
// private spend key).  mw_wallet_load_keys() marks it by setting
// keys.view_only AND leaving sec.spend all-zero, so either check catches it.
mw_err_t mw_wallet_create_from_keys(const char* name, const mw_seckey_t* spend,
                                    const mw_seckey_t* view,
                                    const mw_pubkey_t* spend_pub,
                                    uint32_t restore_height, uint32_t* id_out)
{
    uint8_t     payload[64];
    size_t      payload_len;
    mw_seckey_t derived;
    mw_err_t    err;
    uint8_t     wt        = MW_WT_RAW_KEYS;
    bool        view_only = false;

    memset(payload, 0, sizeof payload);
    memset(&derived, 0, sizeof derived);
    payload_len = 0;

    if (!spend && !view) { err = MW_ERR_INVALID_ARG; goto done; }

    if (spend) {
        // TZ 8.3: only canonical, non-zero scalars are ever accepted.
        if (!mw_sc_check(spend) || mw_sc_is_zero(spend)) {
            err = MW_ERR_INVALID_ARG; goto done;
        }
        if (view) {
            mw_hash_to_scalar(spend->b, 32, &derived);
            if (!mw_ct_equal(view->b, derived.b, 32)) {
                err = MW_ERR_KEY_MISMATCH; goto done;
            }
        }
        if (spend_pub) {
            // Optional cross-check: the caller's public half must be spend*G.
            mw_pubkey_t expect;
            mw_point_scalarmult_base(&expect, spend);
            if (!mw_ct_equal(expect.b, spend_pub->b, 32)) {
                err = MW_ERR_KEY_MISMATCH; goto done;
            }
        }
        memcpy(payload, spend->b, 32);
        payload_len = 32;
        wt          = MW_WT_RAW_KEYS;
        view_only   = false;
    } else {
        // View-only: the private view key alone is not a wallet.
        if (!spend_pub) { err = MW_ERR_INVALID_ARG; goto done; }
        if (!mw_sc_check(view) || mw_sc_is_zero(view)) {
            err = MW_ERR_INVALID_ARG; goto done;
        }
        // NOTE: mw_point_check_public() returns a BOOLEAN (1 = the point is
        // safe), not an mw_err_t. Comparing it against MW_OK would invert the
        // test and accept every malicious point. See src/crypto/ed25519.h.
        if (!mw_point_check_public(spend_pub)) { err = MW_ERR_SUBGROUP; goto done; }

        memcpy(payload,      view->b,      32);
        memcpy(payload + 32, spend_pub->b, 32);
        payload_len = 64;
        wt          = MW_WT_RAW_VIEW_ONLY;
        view_only   = true;
    }

    err = create_entry(name, wt, view_only, payload, payload_len,
                       restore_height, NULL, id_out);

done:
    mw_memzero(payload, sizeof payload);
    mw_memzero(&derived, sizeof derived);
    return err;
}

mw_err_t mw_wallet_unseal_seed(uint32_t id, uint8_t* out, size_t cap, size_t* len)
{
    uint8_t  plain[MW_SEAL_PLAIN_LEN];
    char     label[40];
    const wallet_entry_t* w;
    const uint8_t* payload = NULL;
    mw_err_t err;
    int      idx;
    size_t   n = 0;

    memset(plain, 0, sizeof plain);

    if (!out || !len)                     { err = MW_ERR_INVALID_ARG; goto done; }
    if ((err = ensure_loaded()) != MW_OK) { goto done; }
    idx = find_index(id);
    if (idx < 0)                          { err = MW_ERR_INVALID_ARG; goto done; }
    w = &g_store.wallets[idx];

    seed_label(id, label, sizeof label);
    err = mw_unseal(label, w->encrypted_seed, sizeof w->encrypted_seed,
                    w->seed_iv, w->seed_tag, plain, sizeof plain);
    if (err != MW_OK) goto done;

    // Authenticated, but the wallet_type and the sealed bytes must still agree.
    err = payload_from_plain(w->wallet_type, plain, &payload, &n);
    if (err != MW_OK) goto done;
    if (cap < n) { err = MW_ERR_INVALID_ARG; goto done; }

    memcpy(out, payload, n);
    *len = n;
    err  = MW_OK;

done:
    mw_memzero(plain, sizeof plain);
    return err;
}

// TZ 8.1: unseal -> derive -> wipe, with exactly one cleanup path.
mw_err_t mw_wallet_load_keys(uint32_t id, const char* passphrase,
                             mw_account_keys_t* keys_out)
{
    // Sized for the largest payload: a view-only record is view || spend_pub.
    uint8_t  seed[MW_SEAL_PLAIN_LEN];
    size_t   seed_len = 0;
    const wallet_entry_t* w;
    uint8_t  wt = MW_WT_LEGACY;
    mw_err_t err;
    int      idx;

    memset(seed, 0, sizeof seed);

    if (!keys_out || !passphrase)         { err = MW_ERR_INVALID_ARG; goto done; }
    memset(keys_out, 0, sizeof *keys_out);
    if ((err = ensure_loaded()) != MW_OK) { goto done; }
    idx = find_index(id);
    if (idx < 0)                          { err = MW_ERR_INVALID_ARG; goto done; }
    w  = &g_store.wallets[idx];
    wt = w->wallet_type;

    err = mw_wallet_unseal_seed(id, seed, sizeof seed, &seed_len);
    if (err != MW_OK) goto done;

    switch (wt) {
        case MW_WT_LEGACY:
            err = mw_seed_to_keys(MW_SEED_MONERO_LEGACY, seed, seed_len,
                                  passphrase, keys_out);
            break;
        case MW_WT_POLYSEED:
            err = mw_seed_to_keys(MW_SEED_POLYSEED, seed, seed_len,
                                  passphrase, keys_out);
            break;
        case MW_WT_RAW_KEYS:
            // Imported spend key: there is no seed and therefore no passphrase
            // to fold in - the stored scalar IS the spend key.
            mw_keys_from_legacy_seed(seed, keys_out);
            err = mw_keys_derive_public(keys_out);
            break;
        case MW_WT_RAW_VIEW_ONLY:
            // View-only import: seed == view secret || PUBLIC spend key.
            //
            // sec.spend stays all-zero and view_only is set, so BOTH signing
            // and key-image sync have an unambiguous early-refusal check -
            // neither is possible without the private spend key.
            if (seed_len != 64) { err = MW_ERR_FORMAT; break; }
            memcpy(keys_out->sec.view.b, seed, 32);
            memcpy(keys_out->pub.spend.b, seed + 32, 32);
            keys_out->view_only = true;
            // TZ 8.3: re-validate the stored point even though GCM already
            // authenticated it. Boolean convention - 1 means the point is safe.
            if (!mw_point_check_public(&keys_out->pub.spend)) {
                err = MW_ERR_SUBGROUP;
                break;
            }
            // Fills pub.view and re-checks it; leaves pub.spend alone because
            // view_only is set.
            err = mw_keys_derive_public(keys_out);
            break;
        default:
            err = MW_ERR_FORMAT;
            break;
    }

done:
    // The seed is gone before this function returns, on every path.
    mw_memzero(seed, sizeof seed);
    seed_len = 0;
    (void)seed_len;
    if (err != MW_OK && keys_out) mw_memzero(keys_out, sizeof *keys_out);
    return err;
}

// task 3 item 5: open the base wallet or the passphrase wallet of a record.
mw_err_t mw_wallet_open(uint32_t id, const char* passphrase,
                        mw_account_keys_t* keys_out, bool* verified)
{
    uint8_t  plain[MW_SEAL_PLAIN_LEN];
    uint8_t  check[MW_PP_CHECK_LEN];
    char     label[40];
    const wallet_entry_t* w;
    mw_err_t err;
    int      idx;
    const bool with_pp = passphrase && passphrase[0] != '\0';

    memset(plain, 0, sizeof plain);
    memset(check, 0, sizeof check);
    if (verified) *verified = false;
    if (!keys_out) return MW_ERR_INVALID_ARG;
    if ((err = ensure_loaded()) != MW_OK) return err;
    idx = find_index(id);
    if (idx < 0) return MW_ERR_INVALID_ARG;
    w = &g_store.wallets[idx];

    const uint8_t state = mw_wallet_pp_state(id);
    if (with_pp && state == MW_PP_NONE) return MW_ERR_INVALID_ARG;

    err = mw_wallet_load_keys(id, with_pp ? passphrase : "", keys_out);
    if (err != MW_OK || !with_pp) {
        if (err == MW_OK && verified) *verified = true;
        return err;
    }
    if (state != MW_PP_SET) return MW_OK;       // old record: nothing to check

    seed_label(id, label, sizeof label);
    err = mw_unseal(label, w->encrypted_seed, sizeof w->encrypted_seed,
                    w->seed_iv, w->seed_tag, plain, sizeof plain);
    if (err == MW_OK) {
        if (plain[MW_PP_REC_OFF] != MW_PP_REC_MARKER ||
            plain[MW_PP_REC_OFF + 1] != MW_PP_REC_VERSION) {
            err = MW_ERR_FORMAT;
        } else {
            pp_check_of(keys_out, check);
            err = mw_ct_equal(check, plain + MW_PP_REC_OFF + 2, MW_PP_CHECK_LEN)
                      ? MW_OK : MW_ERR_DECRYPT;
        }
    }
    mw_memzero(plain, sizeof plain);
    mw_memzero(check, sizeof check);
    if (err != MW_OK) {
        mw_memzero(keys_out, sizeof *keys_out);
        return err;
    }
    if (verified) *verified = true;
    return MW_OK;
}

// TZ 7.2: secure erase.  The record is overwritten in place and committed
// before the entry is removed, so the old ciphertext is not simply orphaned.
// See docs/security.md for what flash wear-levelling does and does not
// guarantee here.
mw_err_t mw_wallet_delete(uint32_t id)
{
    wallet_entry_t* w;
    mw_err_t err;
    int idx;
    uint32_t i;

    err = ensure_loaded();
    if (err != MW_OK) return err;

    idx = find_index(id);
    if (idx < 0) return MW_ERR_INVALID_ARG;
    w = &g_store.wallets[idx];

    // Pass 1 and 2: random. Pass 3: zeros. Each one is committed to storage.
    // Fields are scrubbed individually rather than with one memset over the
    // struct so the bool members never hold a trap representation.
    for (int pass = 0; pass < 3; pass++) {
        if (pass < 2) {
            mw_random_bytes(w->encrypted_seed, sizeof w->encrypted_seed);
            mw_random_bytes(w->seed_iv,        sizeof w->seed_iv);
            mw_random_bytes(w->seed_tag,       sizeof w->seed_tag);
            mw_random_bytes(w->name,           sizeof w->name);
            mw_random_bytes(&w->restore_height, sizeof w->restore_height);
            mw_random_bytes(&w->wallet_type,    sizeof w->wallet_type);
        } else {
            mw_memzero(w->encrypted_seed, sizeof w->encrypted_seed);
            mw_memzero(w->seed_iv,        sizeof w->seed_iv);
            mw_memzero(w->seed_tag,       sizeof w->seed_tag);
            mw_memzero(w->name,           sizeof w->name);
            w->restore_height = 0;
            w->wallet_type    = 0;
        }
        w->name[WALLET_NAME_LEN - 1] = '\0';
        w->is_view_only = false;
        w->is_hidden    = false;
        // The id is kept so the directory stays structurally valid between
        // passes; it is dropped together with the slot below.
        err = persist();
        if (err != MW_OK) return err;
    }

    // Remove the slot and compact.
    for (i = (uint32_t)idx; i + 1 < g_store.count; i++)
        g_store.wallets[i] = g_store.wallets[i + 1];
    memset(&g_store.wallets[g_store.count - 1], 0, sizeof g_store.wallets[0]);
    g_store.count--;

    if (g_store.active_wallet_id == id)
        g_store.active_wallet_id = (g_store.count > 0) ? g_store.wallets[0].id : 0;

    err = persist();
    // The key image cache of both passphrase variants goes with the wallet.
    (void)mw_ki_cache_erase_wallet(id);
    return err;
}

// TZ 7.1: hidden wallets are skipped by the wallet list unless the UI's
// "show hidden" toggle is on.  This is convenience, not security - the record
// is still in the directory and a flash dump still shows it exists.
mw_err_t mw_wallet_set_hidden(uint32_t id, bool hidden)
{
    mw_err_t err = ensure_loaded();
    int idx;

    if (err != MW_OK) return err;
    idx = find_index(id);
    if (idx < 0) return MW_ERR_INVALID_ARG;
    if (g_store.wallets[idx].is_hidden == hidden) return MW_OK;
    g_store.wallets[idx].is_hidden = hidden;
    return persist();
}

mw_err_t mw_wallet_rename(uint32_t id, const char* name)
{
    mw_err_t err;
    int idx;

    err = ensure_loaded();
    if (err != MW_OK) return err;
    err = name_valid(name);
    if (err != MW_OK) return err;

    idx = find_index(id);
    if (idx < 0) return MW_ERR_INVALID_ARG;
    if (name_taken(name, idx)) return MW_ERR_INVALID_ARG;

    memset(g_store.wallets[idx].name, 0, WALLET_NAME_LEN);
    snprintf(g_store.wallets[idx].name, WALLET_NAME_LEN, "%s", name);
    return persist();
}

mw_err_t mw_wallet_set_active(uint32_t id)
{
    mw_err_t err = ensure_loaded();
    if (err != MW_OK) return err;
    if (find_index(id) < 0) return MW_ERR_INVALID_ARG;
    g_store.active_wallet_id = id;
    return persist();
}

const wallet_entry_t* mw_wallet_get(uint32_t id)
{
    int idx;
    if (ensure_loaded() != MW_OK) return NULL;
    idx = find_index(id);
    return (idx < 0) ? NULL : &g_store.wallets[idx];
}

mw_err_t mw_wallet_store_count(uint32_t* count)
{
    mw_err_t err;
    if (!count) return MW_ERR_INVALID_ARG;
    *count = 0;
    err = ensure_loaded();
    if (err != MW_OK) return err;
    *count = g_store.count;
    return MW_OK;
}

uint32_t mw_wallet_ki_gen(uint32_t id, uint8_t variant)
{
    int idx;
    if (variant > 1 || ensure_loaded() != MW_OK) return 0;
    idx = find_index(id);
    return idx < 0 ? 0 : g_store.wallets[idx].ki_gen[variant];
}

mw_err_t mw_wallet_ki_gen_set(uint32_t id, uint8_t variant, uint32_t gen)
{
    int idx;
    mw_err_t err;
    if (variant > 1) return MW_ERR_INVALID_ARG;
    if ((err = ensure_loaded()) != MW_OK) return err;
    idx = find_index(id);
    if (idx < 0) return MW_ERR_INVALID_ARG;
    if (g_store.wallets[idx].ki_gen[variant] == gen) return MW_OK;
    g_store.wallets[idx].ki_gen[variant] = gen;
    return persist();
}

// ---------------------------------------------------------------------------
// Users
// ---------------------------------------------------------------------------

// Runs with `key` installed and puts the previous key (or none) back.
typedef struct { uint8_t key[32]; bool had; } key_save_t;
static void key_push(key_save_t* k, const uint8_t key[32])
{
    k->had = mw_secure_user_key_copy(k->key) == MW_OK;
    (void)mw_secure_user_key_set(key);
}
static void key_pop(key_save_t* k)
{
    if (k->had) (void)mw_secure_user_key_set(k->key);
    else        mw_secure_user_key_clear();
    mw_memzero(k, sizeof *k);
}

// Scratch directory for operations on a user that is not the loaded one.
static wallet_store_t* scratch_alloc(void)
{
    return (wallet_store_t*)dir_alloc(sizeof(wallet_store_t));
}
static void scratch_free(wallet_store_t* s) { dir_free(s, sizeof(wallet_store_t)); }

mw_err_t mw_wallet_store_user_probe(const uint8_t key[32], uint8_t* info,
                                    uint8_t new_key[32])
{
    key_save_t ks;
    uint32_t next = 0;
    uint8_t flags = 0, other[32];
    if (!key) return MW_ERR_INVALID_ARG;
    if (info) *info = 0;
    wallet_store_t* s = scratch_alloc();
    if (!s) return MW_ERR_MEMORY;
    key_push(&ks, key);
    mw_err_t e = dir_read(s, &next, &flags, other);
    key_pop(&ks);
    scratch_free(s);
    if (e == MW_OK) {
        if (info && (flags & DIR_F_PRIMARY)) *info |= MW_USER_PRIMARY;
        if (flags & DIR_F_SUPER) {
            if (info) *info |= MW_USER_SUPERSEDED;
            if (new_key) memcpy(new_key, other, 32);
        }
    }
    mw_memzero(other, sizeof other);
    if (e == MW_ERR_IO) return MW_ERR_DECRYPT;          // no such user
    // DECRYPT: a file of that name that does not open - no usable user.
    // Anything else is a storage fault, not a wrong password.
    return e;
}

mw_err_t mw_wallet_store_mark_primary(void)
{
    mw_err_t e = ensure_loaded();
    if (e != MW_OK) return e;
    if (g_dir_flags & DIR_F_PRIMARY) return MW_OK;
    g_dir_flags |= DIR_F_PRIMARY;
    return persist();
}

mw_err_t mw_wallet_store_user_create(const uint8_t key[32])
{
    key_save_t ks;
    char name[MW_FSTORE_NAME_MAX + 1];
    size_t len = 0;
    uint8_t zero[32];
    if (!key) return MW_ERR_INVALID_ARG;
    memset(zero, 0, sizeof zero);
    wallet_store_t* s = scratch_alloc();
    if (!s) return MW_ERR_MEMORY;
    memset(s, 0, sizeof *s);
    key_push(&ks, key);
    mw_err_t e = dir_name(name);
    if (e == MW_OK && mw_fstore_size(name, &len) == MW_OK) e = MW_ERR_EXISTS;
    if (e == MW_OK) e = dir_write(s, 1, 0, zero);
    key_pop(&ks);
    scratch_free(s);
    return e;
}

mw_err_t mw_wallet_store_user_destroy(void)
{
    uint32_t i;
    mw_err_t err = ensure_loaded();
    if (err != MW_OK) return err;
    for (i = 0; i < g_store.count && i < MAX_WALLETS; i++)
        (void)mw_ki_cache_erase_wallet(g_store.wallets[i].id);
    err = dir_remove();
    mw_wallet_store_close();
    return err;
}

int mw_wallet_store_user_files(void)
{
    return mw_fstore_list(DIR_PREFIX, NULL, 0);
}

mw_err_t mw_wallet_store_decoys_ensure(void)
{
    const int n = mw_wallet_store_user_files();
    if (n < 0) return MW_ERR_IO;
    if (n >= MW_USER_FILES_MIN) return MW_OK;
    uint8_t r = 0;
    mw_random_bytes(&r, 1);
    const int target = MW_USER_FILES_MIN + (int)(r % (MW_USER_DECOYS_MAX - MW_USER_FILES_MIN + 1));
    uint8_t* f = (uint8_t*)dir_alloc(DIR_FILE_LEN);
    if (!f) return MW_ERR_MEMORY;
    mw_err_t e = MW_OK;
    for (int k = n; k < target && e == MW_OK; k++) {
        uint8_t id[12];
        char name[MW_FSTORE_NAME_MAX + 1];
        size_t len = 0;
        mw_random_bytes(id, sizeof id);
        hex_name(id, sizeof id, DIR_PREFIX, name, sizeof name);
        if (mw_fstore_size(name, &len) == MW_OK) { k--; continue; }
        mw_random_bytes(f, DIR_FILE_LEN);
        e = mw_fstore_write(name, f, DIR_FILE_LEN);
    }
    dir_free(f, DIR_FILE_LEN);
    return e;
}

bool mw_wallet_store_any_data(void)
{
    uint8_t blob[BLOB_LEN];
    size_t len = 0;
    bool any = false;
    if (mw_store_blob_read(MW_WALLETS_BLOB_KEY, blob, sizeof blob, &len) == MW_OK)
        any = len >= 6 && blob[5] != 0;
    mw_memzero(blob, sizeof blob);
    return any || mw_wallet_store_user_files() > 0;
}

// Moves the pre-v9 NVS directory to the user whose key is installed. When
// that user already has a directory, the blob is a leftover - an empty one
// that firmware before v9 wrote at every boot, or one whose erase failed
// after it was moved - and is only dropped: merging it could bring back
// wallets deleted since.
mw_err_t mw_wallet_store_migrate_legacy(void)
{
    uint8_t blob[BLOB_LEN];
    size_t len = 0;
    uint32_t next = 1, i, dnext = 1;
    uint8_t zero[32], flags = 0, other[32];
    mw_err_t e;
    memset(zero, 0, sizeof zero);
    memset(other, 0, sizeof other);
    if (mw_store_blob_read(MW_WALLETS_BLOB_KEY, blob, sizeof blob, &len) != MW_OK)
        return MW_OK;                                    // nothing to move
    wallet_store_t* old = scratch_alloc();
    wallet_store_t* cur = scratch_alloc();
    if (!old || !cur) {
        e = MW_ERR_MEMORY;
        goto out;
    }
    e = dir_read(cur, &dnext, &flags, other);
    if (e == MW_OK) {
        e = mw_store_blob_erase(MW_WALLETS_BLOB_KEY);
        goto out;
    }
    if (e != MW_ERR_IO) {
        MW_LOGE("wallet", "user directory unreadable (%s): old directory left in place",
                mw_err_str(e));
        goto out;
    }
    e = legacy_deserialize(old, &next, blob, len);
    if (e != MW_OK) {
        MW_LOGE("wallet", "old wallet directory unreadable (%s): left in place", mw_err_str(e));
        goto out;
    }
    for (i = 0; i < old->count; i++) {
        old->wallets[i].ki_gen[0] = old->wallets[i].ki_gen[1] = 0;
        mw_ki_cache_migrate_legacy(old->wallets[i].id, old->wallets[i].ki_gen);
    }
    e = dir_write(old, next, DIR_F_PRIMARY, zero);
    if (e == MW_OK) e = mw_store_blob_erase(MW_WALLETS_BLOB_KEY);
    if (e == MW_OK) {
        if (old->count)
            MW_LOGI("wallet", "%u wallet(s) moved to the user directory", (unsigned)old->count);
        mw_wallet_store_close();
    }
out:
    mw_memzero(blob, sizeof blob);
    mw_memzero(other, sizeof other);
    scratch_free(old);
    scratch_free(cur);
    return e;
}

#ifdef MW_HOST_BUILD
static int g_host_stop_after_commit;
void mw_host_wallet_store_stop_after_commit(void);
void mw_host_wallet_store_stop_after_commit(void) { g_host_stop_after_commit = 1; }
#endif

// Steps 4..6 of a re-key: key image caches, old directory, flags. `st` is
// the directory under new_key; new_key is installed on return. On a failure
// the change stays committed and pending: the next login finishes it.
static mw_err_t rekey_finish(wallet_store_t* st, uint32_t next, uint8_t keep,
                             const uint8_t old_key[32], const uint8_t new_key[32])
{
    uint8_t zero[32];
    uint32_t i;
    mw_err_t e;
    memset(zero, 0, sizeof zero);
    for (i = 0; i < st->count && i < MAX_WALLETS; i++)
        mw_ki_cache_move(st->wallets[i].id, old_key, new_key);
    (void)mw_secure_user_key_set(old_key);
    e = dir_remove();
    (void)mw_secure_user_key_set(new_key);
    if (e == MW_OK) e = dir_write(st, next, keep, zero);
    mw_wallet_store_close();          // reloaded from storage, under new_key
    if (e != MW_OK)
        MW_LOGE("wallet", "password change: clean-up deferred to the next login (%s)",
                mw_err_str(e));
    return e;
}

mw_err_t mw_wallet_store_resume(void)
{
    mw_err_t e = ensure_loaded();
    if (e != MW_OK) return e;
    if (!(g_dir_flags & DIR_F_FROM)) return MW_OK;
    uint8_t old_key[32], new_key[32];
    memcpy(old_key, g_dir_other, 32);
    const uint8_t keep = (uint8_t)(g_dir_flags & DIR_F_PRIMARY);
    e = mw_secure_user_key_copy(new_key);
    wallet_store_t* st = e == MW_OK ? scratch_alloc() : NULL;
    if (e == MW_OK && !st) e = MW_ERR_MEMORY;
    if (e == MW_OK) {
        MW_LOGI("wallet", "finishing an interrupted password change");
        memcpy(st, &g_store, sizeof *st);
        e = rekey_finish(st, g_next_id, keep, old_key, new_key);
        if (e == MW_OK) e = ensure_loaded();
    }
    scratch_free(st);
    mw_memzero(old_key, sizeof old_key);
    mw_memzero(new_key, sizeof new_key);
    return e;
}

static bool g_rekey_committed;
bool mw_wallet_store_rekey_committed(void) { return g_rekey_committed; }

// The 64-byte sealed plaintexts are moved from one user key to the other
// without being interpreted.
mw_err_t mw_wallet_store_rekey(const uint8_t old_key[32], const uint8_t new_key[32])
{
    uint8_t  plain[MW_SEAL_PLAIN_LEN];
    char     label[40];
    uint8_t  flags = 0, other[32], keep;
    uint32_t next = 1, i;
    mw_err_t err;

    g_rekey_committed = false;
    if (!old_key || !new_key) return MW_ERR_INVALID_ARG;
    memset(plain, 0, sizeof plain);
    memset(other, 0, sizeof other);
    wallet_store_t* st = scratch_alloc();
    if (!st) {
        // Memory is short; whether the change is committed decides what the
        // caller may do: never roll back a committed one.
        char name[MW_FSTORE_NAME_MAX + 1];
        size_t len = 0;
        (void)mw_secure_user_key_set(new_key);
        g_rekey_committed = dir_name(name) == MW_OK && mw_fstore_size(name, &len) == MW_OK;
        (void)mw_secure_user_key_set(g_rekey_committed ? new_key : old_key);
        return MW_ERR_MEMORY;
    }

    // Resumed: the directory under new_key already exists (committed). From
    // here on the change is never rolled back; leftovers are retried.
    (void)mw_secure_user_key_set(new_key);
    err = dir_read(st, &next, &flags, other);
    if (err == MW_OK) {
        g_rekey_committed = true;
        (void)rekey_finish(st, next, (uint8_t)(flags & DIR_F_PRIMARY), old_key, new_key);
        err = MW_OK;
        goto out;
    }
    if (err != MW_ERR_IO) {
        // It exists but does not read now: committed, finished later.
        g_rekey_committed = true;
        mw_wallet_store_close();
        goto out;
    }

    // 1. The source directory. None yet: a directory of firmware before v9
    //    may still sit in NVS (a change it started, finished now) - it is
    //    moved under old_key first; otherwise an empty user.
    (void)mw_secure_user_key_set(old_key);
    err = dir_read(st, &next, &flags, other);
    if (err == MW_ERR_IO) {
        err = mw_wallet_store_migrate_legacy();
        if (err == MW_OK) err = dir_read(st, &next, &flags, other);
        if (err == MW_ERR_IO) {
            memset(st, 0, sizeof *st);
            next = 1;
            flags = 0;
            err = MW_OK;
        }
    } else if (err == MW_OK) {
        // 2. Mark it superseded, so the old password completes the change.
        err = dir_write(st, next, (uint8_t)(DIR_F_SUPER | (flags & DIR_F_PRIMARY)), new_key);
    }
    if (err != MW_OK) goto fail;
    keep = (uint8_t)(flags & DIR_F_PRIMARY);

    // 3. Re-seal every record in RAM. A record already under new_key (a
    //    change of firmware before v9, interrupted after its own re-key) is
    //    left as it is.
    for (i = 0; i < st->count && i < MAX_WALLETS; i++) {
        wallet_entry_t* w = &st->wallets[i];
        seed_label(w->id, label, sizeof label);
        (void)mw_secure_user_key_set(old_key);
        err = mw_unseal(label, w->encrypted_seed, sizeof w->encrypted_seed,
                        w->seed_iv, w->seed_tag, plain, sizeof plain);
        if (err == MW_ERR_DECRYPT) {
            (void)mw_secure_user_key_set(new_key);
            if (mw_unseal(label, w->encrypted_seed, sizeof w->encrypted_seed,
                          w->seed_iv, w->seed_tag, plain, sizeof plain) == MW_OK) {
                mw_memzero(plain, sizeof plain);
                err = MW_OK;
                continue;
            }
            err = MW_ERR_DECRYPT;
        }
        if (err != MW_OK) break;
        (void)mw_secure_user_key_set(new_key);
        err = mw_seal(label, plain, sizeof plain, w->seed_iv, w->seed_tag,
                      w->encrypted_seed, sizeof w->encrypted_seed);
        if (err != MW_OK) break;
    }
    mw_memzero(plain, sizeof plain);
    if (err != MW_OK) goto fail;

    // 4. Commit point: the new directory, remembering the old key.
    (void)mw_secure_user_key_set(new_key);
    err = dir_write(st, next, (uint8_t)(DIR_F_FROM | keep), old_key);
    if (err != MW_OK) {
        (void)mw_secure_user_key_set(new_key);
        (void)dir_remove();
        goto fail;
    }
    g_rekey_committed = true;
#ifdef MW_HOST_BUILD
    if (g_host_stop_after_commit) {               // tests: power lost right here
        g_host_stop_after_commit = 0;
        mw_wallet_store_close();
        err = MW_OK;
        goto out;
    }
#endif
    // 5..6. Key image caches, the old directory, the final flags. A failure
    // here is finished at the next login (resume / probe).
    (void)rekey_finish(st, next, keep, old_key, new_key);
    err = MW_OK;
    goto out;

fail:
    // Back to old_key: drop the "superseded" mark, reload the directory.
    (void)mw_secure_user_key_set(old_key);
    {
        wallet_store_t* back = scratch_alloc();
        uint8_t fl = 0, ot[32];
        uint32_t nx = 1;
        memset(ot, 0, sizeof ot);
        if (back && dir_read(back, &nx, &fl, ot) == MW_OK && (fl & DIR_F_SUPER)) {
            uint8_t zero[32];
            memset(zero, 0, sizeof zero);
            (void)dir_write(back, nx, (uint8_t)(fl & DIR_F_PRIMARY), zero);
        }
        mw_memzero(ot, sizeof ot);
        scratch_free(back);
    }
    mw_wallet_store_close();
    (void)ensure_loaded();
out:
    mw_memzero(other, sizeof other);
    scratch_free(st);
    return err;
}
