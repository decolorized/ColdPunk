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
#include "../crypto/aes_gcm.h"
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

// One sealed directory file per user (see wallet_store.h).
//   file      = iv[16] || tag[16] || AES-GCM(plaintext)
//   plaintext = header || MAX_WALLETS records
// Version 2 (v9.2):
//   header[128] [0..3] "MWUD" [4] 2 [5] count [6] flags [8..11] active id
//               [12..15] next id [16..47] the other key of an interrupted
//               password change [48..63] account name [64..67] generation
//               of the key image container (ki_cache.c)
//               v0.3 (zero in older files): [68..83] account uid
//               [84..87] container size last warned about (64 KiB steps)
//               [88] account options (MW_ACC_OPT_*)
//               [89] 0.3.2: storage format the account was brought to
//               (DIR_FMT; upgrade() has nothing to look for below it)
//   record[184] the 140 bytes of the NVS record; v0.3: [140] network
//               (MW_WNET_*) [141] balance flags [144..151] manual balance;
//               then the passphrase hint [152..183] (NUL-ended)
// Version 3 (0.3.5): the same header, record[248] = the version 2 record and
//               the passphrase record [184..247] (wallet_entry_t.pp_rec).
// Version 1 (v9.1, read and converted): header[64] (no generation),
// record[152] (per-wallet generations at 140..147, no hint).
// The file has the same size whatever it holds, like the decoys; files of an
// older size (directories and decoys) are brought to the current one by
// slots_scan(), a padded directory keeps its older sealed length inside.
#define DIR_PREFIX     "u"
#define DIR_TAG        "mw.user.dir.v1"
#define DIR_LABEL      "mw.dir.v1"
#define DIR_VERSION    3
#define DIR_HDR        128
#define DIR_REC        248
#define DIR_PT_LEN     (DIR_HDR + MAX_WALLETS * DIR_REC)
#define DIR_FILE_LEN   (32 + DIR_PT_LEN)
#define DIR2_REC       184
#define DIR2_PT_LEN    (DIR_HDR + MAX_WALLETS * DIR2_REC)
#define DIR2_FILE_LEN  (32 + DIR2_PT_LEN)
#define DIR1_HDR       64
#define DIR1_REC       152
#define DIR1_PT_LEN    (DIR1_HDR + MAX_WALLETS * DIR1_REC)
#define DIR1_FILE_LEN  (32 + DIR1_PT_LEN)
#define DIR_F_FROM     0x01   // this is the NEW directory; other key = old key
#define DIR_F_SUPER    0x02   // this is the OLD directory; other key = new key
#define DIR_F_PRIMARY  0x04   // the first user's (the record's verifier)
#define DIR_FMT        3      // no per-wallet key image files of older firmware left


// ---------------------------------------------------------------------------
// Module state
// ---------------------------------------------------------------------------
static wallet_store_t g_store;
static uint32_t       g_next_id = 1;
static bool           g_loaded  = false;
// The loaded directory's flags and the other key of an interrupted change.
static uint8_t        g_dir_flags;
static uint8_t        g_dir_other[32];
// The loaded directory is in the v9.1 format (converted by upgrade()).
static bool           g_dir_v1;
// The loaded directory's version (written as DIR_VERSION by the next save).
static int            g_dir_ver;

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

// Non-secret scratch (decoy bytes): PSRAM when there is.
static void* rnd_alloc(size_t n)
{
#if defined(MW_WS_ESP_HEAP)
    void* p = heap_caps_malloc(n, MALLOC_CAP_SPIRAM | MALLOC_CAP_8BIT);
    if (p) return p;
#endif
    return malloc(n);
}

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
    memcpy(pt + 48, s->account, MW_ACCOUNT_NAME_LEN);
    pt[48 + MW_ACCOUNT_NAME_LEN - 1] = 0;
    put_u32(pt + 64, s->ki_gen);
    memcpy(pt + 68, s->uid, 16);
    put_u32(pt + 84, s->ki_warned);
    pt[88] = s->opts;
    pt[89] = s->fmt;
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
        r[140] = w->network;
        r[141] = w->bal_flags;
        put_u32(r + 144, (uint32_t)w->bal_manual);
        put_u32(r + 148, (uint32_t)(w->bal_manual >> 32));
        memcpy(r + 152, w->pp_hint, MW_PP_HINT_LEN);
        r[152 + MW_PP_HINT_LEN - 1] = 0;
        memcpy(r + 184, w->pp_rec, MW_PP_REC_LEN);
    }
}

// Version 1 or 2, by `ver`.
static mw_err_t dir_deserialize(wallet_store_t* s, uint32_t* next_id, uint8_t* flags,
                                uint8_t other[32], const uint8_t* pt, int ver)
{
    uint32_t i, count;
    const size_t hdr = ver == 1 ? DIR1_HDR : DIR_HDR;
    const size_t rec = ver == 1 ? DIR1_REC : ver == 2 ? DIR2_REC : DIR_REC;
    if (memcmp(pt, "MWUD", 4) != 0) return MW_ERR_MAGIC;
    if (pt[4] != ver) return MW_ERR_VERSION;
    count = pt[5];
    if (count > MAX_WALLETS) return MW_ERR_FORMAT;
    memset(s, 0, sizeof *s);
    s->count = count;
    *flags = pt[6];
    s->active_wallet_id = get_u32(pt + 8);
    *next_id = get_u32(pt + 12);
    if (*next_id == 0) *next_id = 1;
    memcpy(other, pt + 16, 32);
    memcpy(s->account, pt + 48, MW_ACCOUNT_NAME_LEN);
    s->account[MW_ACCOUNT_NAME_LEN - 1] = 0;
    if (ver != 1) {
        s->ki_gen = get_u32(pt + 64);
        memcpy(s->uid, pt + 68, 16);
        s->ki_warned = get_u32(pt + 84);
        s->opts = pt[88];
        s->fmt = pt[89];
    }
    for (i = 0; i < count; i++) {
        wallet_entry_t* w = &s->wallets[i];
        const uint8_t* r = pt + hdr + i * rec;
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
        w->pp_state       = (r[139] <= MW_PP_REC) ? r[139] : MW_PP_UNKNOWN;
        if (ver >= 3) memcpy(w->pp_rec, r + 184, MW_PP_REC_LEN);
        if (ver != 1) {
            memcpy(w->pp_hint, r + 152, MW_PP_HINT_LEN);
            w->pp_hint[MW_PP_HINT_LEN - 1] = 0;
            w->network    = r[140] <= MW_WNET_TESTNET ? r[140] : MW_WNET_DEFAULT;
            w->bal_flags  = r[141];
            w->bal_manual = (uint64_t)get_u32(r + 144) | ((uint64_t)get_u32(r + 148) << 32);
        }
        if (w->id == 0) return MW_ERR_FORMAT;
        if (w->id >= *next_id) *next_id = w->id + 1;
    }
    return MW_OK;
}

// Seals and writes `s` as the directory of the installed user key (always
// version DIR_VERSION).
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

// Reads the directory of the installed user key (version 3, 2 or 1 - then
// *v1 is set when v1 is not NULL; *ver_out gets the version).
//   MW_ERR_IO       there is no such file
//   MW_ERR_DECRYPT  a file of that name does not open (damaged)
//   MW_ERR_FORMAT   it exists but could not be read (never "no file")
static mw_err_t dir_read_vv(wallet_store_t* s, uint32_t* next_id, uint8_t* flags,
                            uint8_t other[32], bool* v1, int* ver_out)
{
    char name[MW_FSTORE_NAME_MAX + 1];
    size_t len = 0;
    if (v1) *v1 = false;
    mw_err_t e = dir_name(name);
    if (e != MW_OK) return e;
    if (mw_fstore_size(name, &len) != MW_OK) return MW_ERR_IO;
    if (len != DIR_FILE_LEN && len != DIR2_FILE_LEN && len != DIR1_FILE_LEN)
        return MW_ERR_FORMAT;
    const int ver = len == DIR1_FILE_LEN ? 1 : len == DIR2_FILE_LEN ? 2 : 3;
    const size_t fl = len, pl = len - 32;
    uint8_t* pt = (uint8_t*)dir_alloc(pl);
    uint8_t* f  = (uint8_t*)dir_alloc(fl);
    if (!pt || !f) {
        dir_free(pt, pl);
        dir_free(f, fl);
        return MW_ERR_MEMORY;
    }
    e = mw_fstore_read(name, f, fl, &len);
    if (e != MW_OK) e = MW_ERR_FORMAT;            // it exists: a read fault
    if (e == MW_OK && len != fl) e = MW_ERR_FORMAT;
    int used = ver;
    if (e == MW_OK) {
        e = mw_unseal(DIR_LABEL, f + 32, pl, f, f + 16, pt, pl);
        if (e == MW_ERR_DECRYPT && ver == 3) {
            // A version 2 directory padded to the current size (slots_scan).
            e = mw_unseal(DIR_LABEL, f + 32, DIR2_PT_LEN, f, f + 16, pt, DIR2_PT_LEN);
            used = 2;
        }
        if (e == MW_ERR_DECRYPT && ver >= 2) {
            // A v9.1 directory padded to a later size (slots_scan).
            e = mw_unseal(DIR_LABEL, f + 32, DIR1_PT_LEN, f, f + 16, pt, DIR1_PT_LEN);
            used = 1;
        }
    }
    if (e == MW_OK) e = dir_deserialize(s, next_id, flags, other, pt, used);
    if (e == MW_OK && v1) *v1 = used == 1;
    if (e == MW_OK && ver_out) *ver_out = used;
    dir_free(pt, pl);
    dir_free(f, fl);
    return e;
}

static mw_err_t dir_read_v(wallet_store_t* s, uint32_t* next_id, uint8_t* flags,
                           uint8_t other[32], bool* v1)
{
    return dir_read_vv(s, next_id, flags, other, v1, NULL);
}

static mw_err_t dir_read(wallet_store_t* s, uint32_t* next_id, uint8_t* flags,
                         uint8_t other[32])
{
    return dir_read_v(s, next_id, flags, other, NULL);
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
    g_dir_ver = DIR_VERSION;
    e = dir_read_vv(&g_store, &g_next_id, &g_dir_flags, g_dir_other, &g_dir_v1, &g_dir_ver);
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


// ---- the passphrase record (0.3.5) ----------------------------------------
// wallet_entry_t.pp_rec: [0] version [1..3] 0 [4..15] IV [16..47] the
// passphrase wallet's private spend key under AES-256-GCM [48..63] tag.
// Key: pp_kdf() below. A wallet without a passphrase gets the version byte
// and random bytes; opening it runs exactly the same derivation and the same
// decryption, which fails like a wrong passphrase.
#define PP_REC_V1   1
#define PP_IV_OFF   4
#define PP_CT_OFF   16
#define PP_TAG_OFF  48

static mw_wallet_pp_progress_fn g_pp_prog;
static void*                    g_pp_prog_ctx;
static uint32_t                 g_pp_prog_base;

void mw_wallet_pp_set_progress(mw_wallet_pp_progress_fn fn, void* ctx)
{
    g_pp_prog = fn;
    g_pp_prog_ctx = ctx;
}

static void pp_prog_tick(uint32_t done, void* ctx)
{
    (void)ctx;
    if (!g_pp_prog) return;
    uint64_t d = (uint64_t)g_pp_prog_base + done;
    if (d > MW_PP_KDF_ROUNDS) d = MW_PP_KDF_ROUNDS;
    g_pp_prog((int)(d * 1000u / MW_PP_KDF_ROUNDS), g_pp_prog_ctx);
}

// out = HW_HMAC(tag || step || state): the eFuse key of this chip.
static mw_err_t pp_hw_step(const char* tag, uint8_t step, const uint8_t state[32],
                           uint8_t out[32])
{
    uint8_t msg[24 + 1 + 32];
    const size_t tl = strlen(tag);
    bool bound = false;
    memcpy(msg, tag, tl);
    msg[tl] = step;
    memcpy(msg + tl + 1, state, 32);
    mw_err_t e = mw_secure_hw_hmac(msg, tl + 1 + 32, out, &bound);
    mw_memzero(msg, sizeof msg);
    return e;
}

// The record key of wallet `id` for `passphrase`. Always the full work.
static mw_err_t pp_kdf(const char* passphrase, uint32_t id, const uint8_t uid[16],
                       uint8_t key[32])
{
    uint8_t salt[12 + 16 + 4 + 1], state[32], next_pw[64], h[32];
    const unsigned steps = MW_PP_KDF_HW_STEPS;
    const uint32_t per = MW_PP_KDF_ROUNDS / MW_PP_KDF_HW_STEPS;
    mw_err_t e = MW_OK;

    memcpy(salt, "mw.pp.kdf.v1", 12);
    memcpy(salt + 12, uid, 16);
    put_u32(salt + 28, id);
    salt[32] = 0;
    g_pp_prog_base = 0;
    mw_pbkdf2_set_progress(g_pp_prog ? pp_prog_tick : NULL, NULL);
    mw_pbkdf2_sha256((const uint8_t*)passphrase, strlen(passphrase), salt, sizeof salt, per,
                     state, sizeof state);
    for (unsigned i = 1; i < steps && e == MW_OK; ++i) {
        e = pp_hw_step("mw.pp.hw", (uint8_t)i, state, h);
        if (e != MW_OK) break;
        memcpy(next_pw, state, 32);
        memcpy(next_pw + 32, h, 32);
        salt[32] = (uint8_t)i;
        g_pp_prog_base = per * i;
        pp_prog_tick(0, NULL);
        mw_pbkdf2_sha256(next_pw, sizeof next_pw, salt, sizeof salt, per, state, sizeof state);
    }
    if (e == MW_OK) e = pp_hw_step("mw.pp.hw.final", 0, state, h);
    if (e == MW_OK) mw_hmac_sha256(h, sizeof h, state, sizeof state, key);
    mw_pbkdf2_set_progress(NULL, NULL);
    g_pp_prog_base = MW_PP_KDF_ROUNDS;
    pp_prog_tick(0, NULL);
    mw_memzero(state, sizeof state);
    mw_memzero(next_pw, sizeof next_pw);
    mw_memzero(h, sizeof h);
    mw_memzero(salt, sizeof salt);
    return e;
}

static void pp_aad(uint32_t id, const uint8_t uid[16], uint8_t aad[12 + 4 + 16])
{
    memcpy(aad, "mw.pp.rec.v1", 12);
    put_u32(aad + 12, id);
    memcpy(aad + 16, uid, 16);
}

// A record that opens to nothing.
static void pp_rec_random(uint8_t rec[MW_PP_REC_LEN])
{
    mw_random_bytes(rec, MW_PP_REC_LEN);
    rec[0] = PP_REC_V1;
    rec[1] = rec[2] = rec[3] = 0;
}

// The record of wallet `id` holding `spend` (the passphrase wallet's key).
static mw_err_t pp_rec_make(uint32_t id, const char* passphrase, const mw_seckey_t* spend,
                            uint8_t rec[MW_PP_REC_LEN])
{
    uint8_t uid[16], key[32], aad[32];
    mw_err_t e = mw_wallet_store_account_uid(uid);
    if (e == MW_OK) e = pp_kdf(passphrase, id, uid, key);
    if (e == MW_OK) {
        pp_rec_random(rec);                              // version, IV
        pp_aad(id, uid, aad);
        if (mw_aes256_gcm_encrypt(key, rec + PP_IV_OFF, 12, aad, sizeof aad,
                                  spend->b, 32, rec + PP_CT_OFF, rec + PP_TAG_OFF)
            != MW_AES_GCM_OK)
            e = MW_ERR_FORMAT;
    }
    mw_memzero(key, sizeof key);
    return e;
}

// Opens `rec`: MW_OK with keys_out, MW_ERR_DECRYPT when the passphrase is
// not the record's (or the record holds nothing).
static mw_err_t pp_rec_open(uint32_t id, const char* passphrase,
                            const uint8_t rec[MW_PP_REC_LEN], mw_account_keys_t* keys_out)
{
    uint8_t uid[16], key[32], aad[32], spend[32];
    mw_err_t e = mw_wallet_store_account_uid(uid);
    if (e == MW_OK) e = pp_kdf(passphrase, id, uid, key);
    if (e == MW_OK) {
        pp_aad(id, uid, aad);
        if (rec[0] != PP_REC_V1 ||
            mw_aes256_gcm_decrypt(key, rec + PP_IV_OFF, 12, aad, sizeof aad,
                                  rec + PP_CT_OFF, 32, rec + PP_TAG_OFF, spend)
                != MW_AES_GCM_OK)
            e = MW_ERR_DECRYPT;
    }
    if (e == MW_OK) {
        // spend = sc_reduce32(key32) of the seed offset scheme; the view key
        // follows from it exactly as mw_seed_to_keys() derives it.
        mw_keys_from_legacy_seed(spend, keys_out);
        e = mw_keys_derive_public(keys_out);
    }
    mw_memzero(spend, sizeof spend);
    mw_memzero(key, sizeof key);
    if (e != MW_OK) mw_memzero(keys_out, sizeof *keys_out);
    return e;
}

// `pp_pass` and `pp_keys`: the passphrase and its wallet (both or neither).
static mw_err_t create_entry(const char* name, uint8_t wallet_type, bool view_only,
                             const uint8_t* payload, size_t payload_len,
                             uint32_t restore_height, const char* pp_pass,
                             const mw_account_keys_t* pp_keys, uint32_t* id_out)
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
    // 0.3.5: no passphrase mark inside the sealed seed any more (bytes 48..63
    // stay random padding) - the record below is the same for every wallet.
    if (pp_keys && wallet_type != MW_WT_LEGACY && wallet_type != MW_WT_POLYSEED) {
        err = MW_ERR_INVALID_ARG;                // raw keys have no passphrase
        goto done;
    }

    w = &g_store.wallets[g_store.count];
    memset(w, 0, sizeof *w);
    if (pp_keys) {
        err = pp_rec_make(id, pp_pass, &pp_keys->sec.spend, w->pp_rec);
        if (err != MW_OK) { memset(w, 0, sizeof *w); goto done; }
    } else {
        pp_rec_random(w->pp_rec);
    }
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
    w->pp_state       = MW_PP_REC;
    // The device's network setting now: the wallet keeps it from here on.
    {
        mw_settings_t st;
        int net = MW_DEFAULT_NETWORK;
        if (mw_settings_load(&st) == MW_OK) net = st.network;
        w->network = net == MW_NET_STAGENET ? MW_WNET_STAGENET
                   : net == MW_NET_TESTNET  ? MW_WNET_TESTNET : MW_WNET_MAINNET;
    }

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
                        restore_height, NULL, NULL, id_out);
}

mw_err_t mw_wallet_create_pp(const char* name, mw_seed_type_t type,
                             const uint8_t* seed_material, size_t seed_len,
                             uint32_t restore_height, const char* passphrase,
                             const mw_account_keys_t* pp_keys, uint32_t* id_out)
{
    uint8_t wt;
    if (type == MW_SEED_MONERO_LEGACY)  wt = MW_WT_LEGACY;
    else if (type == MW_SEED_POLYSEED)  wt = MW_WT_POLYSEED;
    else                                return MW_ERR_INVALID_ARG;
    const bool with_pp = pp_keys && passphrase && passphrase[0];
    if (pp_keys && !with_pp) return MW_ERR_INVALID_ARG;
    return create_entry(name, wt, false, seed_material, seed_len, restore_height,
                        with_pp ? passphrase : NULL, with_pp ? pp_keys : NULL, id_out);
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
                       restore_height, NULL, NULL, id_out);

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

// 0.3.5: the passphrase wallet from the record (wallet_store.h).
mw_err_t mw_wallet_open_pp(uint32_t id, const char* passphrase,
                           mw_account_keys_t* keys_out)
{
    if (!keys_out || !passphrase) return MW_ERR_INVALID_ARG;
    mw_err_t err = ensure_loaded();
    if (err != MW_OK) return err;
    const int idx = find_index(id);
    if (idx < 0) return MW_ERR_INVALID_ARG;

    uint8_t rec[MW_PP_REC_LEN];
    memcpy(rec, g_store.wallets[idx].pp_rec, sizeof rec);
    const uint8_t state = g_store.wallets[idx].pp_state;
    const bool    seed  = g_store.wallets[idx].wallet_type == MW_WT_LEGACY ||
                          g_store.wallets[idx].wallet_type == MW_WT_POLYSEED;
    // The same work for every wallet and every passphrase (an empty one too).
    err = pp_rec_open(id, passphrase, rec, keys_out);
    if (err == MW_OK || err != MW_ERR_DECRYPT) return err;

    // A record from before 0.3.5 that was made with a passphrase: no record
    // yet. Opened the old way once (CryptoNight seed offset; checked when the
    // seed carries a check), then given its record so the next time is like
    // every other wallet.
    if (!passphrase[0] || !seed || rec[0] != 0 ||
        (state != MW_PP_SET && state != MW_PP_UNKNOWN))
        return MW_ERR_DECRYPT;
    bool verified = false;
    err = mw_wallet_open(id, passphrase, keys_out, &verified);
    if (err != MW_OK) return err;
    // MW_PP_UNKNOWN (no check in the seed): any passphrase opens some wallet,
    // so binding a record to it could lock out the right one - such a record
    // keeps being opened the old way.
    if (!verified) return MW_OK;
    err = pp_rec_make(id, passphrase, &keys_out->sec.spend, rec);
    if (err == MW_OK) {
        const int i2 = find_index(id);
        if (i2 >= 0) {
            memcpy(g_store.wallets[i2].pp_rec, rec, sizeof rec);
            g_store.wallets[i2].pp_state = MW_PP_REC;
            (void)persist();                 // tried again next time if this fails
        }
        MW_LOGI("wallet", "passphrase record created");
    }
    mw_memzero(rec, sizeof rec);
    return MW_OK;
}

// task 3 item 5: open the base wallet or (records from before 0.3.5 only) the
// passphrase wallet the old way.
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
    if (with_pp && state != MW_PP_SET && state != MW_PP_UNKNOWN) {
        // 0.3.5 records (and raw-key wallets): only through the record.
        err = mw_wallet_open_pp(id, passphrase, keys_out);
        if (err == MW_OK && verified) *verified = true;
        return err;
    }

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
    if (g_store.active_wallet_id == id) return MW_OK;     // no rewrite for nothing
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

uint32_t mw_wallet_store_ki_gen(void)
{
    return ensure_loaded() == MW_OK ? g_store.ki_gen : 0;
}

mw_err_t mw_wallet_store_ki_gen_set(uint32_t gen)
{
    mw_err_t err;
    if ((err = ensure_loaded()) != MW_OK) return err;
    if (g_store.ki_gen == gen) return MW_OK;
    g_store.ki_gen = gen;
    return persist();
}

mw_err_t mw_wallet_store_slot_hex(char out[MW_SLOT_HEX + 1])
{
    char name[MW_FSTORE_NAME_MAX + 1];
    mw_err_t e = dir_name(name);
    if (e == MW_OK) {
        memcpy(out, name + 1, MW_SLOT_HEX);
        out[MW_SLOT_HEX] = '\0';
    }
    return e;
}

mw_err_t mw_wallet_pp_hint(uint32_t id, char* out, size_t cap)
{
    int idx;
    if (!out || !cap) return MW_ERR_INVALID_ARG;
    out[0] = 0;
    mw_err_t e = ensure_loaded();
    if (e != MW_OK) return e;
    idx = find_index(id);
    if (idx < 0) return MW_ERR_INVALID_ARG;
    snprintf(out, cap, "%s", g_store.wallets[idx].pp_hint);
    return MW_OK;
}

mw_err_t mw_wallet_set_pp_hint(uint32_t id, const char* hint)
{
    int idx;
    size_t n;
    mw_err_t e;
    if (!hint) hint = "";
    n = strlen(hint);
    if (n >= MW_PP_HINT_LEN) return MW_ERR_INVALID_ARG;
    for (size_t i = 0; i < n; i++) {
        const unsigned char c = (unsigned char)hint[i];
        if (c < 0x20u || c == 0x7fu) return MW_ERR_INVALID_ARG;
    }
    if ((e = ensure_loaded()) != MW_OK) return e;
    idx = find_index(id);
    if (idx < 0) return MW_ERR_INVALID_ARG;
    memset(g_store.wallets[idx].pp_hint, 0, MW_PP_HINT_LEN);
    memcpy(g_store.wallets[idx].pp_hint, hint, n);
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

// ---- slots and decoys --------------------------------------------------
// A uniform choice in 0..n-1 (n > 0), without the bias of a plain modulo.
static uint32_t random_below(uint32_t n)
{
    const uint32_t limit = UINT32_MAX - (UINT32_MAX % n);
    uint32_t r;
    do {
        mw_random_bytes(&r, sizeof r);
    } while (r >= limit);
    return r % n;
}

// A slot is a directory file "u<hex>" and a key image container "c<hex>".
// A decoy slot: the "u" file is DIR_FILE_LEN random bytes whose bytes 16..31
// (where a directory has its GCM tag) are HMAC(eFuse key, "mw.decoy.v1" ||
// bytes 0..15); its "c" file is MW_KI_STORE_STEP random bytes. Without the
// chip both are as random as sealed data.
static mw_err_t decoy_tag(const uint8_t iv[16], uint8_t tag[16])
{
    uint8_t msg[11 + 16], mac[32];
    bool bound = false;
    memcpy(msg, "mw.decoy.v1", 11);
    memcpy(msg + 11, iv, 16);
    mw_err_t e = mw_secure_hw_hmac(msg, sizeof msg, mac, &bound);
    if (e == MW_OK) memcpy(tag, mac, 16);
    mw_memzero(mac, sizeof mac);
    return e;
}

static void cache_name_of(const char* dir, char out[MW_FSTORE_NAME_MAX + 1])
{
    snprintf(out, MW_FSTORE_NAME_MAX + 1, "c%s", dir + 1);
}

// Writes a decoy slot (both files; `f` holds MW_KI_STORE_STEP bytes).
static mw_err_t decoy_write(uint8_t* f)
{
    uint8_t id[12];
    char name[MW_FSTORE_NAME_MAX + 1], cname[MW_FSTORE_NAME_MAX + 1];
    size_t len = 0;
    mw_err_t e;
    do {
        mw_random_bytes(id, sizeof id);
        hex_name(id, sizeof id, DIR_PREFIX, name, sizeof name);
    } while (mw_fstore_size(name, &len) == MW_OK);
    cache_name_of(name, cname);
    mw_random_bytes(f, MW_KI_STORE_STEP);
    e = mw_fstore_write(cname, f, MW_KI_STORE_STEP);
    if (e != MW_OK) return e;
    mw_random_bytes(f, DIR_FILE_LEN);
    e = decoy_tag(f, f + 16);
    if (e == MW_OK) e = mw_fstore_write(name, f, DIR_FILE_LEN);
    return e;
}

// The verdicts of is_decoy(), per file and its mw_fstore_seq(): a slot file
// is read and its mark computed once until it changes (0.3.2: every login
// scanned all slots twice).
#define DECOY_CACHE 64
static struct {
    char     name[MW_FSTORE_NAME_MAX + 1];
    uint32_t seq;
    uint8_t  decoy, old;
} g_dc[DECOY_CACHE];
static unsigned g_dc_next;

// A decoy of any directory size (v9.1 decoys are DIR1_FILE_LEN, those of
// 0.3.0..0.3.4 DIR2_FILE_LEN).
static bool is_decoy(const char* name, uint8_t* f, bool* old_size)
{
    size_t len = 0;
    uint8_t tag[16];
    if (old_size) *old_size = false;
    const uint32_t seq = mw_fstore_seq(name);
    for (unsigned i = 0; seq && i < DECOY_CACHE; i++) {
        if (g_dc[i].seq == seq && strcmp(g_dc[i].name, name) == 0) {
            if (old_size) *old_size = g_dc[i].old != 0;
            return g_dc[i].decoy != 0;
        }
    }
    bool d = false;
    if (mw_fstore_size(name, &len) == MW_OK &&
        (len == DIR_FILE_LEN || len == DIR2_FILE_LEN || len == DIR1_FILE_LEN) &&
        mw_fstore_read(name, f, len, &len) == MW_OK && decoy_tag(f, tag) == MW_OK) {
        d = mw_ct_equal(tag, f + 16, 16) != 0;
        if (d && old_size) *old_size = len != DIR_FILE_LEN;
        if (seq) {
            // Remembered only when the answer came from the file itself.
            unsigned slot = DECOY_CACHE;
            for (unsigned i = 0; i < DECOY_CACHE && slot == DECOY_CACHE; i++)
                if (strcmp(g_dc[i].name, name) == 0) slot = i;
            if (slot == DECOY_CACHE) slot = g_dc_next++ % DECOY_CACHE;
            snprintf(g_dc[slot].name, sizeof g_dc[slot].name, "%s", name);
            g_dc[slot].seq = seq;
            g_dc[slot].decoy = d ? 1 : 0;
            g_dc[slot].old = (d && len != DIR_FILE_LEN) ? 1 : 0;
        }
    }
    return d;
}

static void slot_remove(const char* dir)
{
    char cname[MW_FSTORE_NAME_MAX + 1];
    cache_name_of(dir, cname);
    (void)mw_fstore_remove(dir);
    (void)mw_fstore_remove(cname);
}

// Names of the directory files; the decoys come first (`*decoys` of them).
// Decoys of the v9.1 size are replaced by current ones first. -1 on an I/O
// error.
#define SLOT_SCAN_MAX (MW_USER_FILES_MAX + 16)
static char g_slot_names[SLOT_SCAN_MAX][MW_FSTORE_NAME_MAX + 1];

static int slots_scan(int* decoys)
{
    *decoys = 0;
    uint8_t* f = (uint8_t*)rnd_alloc(MW_KI_STORE_STEP);
    if (!f) return -1;
    int n = mw_fstore_list(DIR_PREFIX, g_slot_names, SLOT_SCAN_MAX);
    for (int i = 0; i < n && i < SLOT_SCAN_MAX; i++) {
        bool old = false;
        size_t len = 0;
        char cname[MW_FSTORE_NAME_MAX + 1];
        if (is_decoy(g_slot_names[i], f, &old)) {
            if (old) {
                slot_remove(g_slot_names[i]);
                (void)decoy_write(f);
            }
            continue;
        }
        // An account of an older size that has not logged in since the
        // update: padded to the current size (dir_read_v() reads it), so it
        // does not stand out among the converted slots.
        if (mw_fstore_size(g_slot_names[i], &len) == MW_OK &&
            (len == DIR1_FILE_LEN || len == DIR2_FILE_LEN)) {
            const size_t old = len;
            if (mw_fstore_read(g_slot_names[i], f, old, &len) == MW_OK && len == old) {
                mw_random_bytes(f + old, DIR_FILE_LEN - old);
                (void)mw_fstore_write(g_slot_names[i], f, DIR_FILE_LEN);
            }
        }
        // Every slot has its container file; an account without one gets
        // random bytes until it logs in (an unreadable container is empty).
        cache_name_of(g_slot_names[i], cname);
        if (mw_fstore_size(cname, &len) != MW_OK) {
            mw_random_bytes(f, MW_KI_STORE_STEP);
            (void)mw_fstore_write(cname, f, MW_KI_STORE_STEP);
        }
    }
    n = mw_fstore_list(DIR_PREFIX, g_slot_names, SLOT_SCAN_MAX);
    for (int i = 0; i < n && i < SLOT_SCAN_MAX; i++) {
        if (!is_decoy(g_slot_names[i], f, NULL)) continue;
        if (i != *decoys) {
            char t[MW_FSTORE_NAME_MAX + 1];
            memcpy(t, g_slot_names[*decoys], sizeof t);
            memcpy(g_slot_names[*decoys], g_slot_names[i], sizeof t);
            memcpy(g_slot_names[i], t, sizeof t);
        }
        (*decoys)++;
    }
    dir_free(f, MW_KI_STORE_STEP);
    return n;
}

// How many accounts this device takes: MW_USERS_MIN..MW_USER_FILES_MAX,
// fixed per chip (HMAC of the eFuse key), so that filling the slots does not
// tell how many accounts there were.
static int capacity(void)
{
    uint8_t mac[32];
    bool bound = false;
    int c = MW_USERS_MIN;
    if (mw_secure_hw_hmac((const uint8_t*)"mw.capacity.v1", 14, mac, &bound) == MW_OK)
        c = MW_USERS_MIN + (int)(mac[0] % (MW_USER_FILES_MAX - MW_USERS_MIN + 1));
    mw_memzero(mac, sizeof mac);
    return c;
}

static mw_err_t name_check(const char* name, size_t cap)
{
    size_t i;
    bool vis = false;
    if (!name) return MW_ERR_INVALID_ARG;
    for (i = 0; name[i]; i++) {
        const unsigned char c = (unsigned char)name[i];
        if (c < 0x20u || c == 0x7fu) return MW_ERR_INVALID_ARG;
        if (c != ' ') vis = true;
    }
    if (i == 0 || i >= cap || !vis) return MW_ERR_INVALID_ARG;
    return MW_OK;
}

// Whether a slot may be given to another account: a decoy is left beyond
// the ones the capacity keeps.
static bool slot_free_now(int n, int decoys)
{
    if (n < 0) return false;
    const int accounts = n - decoys;
    if (n < MW_USER_FILES_MAX) return accounts < capacity();   // first start
    return decoys > 0 && accounts < capacity();
}

bool mw_wallet_store_slot_free(void)
{
    int decoys = 0;
    const int n = slots_scan(&decoys);
    return slot_free_now(n, decoys);
}

mw_err_t mw_wallet_store_user_create(const uint8_t key[32], const char* name)
{
    key_save_t ks;
    char fname[MW_FSTORE_NAME_MAX + 1];
    size_t len = 0;
    uint8_t zero[32];
    int decoys = 0;
    if (!key) return MW_ERR_INVALID_ARG;
    if (name && name[0] && name_check(name, MW_ACCOUNT_NAME_LEN) != MW_OK)
        return MW_ERR_INVALID_ARG;
    const int n = slots_scan(&decoys);
    if (n < 0) return MW_ERR_IO;
    if (!slot_free_now(n, decoys)) return MW_ERR_TOO_MANY;
    memset(zero, 0, sizeof zero);
    wallet_store_t* s = scratch_alloc();
    if (!s) return MW_ERR_MEMORY;
    memset(s, 0, sizeof *s);
    snprintf(s->account, sizeof s->account, "%s", (name && name[0]) ? name : "Account");
    s->fmt = DIR_FMT;                     // a new account has nothing old
    key_push(&ks, key);
    mw_err_t e = dir_name(fname);
    if (e == MW_OK && mw_fstore_size(fname, &len) == MW_OK) e = MW_ERR_EXISTS;
    if (e == MW_OK) e = dir_write(s, 1, 0, zero);
    if (e == MW_OK) {
        // Its container: the slot's second file, empty, generation 0 (that
        // of the new directory). Nothing of the logged-in account is touched.
        e = mw_ki_store_create_gen(0);
        if (e != MW_OK) (void)dir_remove();
    }
    key_pop(&ks);
    scratch_free(s);
    // The account first, then a decoy goes: a cut in between leaves one slot
    // too many, which decoys_ensure() drops.
    if (e == MW_OK && decoys > 0 && n >= MW_USER_FILES_MAX)
        slot_remove(g_slot_names[random_below((uint32_t)decoys)]);
    return e;
}

mw_err_t mw_wallet_store_account_name(char* out, size_t cap)
{
    if (!out || !cap) return MW_ERR_INVALID_ARG;
    out[0] = 0;
    mw_err_t e = ensure_loaded();
    if (e == MW_OK) snprintf(out, cap, "%s", g_store.account);
    return e;
}

mw_err_t mw_wallet_store_account_rename(const char* name)
{
    mw_err_t e = name_check(name, MW_ACCOUNT_NAME_LEN);
    if (e != MW_OK) return e;
    if ((e = ensure_loaded()) != MW_OK) return e;
    memset(g_store.account, 0, sizeof g_store.account);
    snprintf(g_store.account, sizeof g_store.account, "%s", name);
    return persist();
}

mw_err_t mw_wallet_store_account_uid(uint8_t out[16])
{
    if (!out) return MW_ERR_INVALID_ARG;
    mw_err_t e = ensure_loaded();
    if (e != MW_OK) return e;
    if (mw_ct_is_zero(g_store.uid, sizeof g_store.uid)) {
        // Accounts made before v0.3: one now, kept from here on.
        do {
            mw_random_bytes(g_store.uid, sizeof g_store.uid);
        } while (mw_ct_is_zero(g_store.uid, sizeof g_store.uid));
        e = persist();
        if (e != MW_OK) {
            memset(g_store.uid, 0, sizeof g_store.uid);
            return e;
        }
    }
    memcpy(out, g_store.uid, 16);
    return MW_OK;
}

int mw_wallet_store_accounts(void)
{
    int decoys = 0;
    const int n = slots_scan(&decoys);
    return n < 0 ? -1 : n - decoys;
}

uint8_t mw_wallet_store_opts(void)
{
    return ensure_loaded() == MW_OK ? g_store.opts : 0;
}

mw_err_t mw_wallet_store_set_opts(uint8_t opts)
{
    mw_err_t e = ensure_loaded();
    if (e != MW_OK) return e;
    if (g_store.opts == opts) return MW_OK;
    const uint8_t old = g_store.opts;
    g_store.opts = opts;
    e = persist();
    if (e != MW_OK) g_store.opts = old;
    return e;
}

uint32_t mw_wallet_store_ki_warned(void)
{
    return ensure_loaded() == MW_OK ? g_store.ki_warned : 0;
}

mw_err_t mw_wallet_store_set_ki_warned(uint32_t steps)
{
    mw_err_t e = ensure_loaded();
    if (e != MW_OK) return e;
    if (g_store.ki_warned == steps) return MW_OK;
    g_store.ki_warned = steps;
    return persist();
}

int mw_wallet_network(uint32_t id)
{
    const wallet_entry_t* w = mw_wallet_get(id);
    switch (w ? w->network : MW_WNET_DEFAULT) {
    case MW_WNET_MAINNET:  return MW_NET_MAINNET;
    case MW_WNET_STAGENET: return MW_NET_STAGENET;
    case MW_WNET_TESTNET:  return MW_NET_TESTNET;
    default: {
        mw_settings_t st;
        int n = MW_DEFAULT_NETWORK;
        if (mw_settings_load(&st) == MW_OK) n = st.network;
        return n;
    }
    }
}

mw_err_t mw_wallet_set_network(uint32_t id, uint8_t wnet)
{
    int idx;
    mw_err_t e;
    if (wnet > MW_WNET_TESTNET) return MW_ERR_INVALID_ARG;
    if ((e = ensure_loaded()) != MW_OK) return e;
    if ((idx = find_index(id)) < 0) return MW_ERR_INVALID_ARG;
    const uint8_t old = g_store.wallets[idx].network;
    g_store.wallets[idx].network = wnet;
    e = persist();
    if (e != MW_OK) g_store.wallets[idx].network = old;
    return e;
}

mw_err_t mw_wallet_set_manual_balance(uint32_t id, bool set, uint64_t piconero)
{
    int idx;
    mw_err_t e;
    if ((e = ensure_loaded()) != MW_OK) return e;
    if ((idx = find_index(id)) < 0) return MW_ERR_INVALID_ARG;
    wallet_entry_t* w = &g_store.wallets[idx];
    const uint8_t of = w->bal_flags;
    const uint64_t ov = w->bal_manual;
    if (set) { w->bal_flags |= MW_BAL_MANUAL; w->bal_manual = piconero; }
    else     { w->bal_flags &= (uint8_t)~MW_BAL_MANUAL; w->bal_manual = 0; }
    if (w->bal_flags == of && w->bal_manual == ov) return MW_OK;
    e = persist();
    if (e != MW_OK) { w->bal_flags = of; w->bal_manual = ov; }
    return e;
}

mw_err_t mw_wallet_store_user_destroy(void)
{
    mw_err_t err = ensure_loaded();
    if (err != MW_OK) return err;
    (void)mw_ki_store_remove();
    err = dir_remove();
    mw_wallet_store_close();
    if (err == MW_OK) (void)mw_wallet_store_decoys_ensure();   // the slot is a decoy again
    return err;
}

int mw_wallet_store_user_files(void)
{
    return mw_fstore_list(DIR_PREFIX, NULL, 0);
}

static mw_wallet_store_progress_fn g_ws_prog;
static void*                       g_ws_prog_ctx;
void mw_wallet_store_set_progress(mw_wallet_store_progress_fn fn, void* ctx)
{
    g_ws_prog = fn;
    g_ws_prog_ctx = ctx;
}
static void ws_progress(uint32_t done, uint32_t total)
{
    if (g_ws_prog) g_ws_prog(done, total, g_ws_prog_ctx);
}

mw_err_t mw_wallet_store_decoys_ensure(void)
{
    int decoys = 0;
    int n = slots_scan(&decoys);
    if (n < 0) return MW_ERR_IO;
    mw_err_t e = MW_OK;
    if (n > MW_USER_FILES_MAX) {
        for (int i = 0; i < decoys && n > MW_USER_FILES_MAX; i++, n--)
            slot_remove(g_slot_names[i]);
        return e;
    }
    uint8_t* f = (uint8_t*)rnd_alloc(MW_KI_STORE_STEP);
    if (!f) return MW_ERR_MEMORY;
    const uint32_t todo = (uint32_t)(MW_USER_FILES_MAX - n);
    for (uint32_t k = 0; n < MW_USER_FILES_MAX && e == MW_OK; n++, k++) {
        ws_progress(k, todo);
        e = decoy_write(f);
    }
    ws_progress(todo, todo);
    dir_free(f, MW_KI_STORE_STEP);
    return e;
}


#ifdef MW_HOST_BUILD
// Host tests: turns a wallet back into a record of firmware before 0.3.5 -
// no passphrase record, and (pp_keys != NULL) the old sealed check with
// state MW_PP_SET, else MW_PP_NONE.
mw_err_t mw_host_wallet_make_old(uint32_t id, const mw_account_keys_t* pp_keys);
mw_err_t mw_host_wallet_make_old(uint32_t id, const mw_account_keys_t* pp_keys)
{
    uint8_t plain[MW_SEAL_PLAIN_LEN];
    char label[40];
    mw_err_t e = ensure_loaded();
    if (e != MW_OK) return e;
    const int idx = find_index(id);
    if (idx < 0) return MW_ERR_INVALID_ARG;
    wallet_entry_t* w = &g_store.wallets[idx];
    seed_label(id, label, sizeof label);
    e = mw_unseal(label, w->encrypted_seed, sizeof w->encrypted_seed, w->seed_iv, w->seed_tag,
                  plain, sizeof plain);
    if (e != MW_OK) return e;
    if (pp_keys) {
        plain[MW_PP_REC_OFF]     = MW_PP_REC_MARKER;
        plain[MW_PP_REC_OFF + 1] = MW_PP_REC_VERSION;
        pp_check_of(pp_keys, plain + MW_PP_REC_OFF + 2);
    }
    e = mw_seal(label, plain, sizeof plain, w->seed_iv, w->seed_tag, w->encrypted_seed,
                sizeof w->encrypted_seed);
    mw_memzero(plain, sizeof plain);
    if (e != MW_OK) return e;
    memset(w->pp_rec, 0, sizeof w->pp_rec);
    w->pp_state = pp_keys ? MW_PP_SET : MW_PP_NONE;
    g_dir_ver = 2;
    return persist();
}
#endif

mw_err_t mw_wallet_store_upgrade(void)
{
    uint32_t i;
    mw_err_t e = ensure_loaded();
    if (e != MW_OK) return e;
    // Done before (0.3.2): only the container must exist. Wallets added
    // since never had files of an older format.
    // 0.3.5: every wallet without a passphrase record gets a random one - all
    // but the pre-0.3.5 passphrase wallets, which get theirs at their first
    // mw_wallet_open_pp() - and the directory is written in the current
    // version.
    {
        bool changed = g_dir_ver < DIR_VERSION;
        for (i = 0; i < g_store.count && i < MAX_WALLETS; i++) {
            wallet_entry_t* w = &g_store.wallets[i];
            const bool seed = w->wallet_type == MW_WT_LEGACY || w->wallet_type == MW_WT_POLYSEED;
            if (w->pp_rec[0] != 0) continue;
            if (seed && (w->pp_state == MW_PP_SET || w->pp_state == MW_PP_UNKNOWN)) continue;
            pp_rec_random(w->pp_rec);
            w->pp_state = MW_PP_REC;
            changed = true;
        }
        if (changed) {
            e = persist();
            if (e != MW_OK) return e;
            g_dir_ver = DIR_VERSION;
        }
    }
    if (!g_dir_v1 && g_store.fmt >= DIR_FMT) return mw_ki_store_create();
    if (g_dir_v1) {
        // v9.1 -> v2: the same records, the hint empty; per-wallet key image
        // generations are replaced by the container's.
        e = persist();
        if (e != MW_OK) return e;
        g_dir_v1 = false;
        MW_LOGI("wallet", "user directory converted to the current format");
    }
    for (i = 0; i < g_store.count && i < MAX_WALLETS; i++)
        mw_ki_cache_import_old(g_store.wallets[i].id);
    e = mw_ki_store_create();
    if (e != MW_OK) return e;
    // Marked only when nothing old is left (a failed import is retried).
    bool left = false;
    for (i = 0; i < g_store.count && i < MAX_WALLETS && !left; i++)
        left = mw_ki_cache_old_left(g_store.wallets[i].id);
    if (left) return MW_OK;
    if ((e = ensure_loaded()) != MW_OK) return e;    // import_old closed nothing, but be sure
    g_store.fmt = DIR_FMT;
    return persist();
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
    snprintf(old->account, sizeof old->account, "Main");
    e = dir_write(old, next, DIR_F_PRIMARY, zero);
    if (e == MW_OK) {
        // The key image caches follow into the account's container.
        mw_wallet_store_close();
        for (i = 0; i < old->count; i++) mw_ki_cache_import_old(old->wallets[i].id);
        (void)mw_ki_store_create();
        e = mw_store_blob_erase(MW_WALLETS_BLOB_KEY);
    }
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
// Host tests: writes `st` as a v9.1 directory of the installed key.
mw_err_t mw_host_wallet_store_write_v1(const wallet_store_t* st, uint32_t next_id);
mw_err_t mw_host_wallet_store_write_v1(const wallet_store_t* st, uint32_t next_id)
{
    char name[MW_FSTORE_NAME_MAX + 1];
    static uint8_t pt[DIR1_PT_LEN], f[DIR1_FILE_LEN];
    uint32_t i;
    mw_err_t e = dir_name(name);
    if (e != MW_OK) return e;
    memset(pt, 0, sizeof pt);
    memcpy(pt, "MWUD", 4);
    pt[4] = 1;
    pt[5] = (uint8_t)st->count;
    put_u32(pt + 8, st->active_wallet_id);
    put_u32(pt + 12, next_id);
    memcpy(pt + 48, st->account, MW_ACCOUNT_NAME_LEN);
    for (i = 0; i < st->count; i++) {
        const wallet_entry_t* w = &st->wallets[i];
        uint8_t* r = pt + DIR1_HDR + i * DIR1_REC;
        put_u32(r, w->id);
        memcpy(r + 4,   w->name, WALLET_NAME_LEN);
        memcpy(r + 36,  w->encrypted_seed, 64);
        memcpy(r + 100, w->seed_iv, 16);
        memcpy(r + 116, w->seed_tag, 16);
        put_u32(r + 132, w->restore_height);
        r[136] = w->wallet_type;
        r[137] = w->is_view_only ? 1u : 0u;
        r[138] = w->is_hidden ? 1u : 0u;
        r[139] = w->pp_state;
    }
    e = mw_seal(DIR_LABEL, pt, DIR1_PT_LEN, f, f + 16, f + 32, DIR1_PT_LEN);
    if (e == MW_OK) e = mw_fstore_write(name, f, DIR1_FILE_LEN);
    mw_wallet_store_close();
    return e;
}

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
    mw_err_t e;
    memset(zero, 0, sizeof zero);
    // Per-wallet key image files of v9.1 still named under old_key (a change
    // interrupted then) cannot be followed: they go (rebuilt by an export).
    (void)mw_secure_user_key_set(old_key);
    for (uint32_t i = 0; i < st->count && i < MAX_WALLETS; i++)
        mw_ki_cache_drop_old(st->wallets[i].id);
    e = mw_ki_store_move(old_key, new_key);
    mw_wallet_store_close();
    if (e != MW_OK) {
        // Nothing lost: the change stays pending (FROM) and is finished at
        // the next login.
        MW_LOGE("wallet", "password change: key image caches not moved yet (%s)", mw_err_str(e));
        (void)mw_secure_user_key_set(new_key);
        return e;
    }
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

    // 1. The source directory, brought to the current format under old_key
    //    first: a directory of firmware before v9 may still sit in NVS (a
    //    change it started, finished now), a v9.1 one is converted, old key
    //    image files go into the container. None at all: an empty user.
    (void)mw_secure_user_key_set(old_key);
    mw_wallet_store_close();
    err = dir_read(st, &next, &flags, other);
    if (err == MW_ERR_IO) (void)mw_wallet_store_migrate_legacy();
    mw_wallet_store_close();
    if (!(flags & (DIR_F_SUPER | DIR_F_FROM))) (void)mw_wallet_store_upgrade();
    mw_wallet_store_close();
    (void)mw_secure_user_key_set(old_key);
    err = dir_read(st, &next, &flags, other);
    if (err == MW_ERR_IO) {
        {
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
