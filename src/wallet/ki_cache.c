// Key image cache - see ki_cache.h.
//
// File layout (sealed as a whole with mw_seal, label "mw.ki.v1.<id>.<variant>"):
//
//     file      := iv(16) || tag(16) || AES-GCM(plain)
//     plain     := "MWKI" || version(1) || reserved(3) ||
//                  account(32)  keccak256("mw.ki.account" || spend_pub || view_pub)
//                  count(u32 LE) || count * entry
//     entry     := out_pub(32) || image(32) || major(u32) || minor(u32) || flags(1)
#include "ki_cache.h"
#include "file_store.h"
#include "secure_storage.h"

#include "../crypto/hash.h"
#include "../crypto/memzero.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#if defined(__has_include)
#  if __has_include(<esp_heap_caps.h>)
#    include <esp_heap_caps.h>
#    define MW_KI_PSRAM 1
#  endif
#endif

#define KI_MAGIC      "MWKI"
#define KI_VERSION    1
#define KI_HDR        (4 + 1 + 3 + 32 + 4)
#define KI_ENTRY      (32 + 32 + 4 + 4 + 1)
#define KI_SEAL_HDR   32

static struct {
    bool           open;
    uint32_t       wallet_id;
    uint8_t        variant;
    uint8_t        account[32];
    uint32_t       count;
    bool           dirty;
    mw_ki_entry_t* e;            // MW_KI_CACHE_MAX entries
} g;

static void* ki_alloc(size_t n)
{
#if defined(MW_KI_PSRAM)
    void* p = heap_caps_malloc(n, MALLOC_CAP_SPIRAM | MALLOC_CAP_8BIT);
    if (p) return p;
#endif
    return malloc(n);
}

static void ki_free(void* p, size_t n)
{
    if (!p) return;
    mw_memzero(p, n);
    free(p);
}

static void file_name(uint32_t id, uint8_t variant, char* out, size_t cap)
{
    snprintf(out, cap, "ki_%08lx_%u.bin", (unsigned long)id, (unsigned)variant);
}

static void seal_label(uint32_t id, uint8_t variant, char* out, size_t cap)
{
    snprintf(out, cap, "mw.ki.v1.%08lx.%u", (unsigned long)id, (unsigned)variant);
}

static void account_hash(const mw_account_keys_t* keys, uint8_t out[32])
{
    uint8_t buf[13 + 64];
    memcpy(buf, "mw.ki.account", 13);
    memcpy(buf + 13, keys->pub.spend.b, 32);
    memcpy(buf + 45, keys->pub.view.b, 32);
    mw_keccak256(buf, sizeof(buf), out);
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

// Reads and unseals the file into g.e. Any failure leaves the cache empty.
static void load_file(void)
{
    char name[MW_FSTORE_NAME_MAX + 1], label[40];
    size_t size = 0, got = 0;
    file_name(g.wallet_id, g.variant, name, sizeof name);
    if (mw_fstore_size(name, &size) != MW_OK) return;          // no file yet
    if (size < KI_SEAL_HDR + KI_HDR ||
        size > KI_SEAL_HDR + KI_HDR + (size_t)MW_KI_CACHE_MAX * KI_ENTRY) return;

    uint8_t* file = (uint8_t*)ki_alloc(size);
    uint8_t* plain = (uint8_t*)ki_alloc(size);
    if (!file || !plain) {
        ki_free(file, size);
        ki_free(plain, size);
        return;
    }
    const size_t ct_len = size - KI_SEAL_HDR;
    seal_label(g.wallet_id, g.variant, label, sizeof label);
    if (mw_fstore_read(name, file, size, &got) == MW_OK && got == size &&
        mw_unseal(label, file + KI_SEAL_HDR, ct_len, file, file + 16, plain, ct_len) == MW_OK &&
        memcmp(plain, KI_MAGIC, 4) == 0 && plain[4] == KI_VERSION &&
        memcmp(plain + 8, g.account, 32) == 0) {
        const uint32_t n = get_u32(plain + 40);
        if (n <= MW_KI_CACHE_MAX && KI_HDR + (size_t)n * KI_ENTRY == ct_len) {
            const uint8_t* p = plain + KI_HDR;
            for (uint32_t i = 0; i < n; i++, p += KI_ENTRY) {
                mw_ki_entry_t* e = &g.e[i];
                memcpy(e->out_pub.b, p, 32);
                memcpy(e->image.b, p + 32, 32);
                e->major = get_u32(p + 64);
                e->minor = get_u32(p + 68);
                e->flags = p[72];
            }
            g.count = n;
        }
    }
    ki_free(file, size);
    ki_free(plain, size);
}

mw_err_t mw_ki_cache_open(uint32_t wallet_id, uint8_t variant,
                          const mw_account_keys_t* keys)
{
    if (keys == NULL || variant > 1) return MW_ERR_INVALID_ARG;
    mw_ki_cache_close();
    g.e = (mw_ki_entry_t*)ki_alloc((size_t)MW_KI_CACHE_MAX * sizeof(mw_ki_entry_t));
    if (!g.e) return MW_ERR_MEMORY;
    memset(g.e, 0, (size_t)MW_KI_CACHE_MAX * sizeof(mw_ki_entry_t));
    g.wallet_id = wallet_id;
    g.variant = variant;
    g.count = 0;
    g.dirty = false;
    account_hash(keys, g.account);
    g.open = true;
    load_file();
    return MW_OK;
}

void mw_ki_cache_close(void)
{
    if (g.e) ki_free(g.e, (size_t)MW_KI_CACHE_MAX * sizeof(mw_ki_entry_t));
    mw_memzero(&g, sizeof(g));
}

bool     mw_ki_cache_is_open(void) { return g.open; }
uint32_t mw_ki_cache_count(void)   { return g.open ? g.count : 0; }

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

mw_err_t mw_ki_cache_put(const mw_ki_entry_t* e)
{
    if (!g.open) return MW_ERR_NOT_SUPPORTED;
    if (!e) return MW_ERR_INVALID_ARG;
    for (uint32_t i = 0; i < g.count; i++) {
        mw_ki_entry_t* x = &g.e[i];
        if (memcmp(x->out_pub.b, e->out_pub.b, 32) == 0) {
            if (memcmp(x->image.b, e->image.b, 32) != 0 || x->major != e->major ||
                x->minor != e->minor) {
                x->image = e->image;                 // recomputed: trust the new one
                x->major = e->major;
                x->minor = e->minor;
                g.dirty = true;
            }
            if ((x->flags | e->flags) != x->flags) {
                x->flags |= e->flags;
                g.dirty = true;
            }
            return MW_OK;
        }
    }
    if (g.count >= MW_KI_CACHE_MAX) return MW_ERR_TOO_MANY;
    g.e[g.count++] = *e;
    g.dirty = true;
    return MW_OK;
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

mw_err_t mw_ki_cache_save(void)
{
    char name[MW_FSTORE_NAME_MAX + 1], label[40];
    if (!g.open) return MW_ERR_NOT_SUPPORTED;
    if (!g.dirty) return MW_OK;

    const size_t pt_len = KI_HDR + (size_t)g.count * KI_ENTRY;
    const size_t total = KI_SEAL_HDR + pt_len;
    uint8_t* plain = (uint8_t*)ki_alloc(pt_len);
    uint8_t* file = (uint8_t*)ki_alloc(total);
    if (!plain || !file) {
        ki_free(plain, pt_len);
        ki_free(file, total);
        return MW_ERR_MEMORY;
    }
    memset(plain, 0, KI_HDR);
    memcpy(plain, KI_MAGIC, 4);
    plain[4] = KI_VERSION;
    memcpy(plain + 8, g.account, 32);
    put_u32(plain + 40, g.count);
    uint8_t* p = plain + KI_HDR;
    for (uint32_t i = 0; i < g.count; i++, p += KI_ENTRY) {
        const mw_ki_entry_t* e = &g.e[i];
        memcpy(p, e->out_pub.b, 32);
        memcpy(p + 32, e->image.b, 32);
        put_u32(p + 64, e->major);
        put_u32(p + 68, e->minor);
        p[72] = e->flags;
    }

    seal_label(g.wallet_id, g.variant, label, sizeof label);
    mw_err_t err = mw_seal(label, plain, pt_len, file, file + 16, file + KI_SEAL_HDR, pt_len);
    if (err == MW_OK) {
        file_name(g.wallet_id, g.variant, name, sizeof name);
        err = mw_fstore_write(name, file, total);
    }
    if (err == MW_OK) g.dirty = false;
    ki_free(plain, pt_len);
    ki_free(file, total);
    return err;
}

void mw_ki_cache_rekey(uint32_t wallet_id, const uint8_t old_key[32],
                       const uint8_t new_key[32])
{
    char name[MW_FSTORE_NAME_MAX + 1], label[40];
    if (!old_key || !new_key) return;
    if (g.open && g.wallet_id == wallet_id) mw_ki_cache_close();
    for (uint8_t v = 0; v < 2; v++) {
        size_t size = 0, got = 0;
        file_name(wallet_id, v, name, sizeof name);
        if (mw_fstore_size(name, &size) != MW_OK) continue;
        uint8_t* file = (size > KI_SEAL_HDR) ? (uint8_t*)ki_alloc(size) : NULL;
        uint8_t* plain = (size > KI_SEAL_HDR) ? (uint8_t*)ki_alloc(size) : NULL;
        bool ok = false;
        if (file && plain && mw_fstore_read(name, file, size, &got) == MW_OK && got == size) {
            const size_t ct_len = size - KI_SEAL_HDR;
            seal_label(wallet_id, v, label, sizeof label);
            if (mw_secure_user_key_set(old_key) == MW_OK &&
                mw_unseal(label, file + KI_SEAL_HDR, ct_len, file, file + 16, plain,
                          ct_len) == MW_OK &&
                mw_secure_user_key_set(new_key) == MW_OK &&
                mw_seal(label, plain, ct_len, file, file + 16, file + KI_SEAL_HDR,
                        ct_len) == MW_OK &&
                mw_fstore_write(name, file, size) == MW_OK) {
                ok = true;
            }
        }
        if (!ok) (void)mw_fstore_remove(name);
        ki_free(file, size);
        ki_free(plain, size);
    }
    (void)mw_secure_user_key_set(new_key);
}

mw_err_t mw_ki_cache_erase_wallet(uint32_t wallet_id)
{
    char name[MW_FSTORE_NAME_MAX + 1];
    mw_err_t err = MW_OK;
    if (g.open && g.wallet_id == wallet_id) mw_ki_cache_close();
    for (uint8_t v = 0; v < 2; v++) {
        file_name(wallet_id, v, name, sizeof name);
        const mw_err_t e = mw_fstore_remove(name);
        if (e != MW_OK) err = e;
    }
    return err;
}
