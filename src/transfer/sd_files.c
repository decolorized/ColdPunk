// SD card file browser: classification, ordering and result names.
// See sd_files.h.
//
// SPDX-License-Identifier: MIT
#include "sd_files.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "../monero/file_formats.h"

#define MW_SDF_T_MIN  946684800LL     // 2000-01-01
#define MW_SDF_T_MAX 4102444800LL     // 2100-01-01

mw_sdf_kind_t mw_sdf_kind(const uint8_t* head, size_t len)
{
    if (!head || len == 0) return MW_SDF_NONE;
    switch (mw_file_detect(head, len)) {
    case MW_FMT_OUTPUTS:     return MW_SDF_OUTPUTS;
    case MW_FMT_UNSIGNED_TX: return MW_SDF_UNSIGNED;
    default:                 return MW_SDF_NONE;
    }
}

bool mw_sdf_time_valid(int64_t t)
{
    return t >= MW_SDF_T_MIN && t < MW_SDF_T_MAX;
}

bool mw_sdf_name_time(const char* name, int64_t* out)
{
    if (!name) return false;
    const char* p = name;
    while (*p) {
        if (*p < '0' || *p > '9') { ++p; continue; }
        const char* q = p;
        while (*q >= '0' && *q <= '9') ++q;
        if (q - p == 10) {
            int64_t v = 0;
            for (const char* r = p; r < q; ++r) v = v * 10 + (*r - '0');
            if (mw_sdf_time_valid(v)) {
                if (out) *out = v;
                return true;
            }
        }
        p = q;
    }
    return false;
}

int64_t mw_sdf_sort_time(const mw_sd_entry_t* e)
{
    if (!e) return 0;
    if (mw_sdf_time_valid(e->mtime)) return e->mtime;
    int64_t t = 0;
    return mw_sdf_name_time(e->name, &t) ? t : 0;
}

static int cmp_entry(const void* a, const void* b)
{
    const mw_sd_entry_t* x = (const mw_sd_entry_t*)a;
    const mw_sd_entry_t* y = (const mw_sd_entry_t*)b;
    const int64_t tx = mw_sdf_sort_time(x), ty = mw_sdf_sort_time(y);
    if (tx != ty) return (tx > ty) ? -1 : 1;           // newest first
    return strcmp(x->name, y->name);
}

void mw_sdf_sort(mw_sd_entry_t* e, int n)
{
    if (e && n > 1) qsort(e, (size_t)n, sizeof(*e), cmp_entry);
}

// out = in[0..keep) + mid + in[skip..]; the head `in[0..keep)` is shortened
// when the whole would not fit.
static mw_err_t splice(const char* in, size_t keep, const char* mid, size_t skip,
                       char* out, size_t cap)
{
    const size_t in_len   = strlen(in);
    const char*  tail     = in + skip;
    const size_t tail_len = in_len - skip;
    const size_t mid_len  = strlen(mid);
    if (cap == 0 || mid_len + tail_len + 1 > cap) return MW_ERR_RANGE;
    size_t head = keep;
    if (head + mid_len + tail_len + 1 > cap) head = cap - 1 - mid_len - tail_len;
    memcpy(out, in, head);
    memcpy(out + head, mid, mid_len);
    memcpy(out + head + mid_len, tail, tail_len);
    out[head + mid_len + tail_len] = '\0';
    return MW_OK;
}

mw_err_t mw_sdf_result_name(mw_sdf_kind_t k, const char* in, char* out, size_t cap)
{
    if (!in || !out || !in[0]) return MW_ERR_INVALID_ARG;
    const size_t n = strlen(in);
    if (k == MW_SDF_OUTPUTS) {
        static const char suf[] = "_outputs";
        const size_t sl = sizeof(suf) - 1;
        if (n > sl && strcmp(in + n - sl, suf) == 0)
            return splice(in, n - sl, "_keyImages", n, out, cap);
        return splice(in, n, "_keyImages", n, out, cap);
    }
    if (k == MW_SDF_UNSIGNED) {
        const char* u = strstr(in, "unsigned_monero_tx");
        if (u) {
            const size_t at = (size_t)(u - in);
            return splice(in, at, "signed", at + 8 /* "unsigned" */, out, cap);
        }
        return splice(in, n, "_signed_monero_tx", n, out, cap);
    }
    return MW_ERR_INVALID_ARG;
}

// ------------------------------------------------------- safe file names
static bool reserved_stem(const char* s, size_t n)
{
    static const char* const fixed[] = { "CON", "PRN", "AUX", "NUL" };
    char up[5];
    if (n < 3 || n > 4) return false;
    for (size_t i = 0; i < n; ++i) {
        char c = s[i];
        if (c >= 'a' && c <= 'z') c = (char)(c - 'a' + 'A');
        up[i] = c;
    }
    up[n] = '\0';
    if (n == 3) {
        for (size_t i = 0; i < sizeof fixed / sizeof fixed[0]; ++i)
            if (strcmp(up, fixed[i]) == 0) return true;
        return false;
    }
    return (memcmp(up, "COM", 3) == 0 || memcmp(up, "LPT", 3) == 0) &&
           up[3] >= '1' && up[3] <= '9';
}

mw_err_t mw_sdf_safe_name(const char* in, char* out, size_t cap)
{
    if (!in || !out || cap < 8) return MW_ERR_INVALID_ARG;
    size_t o = 0;
    out[o++] = '_';                  // room for the reserved-name prefix
    for (const char* p = in; *p && o + 1 < cap; ++p) {
        unsigned char c = (unsigned char)*p;
        if (o == 1 && c == ' ') continue;                 // leading spaces
        if (c < 0x20 || c > 0x7e || strchr("/\\:*?\"<>|", (int)c) != NULL) c = '_';
        out[o++] = (char)c;
    }
    while (o > 1 && (out[o - 1] == ' ' || out[o - 1] == '.')) --o;
    out[o] = '\0';
    if (o == 1) {
        snprintf(out, cap, "wallet");
        return MW_OK;
    }
    const char* dot = strchr(out + 1, '.');
    const size_t stem = dot ? (size_t)(dot - (out + 1)) : o - 1;
    if (!reserved_stem(out + 1, stem)) memmove(out, out + 1, o);   // drop the '_'
    return MW_OK;
}

mw_err_t mw_sdf_viewonly_name(const char* wallet, int n, char* out, size_t cap)
{
    char safe[40];
    if (!out || cap < 24) return MW_ERR_INVALID_ARG;
    mw_err_t e = mw_sdf_safe_name(wallet ? wallet : "", safe, sizeof safe);
    if (e != MW_OK) return e;
    int w = (n <= 1) ? snprintf(out, cap, "%s_viewonly.txt", safe)
                     : snprintf(out, cap, "%s_viewonly_%d.txt", safe, n);
    return (w > 0 && (size_t)w < cap) ? MW_OK : MW_ERR_TOO_MANY;
}

const char mw_sdf_readme_name[] = "ColdPunk_readme.txt";

const char mw_sdf_readme_text[] =
    "ColdPunk - Monero cold wallet: SD card exchange\r\n"
    "===============================================\r\n"
    "\r\n"
    "Put the files from Feather (or MoneroPunkSigner) into the ROOT folder of\r\n"
    "this card:\r\n"
    "\r\n"
    "  * outputs export        (..._outputs)\r\n"
    "      -> the device writes key images      (..._keyImages)\r\n"
    "  * unsigned transaction  (..._unsigned_monero_tx)\r\n"
    "      -> the device writes the signed one  (..._signed_monero_tx)\r\n"
    "\r\n"
    "On the device: open the wallet -> SD card files -> pick a file -> confirm\r\n"
    "on the screen. Newest files are at the top; processed files are marked.\r\n"
    "The result is written next to the source file and gets its date. Then\r\n"
    "import it in Feather (Import key images / Load signed transaction).\r\n"
    "\r\n"
    "Before signing, check the amount, the fee and every full address on the\r\n"
    "DEVICE screen, not on the computer.\r\n"
    "\r\n"
    "Card format: FAT32. Files up to 256 KB. The device never writes a seed,\r\n"
    "a passphrase or the spend key to this card. The private VIEW key and the\r\n"
    "address are written only when you choose \"Export view key\" in the\r\n"
    "wallet menu (file <wallet>_viewonly.txt): that file shows every incoming\r\n"
    "payment of the wallet to whoever reads it - delete it after use.\r\n"
    "\r\n"
    "https://github.com/decolorized/ColdPunk\r\n";
