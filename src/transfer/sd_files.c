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
    "a passphrase or a private key to this card.\r\n"
    "\r\n"
    "https://github.com/decolorized/ColdPunk\r\n";
