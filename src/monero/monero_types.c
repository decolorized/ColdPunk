// Shared helpers for the core Monero value types.
#include "monero_types.h"

#include <string.h>

const char* mw_err_str(mw_err_t err)
{
    switch (err) {
    case MW_OK:                 return "ok";
    case MW_ERR_INVALID_ARG:    return "invalid argument";
    case MW_ERR_CHECKSUM:       return "checksum mismatch";
    case MW_ERR_NUM_WORDS:      return "wrong number of words";
    case MW_ERR_UNKNOWN_WORD:   return "unknown word";
    case MW_ERR_FORMAT:         return "malformed data";
    case MW_ERR_MAGIC:          return "bad magic";
    case MW_ERR_VERSION:        return "unsupported version";
    case MW_ERR_SIGNATURE:      return "bad signature";
    case MW_ERR_DECRYPT:        return "decryption failed";
    case MW_ERR_MEMORY:         return "out of memory";
    case MW_ERR_NOT_SUPPORTED:  return "not supported";
    case MW_ERR_SUBGROUP:       return "point not in main subgroup";
    case MW_ERR_BALANCE:        return "amounts do not balance";
    case MW_ERR_KEY_MISMATCH:   return "key pair mismatch";
    case MW_ERR_TOO_MANY:       return "too many items";
    case MW_ERR_IO:             return "I/O error";
    case MW_ERR_ABORTED:        return "aborted by user";
    case MW_ERR_RANGE:          return "value out of range";
    /* Not failures: the two navigation outcomes of mw_kb_run(). They appear
       here so the switch stays exhaustive and so a stray one is legible in a
       log rather than showing up as "unknown error". */
    case MW_KB_BACK:            return "back to previous word";
    case MW_KB_RESTART:         return "restart phrase entry";
    case MW_ERR_EXISTS:         return "already exists";
    }
    return "unknown error";
}

// Same output as Monero's cryptonote::print_money(): the integer part, a dot
// and all 12 decimal digits (no trailing-zero trimming), so amounts shown on
// the device are byte-identical to what monero-wallet-cli prints.
void mw_format_amount(uint64_t amount, char* out, size_t out_len)
{
    if (out == NULL || out_len == 0) {
        return;
    }

    char buf[32];
    size_t pos = sizeof(buf);
    buf[--pos] = '\0';

    uint64_t frac = amount % MW_ATOMIC_UNITS;
    uint64_t whole = amount / MW_ATOMIC_UNITS;

    for (int i = 0; i < 12; ++i) {
        buf[--pos] = (char)('0' + (int)(frac % 10));
        frac /= 10;
    }
    buf[--pos] = '.';
    if (whole == 0) {
        buf[--pos] = '0';
    } else {
        while (whole != 0) {
            buf[--pos] = (char)('0' + (int)(whole % 10));
            whole /= 10;
        }
    }

    size_t len = sizeof(buf) - 1 - pos;
    if (len >= out_len) {
        len = out_len - 1;       // truncate rather than overflow
    }
    memcpy(out, buf + pos, len);
    out[len] = '\0';
}
