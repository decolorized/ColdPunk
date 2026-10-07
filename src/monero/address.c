// Monero address encoding (TZ 6.5, 12.3).
//
// Wire format:  varint(prefix) || spend_pub(32) || view_pub(32)
//               [ || payment_id(8) for integrated addresses ]
//               || keccak256(everything above)[0..4]
// then Monero-flavoured Base58.
#include "address.h"

#include <string.h>

#include "../crypto/hash.h"

#define ADDR_KEYS_SIZE   64
#define PAYMENT_ID_SIZE   8
#define CHECKSUM_SIZE     4
#define MAX_PREFIX_BYTES 10

typedef struct {
    uint64_t          prefix;
    mw_network_t      net;
    mw_address_type_t type;
} prefix_entry_t;

// Network byte prefixes, straight from cryptonote_config.h.
static const prefix_entry_t g_prefixes[] = {
    { 18, MW_NET_MAINNET,  MW_ADDR_STANDARD   },
    { 19, MW_NET_MAINNET,  MW_ADDR_INTEGRATED },
    { 42, MW_NET_MAINNET,  MW_ADDR_SUBADDRESS },
    { 53, MW_NET_TESTNET,  MW_ADDR_STANDARD   },
    { 54, MW_NET_TESTNET,  MW_ADDR_INTEGRATED },
    { 63, MW_NET_TESTNET,  MW_ADDR_SUBADDRESS },
    { 24, MW_NET_STAGENET, MW_ADDR_STANDARD   },
    { 25, MW_NET_STAGENET, MW_ADDR_INTEGRATED },
    { 36, MW_NET_STAGENET, MW_ADDR_SUBADDRESS },
};

#define NUM_PREFIXES (sizeof(g_prefixes) / sizeof(g_prefixes[0]))

uint64_t mw_address_prefix(mw_network_t net, mw_address_type_t type)
{
    for (size_t i = 0; i < NUM_PREFIXES; ++i) {
        if (g_prefixes[i].net == net && g_prefixes[i].type == type) {
            return g_prefixes[i].prefix;
        }
    }
    return 0;
}

static size_t varint_write(uint64_t v, uint8_t* out)
{
    size_t n = 0;
    while (v >= 0x80) {
        out[n++] = (uint8_t)((v & 0x7f) | 0x80);
        v >>= 7;
    }
    out[n++] = (uint8_t)v;
    return n;
}

// Returns the number of bytes consumed, or 0 on a malformed varint.
static size_t varint_read(const uint8_t* in, size_t len, uint64_t* out)
{
    uint64_t v = 0;
    unsigned shift = 0;
    for (size_t i = 0; i < len && i < MAX_PREFIX_BYTES; ++i) {
        uint8_t b = in[i];
        if (shift >= 64) {
            return 0;
        }
        v |= (uint64_t)(b & 0x7f) << shift;
        if ((b & 0x80) == 0) {
            if (b == 0 && i != 0) {
                return 0;           // non-canonical encoding
            }
            *out = v;
            return i + 1;
        }
        shift += 7;
    }
    return 0;
}

mw_err_t mw_address_encode(const mw_address_t* addr, char* out, size_t out_len)
{
    if (addr == NULL || out == NULL || out_len == 0) {
        return MW_ERR_INVALID_ARG;
    }
    if (addr->type == MW_ADDR_INTEGRATED && !addr->has_payment_id) {
        return MW_ERR_INVALID_ARG;
    }

    uint64_t prefix = mw_address_prefix(addr->network, addr->type);
    if (prefix == 0) {
        return MW_ERR_INVALID_ARG;
    }

    uint8_t buf[MAX_PREFIX_BYTES + ADDR_KEYS_SIZE + PAYMENT_ID_SIZE];
    size_t pos = varint_write(prefix, buf);
    memcpy(buf + pos, addr->spend.b, 32); pos += 32;
    memcpy(buf + pos, addr->view.b, 32);  pos += 32;
    if (addr->type == MW_ADDR_INTEGRATED) {
        memcpy(buf + pos, addr->payment_id, PAYMENT_ID_SIZE);
        pos += PAYMENT_ID_SIZE;
    }

    if (mw_base58_encode_check(buf, pos, out, out_len) == 0) {
        return MW_ERR_RANGE;
    }
    return MW_OK;
}

mw_err_t mw_address_decode(const char* str, mw_address_t* out)
{
    if (str == NULL || out == NULL) {
        return MW_ERR_INVALID_ARG;
    }
    size_t len = strlen(str);
    if (len == 0 || len >= MW_ADDRESS_STR_MAX) {
        return MW_ERR_FORMAT;
    }

    uint8_t buf[MAX_PREFIX_BYTES + ADDR_KEYS_SIZE + PAYMENT_ID_SIZE + CHECKSUM_SIZE];
    size_t written = 0;
    mw_err_t err = mw_base58_decode_check(str, buf, sizeof(buf), &written);
    if (err != MW_OK) {
        return err;
    }

    uint64_t prefix = 0;
    size_t pos = varint_read(buf, written, &prefix);
    if (pos == 0) {
        return MW_ERR_FORMAT;
    }

    const prefix_entry_t* entry = NULL;
    for (size_t i = 0; i < NUM_PREFIXES; ++i) {
        if (g_prefixes[i].prefix == prefix) {
            entry = &g_prefixes[i];
            break;
        }
    }
    if (entry == NULL) {
        return MW_ERR_FORMAT;
    }

    size_t expect = ADDR_KEYS_SIZE +
                    (entry->type == MW_ADDR_INTEGRATED ? PAYMENT_ID_SIZE : 0);
    if (written - pos != expect) {
        return MW_ERR_FORMAT;
    }

    memset(out, 0, sizeof(*out));
    out->network = entry->net;
    out->type    = entry->type;
    memcpy(out->spend.b, buf + pos, 32); pos += 32;
    memcpy(out->view.b, buf + pos, 32);  pos += 32;

    // TZ 8.3: an address is untrusted input (a scanned QR, a typed string), so
    // both points are validated before anything else may use them. Note the
    // BOOLEAN convention - mw_point_check_public() returns 1 when the point is
    // safe, it is NOT an mw_err_t; comparing it against MW_OK would invert the
    // test and accept every low-order point. See src/crypto/ed25519.h.
    if (!mw_point_check_public(&out->spend) ||
        !mw_point_check_public(&out->view)) {
        memset(out, 0, sizeof(*out));
        return MW_ERR_SUBGROUP;
    }

    if (entry->type == MW_ADDR_INTEGRATED) {
        memcpy(out->payment_id, buf + pos, PAYMENT_ID_SIZE);
        out->has_payment_id = true;
    }
    // major/minor are not carried by the wire format; the caller resolves them
    // from its own subaddress table.
    return MW_OK;
}

mw_err_t mw_address_from_keys(const mw_account_keys_t* keys, mw_network_t net,
                              mw_address_t* out)
{
    if (keys == NULL || out == NULL) {
        return MW_ERR_INVALID_ARG;
    }
    memset(out, 0, sizeof(*out));
    out->spend   = keys->pub.spend;
    out->view    = keys->pub.view;
    out->type    = MW_ADDR_STANDARD;
    out->network = net;
    return MW_OK;
}

void mw_address_shorten(const char* full, char* out, size_t out_len, int head,
                        int tail)
{
    if (out == NULL || out_len == 0) {
        return;
    }
    out[0] = '\0';
    if (full == NULL || head < 0 || tail < 0) {
        return;
    }

    size_t len = strlen(full);
    size_t h = (size_t)head;
    size_t t = (size_t)tail;

    // Nothing to gain: copy as much of the original as fits.
    if (len <= h + t + 3 || out_len < h + t + 4) {
        size_t n = len < out_len - 1 ? len : out_len - 1;
        memcpy(out, full, n);
        out[n] = '\0';
        return;
    }

    memcpy(out, full, h);
    memcpy(out + h, "...", 3);
    memcpy(out + h + 3, full + len - t, t);
    out[h + 3 + t] = '\0';
}
