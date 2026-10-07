// Transaction prefix, RCT message hash, tx_extra and the confirmation summary
// (TZ 12.3). Matches cryptonote::transaction_prefix and rct::rctSigBase from
// monero-project/monero 0.18.x.
//
// Prefix layout (what gets keccak-hashed into the "prefix hash"):
//     varint version
//     varint unlock_time
//     varint #inputs
//       for each: 0x02 (txin_to_key)
//                 varint amount (0 for RingCT)
//                 varint #offsets, then each relative offset as a varint
//                 32 bytes key image
//     varint #outputs
//       for each: varint amount (0 for RingCT)
//                 0x02 (txout_to_key) or 0x03 (txout_to_tagged_key)
//                 32 bytes one-time public key
//                 [1 byte view tag, tagged outputs only]
//     varint extra length, then the raw extra bytes
//
// Everything is streamed straight into the Keccak sponge, so no multi-kilobyte
// scratch buffer is needed on the device.
#include "tx.h"

#include <string.h>

#include "address.h"
#include "keys.h"
#include "serialize.h"
#include "../crypto/hash.h"
#include "../crypto/memzero.h"

#define TXIN_TO_KEY          0x02
#define TXOUT_TO_KEY         0x02
#define TXOUT_TO_TAGGED_KEY  0x03

#define TX_EXTRA_TAG_PADDING           0x00
#define TX_EXTRA_TAG_PUBKEY            0x01
#define TX_EXTRA_NONCE                 0x02
#define TX_EXTRA_MERGE_MINING_TAG      0x03
#define TX_EXTRA_TAG_ADDITIONAL_PUBKEYS 0x04
#define TX_EXTRA_NONCE_ENCRYPTED_PAYMENT_ID 0x01

// ------------------------------------------------------------------ helpers
static void keccak_varint(mw_keccak_ctx* ctx, uint64_t v)
{
    uint8_t buf[10];
    size_t n = mw_varint_encode(v, buf);
    mw_keccak_update(ctx, buf, n);
}

static void keccak_u8(mw_keccak_ctx* ctx, uint8_t v)
{
    mw_keccak_update(ctx, &v, 1);
}

// ----------------------------------------------------------- tx_extra scan
// Pulls the 8-byte short payment id out of a tx_extra nonce field.
//
// Two callers need it and they are in different modules, which is why it lives
// here rather than inside the signer: mw_sign_transaction() re-encrypts the
// plaintext id wallet2 supplied, and mw_tx_summarize() needs the id to rebuild
// the integrated address the user is asked to compare on screen.
bool mw_tx_extra_find_payment_id(const uint8_t* extra, size_t len,
                                 uint8_t out[8])
{
    if (extra == NULL || out == NULL) {
        return false;
    }

    mw_reader_t r;
    mw_reader_init(&r, extra, len);
    while (mw_remaining(&r) > 0) {
        uint8_t tag = 0;
        if (!mw_read_u8(&r, &tag)) {
            return false;
        }
        switch (tag) {
        case TX_EXTRA_TAG_PADDING:
            return false;                        // padding runs to the end
        case TX_EXTRA_TAG_PUBKEY:
            if (!mw_skip(&r, 32)) {
                return false;
            }
            break;
        case TX_EXTRA_NONCE: {
            // tx_extra_nonce is a std::string: varint length, then the bytes.
            uint64_t size = 0;
            if (!mw_read_varint(&r, &size) || size > 255) {
                return false;
            }
            if (size == 9 && mw_remaining(&r) >= 9) {
                uint8_t sub = 0;
                mw_read_u8(&r, &sub);
                if (sub == TX_EXTRA_NONCE_ENCRYPTED_PAYMENT_ID) {
                    return mw_read_bytes(&r, out, 8);
                }
                if (!mw_skip(&r, 8)) {
                    return false;
                }
            } else if (!mw_skip(&r, (size_t)size)) {
                return false;
            }
            break;
        }
        case TX_EXTRA_MERGE_MINING_TAG: {
            uint64_t depth = 0;
            if (!mw_read_varint(&r, &depth) || !mw_skip(&r, 32)) {
                return false;
            }
            break;
        }
        case TX_EXTRA_TAG_ADDITIONAL_PUBKEYS: {
            uint64_t n = 0;
            if (!mw_read_varint(&r, &n) || n > 512 ||
                !mw_skip(&r, (size_t)n * 32u)) {
                return false;
            }
            break;
        }
        default:
            return false;                        // unknown tag: stop scanning
        }
    }
    return false;
}

// ------------------------------------------------------ destination check
static bool same_address(const mw_address_t* a, const mw_address_t* b)
{
    return mw_point_eq(&a->spend, &b->spend) && mw_point_eq(&a->view, &b->view);
}

// Own-address candidate n: (0,0), (acct,0), the inputs' subaddresses, then
// the caller's own_hint_* (key image cache). Duplicates are skipped by the
// caller. false past the end.
static bool candidate_at(const mw_transaction_t* tx, unsigned n,
                         uint32_t* major, uint32_t* minor)
{
    if (n == 0) {
        *major = 0;
        *minor = 0;
        return true;
    }
    --n;
    if (n == 0) {
        *major = tx->subaddr_account;
        *minor = 0;
        return true;
    }
    --n;
    if (n < tx->n_inputs) {
        *major = tx->sources[n].subaddr_major;
        *minor = tx->sources[n].subaddr_minor;
        return true;
    }
    n -= tx->n_inputs;
    if (n < tx->n_own_hints && n < MW_MAX_OWN_HINTS) {
        *major = tx->own_hint_major[n];
        *minor = tx->own_hint_minor[n];
        return true;
    }
    return false;
}

static bool candidate_seen(const mw_transaction_t* tx, unsigned n,
                           uint32_t major, uint32_t minor)
{
    for (unsigned j = 0; j < n; ++j) {
        uint32_t M = 0, m = 0;
        if (candidate_at(tx, j, &M, &m) && M == major && m == minor) {
            return true;
        }
    }
    return false;
}

// Does T = D - B equal m(M,m)*G for one (M,m) of the search window? The
// window follows wallet2's lookahead around what the device knows: account
// primaries 0..max(known, acct)+1 (at most MW_OWN_LOOKAHEAD_MAJOR), then
// (acct, highest known minor + MW_OWN_LOOKAHEAD_MINOR down to 1) and the
// same for account 0, MW_OWN_SEARCH_MAX candidates in all.
static bool search_own_subaddress(const mw_account_keys_t* keys,
                                  const mw_transaction_t* tx, const mw_point_t* D,
                                  uint32_t* major, uint32_t* minor, uint16_t* searched)
{
    mw_point_t T;
    *searched = 0;
    if (mw_point_sub(&T, D, &keys->pub.spend) != 0) {
        return false;
    }
    const uint32_t acct = tx->subaddr_account;
    uint32_t top_major = (tx->own_max_major > acct ? tx->own_max_major : acct) + 1u;
    if (top_major > MW_OWN_LOOKAHEAD_MAJOR) {
        top_major = MW_OWN_LOOKAHEAD_MAJOR;
    }
    const uint32_t top_acct = tx->own_max_minor_acct + MW_OWN_LOOKAHEAD_MINOR;
    const uint32_t top_main = tx->own_max_minor_main + MW_OWN_LOOKAHEAD_MINOR;

    for (int pass = 0; pass < 3; ++pass) {
        uint32_t M_lo, M_hi, m_hi;
        if (pass == 0) {                 // account primaries (M, 0)
            M_lo = 1; M_hi = top_major; m_hi = 0;
        } else if (pass == 1) {          // (acct, top..1)
            M_lo = acct; M_hi = acct; m_hi = top_acct;
        } else {                         // (0, top..1)
            if (acct == 0) break;
            M_lo = 0; M_hi = 0; m_hi = top_main;
        }
        for (uint32_t M = M_lo; M <= M_hi; ++M) {
            uint32_t m = m_hi;
            for (;;) {
                if (!(pass == 0 ? M == 0 : m == 0)) {
                    if (*searched >= MW_OWN_SEARCH_MAX) {
                        return false;
                    }
                    mw_scalar_t s;
                    mw_point_t sG;
                    mw_get_subaddress_secret_key(&keys->sec.view, M, pass == 0 ? 0 : m, &s);
                    mw_point_scalarmult_base(&sG, &s);
                    mw_memzero(&s, sizeof(s));
                    ++*searched;
                    if (mw_point_eq(&sG, &T)) {
                        *major = M;
                        *minor = pass == 0 ? 0 : m;
                        return true;
                    }
                }
                if (pass == 0 || m == 0) {
                    break;
                }
                --m;
            }
        }
    }
    return false;
}

static mw_err_t refuse(mw_tx_check_info_t* info, uint8_t reason, uint8_t dest,
                       uint32_t major, uint32_t minor)
{
    info->reason = reason;
    info->dest = dest;
    info->major = major;
    info->minor = minor;
    return reason == MW_TXR_BAD_POINT ? MW_ERR_SUBGROUP
         : reason == MW_TXR_INPUTS ? MW_ERR_INVALID_ARG : MW_ERR_KEY_MISMATCH;
}

// Per-destination match state while the candidates are walked.
#define HIT_OWN    0x01
#define HIT_SPEND  0x02     // our spend key, foreign view key
#define HIT_VIEW   0x04     // our view key, foreign spend key

static mw_err_t check_destinations(const mw_account_keys_t* keys, mw_transaction_t* tx,
                                   mw_tx_check_info_t* info)
{
    const uint32_t acct = tx->subaddr_account;
    uint8_t hit[MW_MAX_DESTINATIONS];
    memset(hit, 0, sizeof(hit));

    // ---- points that came from the file
    for (uint8_t i = 0; i < tx->n_destinations; ++i) {
        const mw_tx_destination_t* d = &tx->destinations[i];
        if (!mw_point_check_public(&d->addr.spend) || !mw_point_check_public(&d->addr.view)) {
            return refuse(info, MW_TXR_BAD_POINT, i, 0, 0);
        }
    }
    if (tx->has_change_addr && (!mw_point_check_public(&tx->change_addr.spend) ||
                                !mw_point_check_public(&tx->change_addr.view))) {
        return refuse(info, MW_TXR_BAD_POINT, 0xFF, 0, 0);
    }

    // ---- inputs: matched, all in subaddr_account (wallet2 throws "the tx
    //      uses funds from multiple accounts")
    for (uint8_t i = 0; i < tx->n_inputs; ++i) {
        const mw_tx_source_t* s = &tx->sources[i];
        if (!s->subaddr_known) {
            return refuse(info, MW_TXR_INPUTS, i, 0, 0);
        }
        if (s->subaddr_major != acct) {
            return refuse(info, MW_TXR_ACCOUNT, i, s->subaddr_major, s->subaddr_minor);
        }
    }

    // ---- own candidates, one derived address at a time
    bool change_own = false;
    uint32_t change_M = 0, change_m = 0;
    {
        mw_address_t cand;
        uint32_t M = 0, m = 0;
        for (unsigned n = 0; candidate_at(tx, n, &M, &m); ++n) {
            if (candidate_seen(tx, n, M, m)) {
                continue;
            }
            if (mw_get_subaddress(keys, M, m, &cand) != MW_OK) {
                return MW_ERR_INVALID_ARG;
            }
            for (uint8_t i = 0; i < tx->n_destinations; ++i) {
                mw_tx_destination_t* d = &tx->destinations[i];
                const bool sp = mw_point_eq(&d->addr.spend, &cand.spend) != 0;
                const bool vw = mw_point_eq(&d->addr.view, &cand.view) != 0;
                if (sp && vw) {
                    if (!(hit[i] & HIT_OWN)) {
                        hit[i] |= HIT_OWN;
                        d->own_major = M;
                        d->own_minor = m;
                    }
                } else if (sp) {
                    hit[i] |= HIT_SPEND;
                } else if (vw) {
                    hit[i] |= HIT_VIEW;
                }
            }
            if (M == acct && m == 0) {
                tx->change_derived = cand;
            }
            if (tx->has_change_addr && !change_own && same_address(&tx->change_addr, &cand)) {
                change_own = true;
                change_M = M;
                change_m = m;
            }
        }
        mw_memzero(&cand, sizeof(cand));
    }

    // ---- classify every destination (0-amount ones included)
    for (uint8_t i = 0; i < tx->n_destinations; ++i) {
        mw_tx_destination_t* d = &tx->destinations[i];
        if (!(hit[i] & HIT_OWN)) {
            if (hit[i] & HIT_VIEW) {
                return refuse(info, MW_TXR_HYBRID_OUR_VIEW, i, 0, 0);
            }
            if (hit[i] & HIT_SPEND) {
                return refuse(info, MW_TXR_HYBRID_OUR_SPEND, i, 0, 0);
            }
            // A view key tied to ours: C == a*D. Either one of our
            // subaddresses the device has not seen yet, or a hybrid.
            mw_point_t aD;
            if (mw_point_scalarmult(&aD, &keys->sec.view, &d->addr.spend) == 0 &&
                mw_point_eq(&aD, &d->addr.view)) {
                uint32_t M = 0, m = 0;
                uint16_t searched = 0;
                const bool found = search_own_subaddress(keys, tx, &d->addr.spend,
                                                         &M, &m, &searched);
                info->searched = searched;
                if (!found) {
                    return refuse(info, MW_TXR_HYBRID_VIEW_LINKED, i, 0, 0);
                }
                hit[i] |= HIT_OWN;
                d->own_major = M;
                d->own_minor = m;
            }
        }
        if (hit[i] & HIT_OWN) {
            // An own address paid with the wrong derivation is an output the
            // wallet never finds.
            if (d->is_subaddress != ((d->own_major | d->own_minor) != 0)) {
                return refuse(info, MW_TXR_OWN_FLAG, i, d->own_major, d->own_minor);
            }
            d->kind = MW_DEST_OWN;
        }
    }

    // ---- change_dts
    if (!tx->has_change_addr) {
        return MW_OK;
    }
    uint64_t paid = 0;
    for (uint8_t i = 0; i < tx->n_destinations; ++i) {
        const mw_tx_destination_t* d = &tx->destinations[i];
        if (same_address(&d->addr, &tx->change_addr)) {
            if (d->amount > UINT64_MAX - paid) {
                return MW_ERR_RANGE;
            }
            paid += d->amount;
        }
    }
    if (tx->change_amount == 0 && paid == 0) {
        // wallet2's zero change: a 0-amount output to a random address.
        for (uint8_t i = 0; i < tx->n_destinations; ++i) {
            mw_tx_destination_t* d = &tx->destinations[i];
            if (same_address(&d->addr, &tx->change_addr)) {
                d->kind = MW_DEST_DUMMY;
            }
        }
        return MW_OK;
    }
    if (!change_own) {
        return refuse(info, MW_TXR_CHANGE_NOT_OURS, 0xFF, acct, 0);
    }
    if (change_M != acct || change_m != 0) {
        return refuse(info, MW_TXR_CHANGE_INDEX, 0xFF, change_M, change_m);
    }
    if (tx->change_is_subaddress != (acct != 0)) {
        return refuse(info, MW_TXR_CHANGE_FLAG, 0xFF, acct, 0);
    }
    if (tx->change_amount > paid) {
        info->claimed = tx->change_amount;
        info->paid = paid;
        return refuse(info, MW_TXR_CHANGE_UNPAID, 0xFF, acct, 0);
    }
    for (uint8_t i = 0; i < tx->n_destinations; ++i) {
        mw_tx_destination_t* d = &tx->destinations[i];
        if (same_address(&d->addr, &tx->change_addr)) {
            d->kind = MW_DEST_CHANGE;
            d->is_change = true;
        }
    }
    tx->change_verified = true;
    tx->change_major = acct;
    tx->change_minor = 0;
    return MW_OK;
}

mw_err_t mw_tx_check_destinations(const mw_account_keys_t* keys, mw_transaction_t* tx,
                                  mw_tx_check_info_t* info)
{
    if (keys == NULL || tx == NULL) {
        return MW_ERR_INVALID_ARG;
    }
    if (tx->n_destinations > MW_MAX_DESTINATIONS || tx->n_inputs > MW_MAX_INPUTS) {
        return MW_ERR_TOO_MANY;
    }

    tx->change_verified = false;
    tx->change_major = 0;
    tx->change_minor = 0;
    memset(&tx->change_derived, 0, sizeof(tx->change_derived));
    memset(&tx->check, 0, sizeof(tx->check));
    for (uint8_t i = 0; i < tx->n_destinations; ++i) {
        tx->destinations[i].is_change = false;
        tx->destinations[i].kind = MW_DEST_FOREIGN;
        tx->destinations[i].own_major = 0;
        tx->destinations[i].own_minor = 0;
    }

    const mw_err_t err = check_destinations(keys, tx, &tx->check);
    if (err != MW_OK) {
        // Nothing half-classified survives a refusal.
        tx->change_verified = false;
        for (uint8_t i = 0; i < tx->n_destinations; ++i) {
            tx->destinations[i].is_change = false;
            tx->destinations[i].kind = MW_DEST_FOREIGN;
        }
    }
    if (info != NULL) {
        *info = tx->check;
    }
    return err;
}

// ------------------------------------------------------------------ balance
mw_err_t mw_tx_check_balance(const mw_transaction_t* tx)
{
    if (tx == NULL) {
        return MW_ERR_INVALID_ARG;
    }
    if (tx->n_inputs == 0 || tx->n_inputs > MW_MAX_INPUTS) {
        return MW_ERR_TOO_MANY;
    }
    if (tx->n_outputs == 0 || tx->n_outputs > MW_MAX_OUTPUTS) {
        return MW_ERR_TOO_MANY;
    }

    uint64_t in = 0;
    for (uint8_t i = 0; i < tx->n_inputs; ++i) {
        if (tx->sources[i].amount > UINT64_MAX - in) {
            return MW_ERR_RANGE;
        }
        in += tx->sources[i].amount;
    }

    uint64_t out = tx->fee;
    for (uint8_t i = 0; i < tx->n_outputs; ++i) {
        if (tx->outputs[i].amount > UINT64_MAX - out) {
            return MW_ERR_RANGE;
        }
        out += tx->outputs[i].amount;
    }

    return (in == out) ? MW_OK : MW_ERR_BALANCE;
}

// ------------------------------------------------------------------ summary
// The address shown to the user is re-encoded from the keys we are actually
// going to pay, never copied from a string in the file.
static mw_err_t encode_destination(const mw_transaction_t* tx, const mw_tx_destination_t* d,
                                   mw_network_t net, char* out)
{
    mw_address_t addr = d->addr;
    addr.network = net;
    if (d->is_subaddress) {
        addr.type = MW_ADDR_SUBADDRESS;
        addr.has_payment_id = false;
    } else if (d->is_integrated || d->addr.type == MW_ADDR_INTEGRATED ||
               addr.has_payment_id) {
        // The unsigned tx set marks a destination as integrated with a flag,
        // but keeps the payment id in tx_extra rather than in the destination
        // record. Re-deriving the type from has_payment_id alone therefore
        // used to downgrade every integrated recipient to its 95-character
        // base address - and the user is told to compare that address with
        // the online wallet character by character, a comparison that could
        // then never succeed.
        if (!addr.has_payment_id) {
            // The PLAIN payment id lives in the extra the online wallet
            // supplied; the signed extra carries it encrypted.
            if (!mw_tx_extra_find_payment_id(tx->extra_in, tx->extra_in_len,
                                             addr.payment_id)) {
                // Refuse rather than fall back to the base address: showing
                // a different address than the one being paid is exactly the
                // failure this check exists to prevent.
                return MW_ERR_FORMAT;
            }
            addr.has_payment_id = true;
        }
        addr.type = MW_ADDR_INTEGRATED;
    } else {
        addr.type = MW_ADDR_STANDARD;
    }
    return mw_address_encode(&addr, out, MW_ADDRESS_STR_MAX);
}

static mw_err_t add_recipient(const mw_transaction_t* tx, const mw_tx_destination_t* d,
                              uint64_t amount, mw_network_t net, mw_tx_summary_t* out)
{
    if (out->n_recipients >= MW_MAX_DESTINATIONS) {
        return MW_ERR_TOO_MANY;
    }
    if (amount > UINT64_MAX - out->total_out) {
        return MW_ERR_RANGE;
    }
    const uint8_t r = out->n_recipients;
    mw_err_t err = encode_destination(tx, d, net, out->recipients[r]);
    if (err != MW_OK) {
        return err;
    }
    out->total_out += amount;
    out->amounts[r] = amount;
    if (d->kind == MW_DEST_OWN || d->kind == MW_DEST_CHANGE) {
        out->recipient_own[r] = true;
        out->recipient_major[r] = d->own_major;
        out->recipient_minor[r] = d->own_minor;
    }
    ++out->n_recipients;
    return MW_OK;
}

mw_err_t mw_tx_summarize(const mw_transaction_t* tx, mw_network_t net,
                         mw_tx_summary_t* out)
{
    if (tx == NULL || out == NULL) {
        return MW_ERR_INVALID_ARG;
    }
    if (tx->n_destinations > MW_MAX_DESTINATIONS ||
        tx->n_inputs > MW_MAX_INPUTS || tx->n_outputs > MW_MAX_OUTPUTS) {
        return MW_ERR_TOO_MANY;
    }

    memset(out, 0, sizeof(*out));
    out->fee = tx->fee;
    out->n_inputs = tx->n_inputs;
    out->n_outputs = tx->n_outputs;

    for (uint8_t i = 0; i < tx->n_inputs; ++i) {
        if (tx->sources[i].amount > UINT64_MAX - out->total_in) {
            return MW_ERR_RANGE;
        }
        out->total_in += tx->sources[i].amount;
    }

    // Change: only the address the device re-derived counts as change.
    uint64_t change_paid = 0;
    const mw_tx_destination_t* change_dest = NULL;
    for (uint8_t i = 0; i < tx->n_destinations; ++i) {
        const mw_tx_destination_t* d = &tx->destinations[i];
        const bool change = (d->kind == MW_DEST_CHANGE);
        if (change != d->is_change) {
            return MW_ERR_INVALID_ARG;
        }
        if (!change) {
            continue;
        }
        if (!tx->change_verified || !same_address(&d->addr, &tx->change_derived)) {
            return MW_ERR_INVALID_ARG;
        }
        if (d->amount > UINT64_MAX - change_paid) {
            return MW_ERR_RANGE;
        }
        change_paid += d->amount;
        change_dest = d;
    }
    if (change_dest != NULL) {
        if (tx->change_amount > change_paid) {
            return MW_ERR_INVALID_ARG;
        }
        out->change = tx->change_amount;
        out->has_change = tx->change_amount > 0;
        out->change_major = tx->change_major;
        out->change_minor = tx->change_minor;
        mw_address_t ca = tx->change_derived;
        ca.network = net;
        ca.type = (tx->change_major | tx->change_minor) ? MW_ADDR_SUBADDRESS
                                                        : MW_ADDR_STANDARD;
        ca.has_payment_id = false;
        mw_err_t err = mw_address_encode(&ca, out->change_addr, MW_ADDRESS_STR_MAX);
        if (err != MW_OK) {
            return err;
        }
    }

    for (uint8_t i = 0; i < tx->n_destinations; ++i) {
        const mw_tx_destination_t* d = &tx->destinations[i];
        if (d->kind == MW_DEST_CHANGE) {
            continue;
        }
        if (d->kind == MW_DEST_DUMMY) {
            if (d->amount != 0) {
                return MW_ERR_INVALID_ARG;
            }
            ++out->n_dummy;
            continue;
        }
        mw_err_t err = add_recipient(tx, d, d->amount, net, out);
        if (err != MW_OK) {
            return err;
        }
    }
    // A payment to the change address beyond the claimed change (a send to
    // self at (acct, 0)) is shown as an own recipient.
    if (change_dest != NULL && change_paid > tx->change_amount) {
        mw_err_t err = add_recipient(tx, change_dest, change_paid - tx->change_amount,
                                     net, out);
        if (err != MW_OK) {
            return err;
        }
    }

    // Fee sanity: dropped change turns into fee.
    const uint64_t moved = out->total_out + out->change;
    out->high_fee = out->fee > MW_TX_HIGH_FEE_ABS ||
                    (out->fee > UINT64_MAX / 10u) || out->fee * 10u > moved;
    return MW_OK;
}

// -------------------------------------------------------------- prefix hash
mw_err_t mw_tx_prefix_hash(const mw_transaction_t* tx, uint8_t out[32])
{
    if (tx == NULL || out == NULL) {
        return MW_ERR_INVALID_ARG;
    }
    if (tx->n_inputs == 0 || tx->n_inputs > MW_MAX_INPUTS ||
        tx->n_outputs == 0 || tx->n_outputs > MW_MAX_OUTPUTS) {
        return MW_ERR_TOO_MANY;
    }
    if (tx->tx_extra_len > MW_MAX_TX_EXTRA) {
        return MW_ERR_TOO_MANY;
    }

    mw_keccak_ctx ctx;
    mw_keccak_init(&ctx);

    keccak_varint(&ctx, tx->version);
    keccak_varint(&ctx, tx->unlock_time);

    keccak_varint(&ctx, tx->n_inputs);
    for (uint8_t i = 0; i < tx->n_inputs; ++i) {
        const mw_tx_source_t* s = &tx->sources[i];
        if (s->ring_size == 0 || s->ring_size > MW_MAX_RING_SIZE) {
            return MW_ERR_TOO_MANY;
        }
        keccak_u8(&ctx, TXIN_TO_KEY);
        keccak_varint(&ctx, 0);                  // RingCT: amount is hidden
        keccak_varint(&ctx, s->ring_size);
        for (uint8_t k = 0; k < s->ring_size; ++k) {
            keccak_varint(&ctx, s->key_offsets[k]);
        }
        mw_keccak_update(&ctx, s->key_image.b, 32);
    }

    keccak_varint(&ctx, tx->n_outputs);
    for (uint8_t i = 0; i < tx->n_outputs; ++i) {
        const mw_tx_output_t* o = &tx->outputs[i];
        keccak_varint(&ctx, 0);                  // RingCT: amount is hidden
        keccak_u8(&ctx, o->has_view_tag ? TXOUT_TO_TAGGED_KEY : TXOUT_TO_KEY);
        mw_keccak_update(&ctx, o->out_pubkey.b, 32);
        if (o->has_view_tag) {
            keccak_u8(&ctx, o->view_tag);
        }
    }

    keccak_varint(&ctx, tx->tx_extra_len);
    if (tx->tx_extra_len != 0) {
        mw_keccak_update(&ctx, tx->tx_extra, tx->tx_extra_len);
    }

    mw_keccak_final(&ctx, out);
    return MW_OK;
}

// --------------------------------------------------------- RCT message hash
// rctSigBase for type 6 (BulletproofPlus):
//     byte   type
//     varint txnFee
//     for each output: 8 bytes of the masked amount (ecdhInfo, short form)
//     for each output: 32 bytes outPk.mask
// pseudoOuts live in the prunable part for every bulletproof-era type, so they
// are not part of this hash.
//
// message = keccak( prefix_hash || keccak(rctSigBase) || keccak(bp blob) )
mw_err_t mw_tx_rct_message(const mw_transaction_t* tx,
                           const uint8_t* bp_serialized, size_t bp_len,
                           uint8_t out[32])
{
    if (tx == NULL || out == NULL || (bp_serialized == NULL && bp_len != 0)) {
        return MW_ERR_INVALID_ARG;
    }
    if (tx->n_outputs == 0 || tx->n_outputs > MW_MAX_OUTPUTS) {
        return MW_ERR_TOO_MANY;
    }

    uint8_t prefix_hash[32];
    mw_err_t err = mw_tx_prefix_hash(tx, prefix_hash);
    if (err != MW_OK) {
        return err;
    }

    mw_keccak_ctx ctx;
    mw_keccak_init(&ctx);
    keccak_u8(&ctx, tx->rct_type);
    keccak_varint(&ctx, tx->fee);
    for (uint8_t i = 0; i < tx->n_outputs; ++i) {
        mw_keccak_update(&ctx, tx->outputs[i].ecdh_amount, 8);
    }
    for (uint8_t i = 0; i < tx->n_outputs; ++i) {
        mw_keccak_update(&ctx, tx->outputs[i].commitment.b, 32);
    }
    uint8_t base_hash[32];
    mw_keccak_final(&ctx, base_hash);

    uint8_t bp_hash[32];
    mw_keccak256(bp_serialized, bp_len, bp_hash);

    uint8_t buf[96];
    memcpy(buf, prefix_hash, 32);
    memcpy(buf + 32, base_hash, 32);
    memcpy(buf + 64, bp_hash, 32);
    mw_keccak256(buf, sizeof(buf), out);
    return MW_OK;
}

// ------------------------------------------------------------------ extra
// construct_tx() finishes with sort_tx_extra(), which emits the fields in a
// fixed order: tx public key (0x01), additional tx public keys (0x04), then
// the nonce (0x02). A cold-signed wallet2 transaction therefore always has
// exactly this layout, and so does ours.
mw_err_t mw_tx_extra_build(mw_transaction_t* tx,
                           const mw_pubkey_t* additional, uint8_t n_additional,
                           const uint8_t* nonce, size_t nonce_len)
{
    if (tx == NULL) {
        return MW_ERR_INVALID_ARG;
    }
    if (n_additional > MW_MAX_OUTPUTS) {
        return MW_ERR_TOO_MANY;
    }
    if (n_additional != 0 && additional == NULL) {
        return MW_ERR_INVALID_ARG;
    }
    if ((nonce == NULL && nonce_len != 0) || nonce_len > 255) {
        return MW_ERR_INVALID_ARG;
    }

    uint8_t buf[MW_MAX_TX_EXTRA];
    mw_writer_t w;
    mw_writer_init(&w, buf, sizeof(buf));

    mw_write_u8(&w, TX_EXTRA_TAG_PUBKEY);
    mw_write_point(&w, &tx->tx_public_key);

    if (n_additional != 0) {
        mw_write_u8(&w, TX_EXTRA_TAG_ADDITIONAL_PUBKEYS);
        mw_write_varint(&w, n_additional);
        for (uint8_t i = 0; i < n_additional; ++i) {
            mw_write_point(&w, &additional[i]);
        }
    }

    if (nonce != NULL) {
        mw_write_u8(&w, TX_EXTRA_NONCE);
        mw_write_varint(&w, nonce_len);
        mw_write_bytes(&w, nonce, nonce_len);
    }

    if (w.overflow) {
        mw_memzero(buf, sizeof(buf));
        return MW_ERR_TOO_MANY;
    }

    memcpy(tx->tx_extra, buf, w.pos);
    tx->tx_extra_len = (uint16_t)w.pos;
    mw_memzero(buf, sizeof(buf));
    return MW_OK;
}
