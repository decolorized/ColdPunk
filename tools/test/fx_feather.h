// Test fixture: an INDEPENDENT encoder for the Monero / Feather exchange
// files and a decoder for signed transactions.
//
// It is written from the wallet2 / serialization sources directly (see
// file_formats.h for the rules), not from the device parser, so a mistake in
// one is not silently mirrored by the other:
//   FIELD(u64/u32)  fixed little endian      VARINT_FIELD  varint
//   bool            1 byte                   vector/string varint count
//   pair            varint 2 + elements      tuple<3>      varint 3 + elements
//   u64/size_t/u32 elements of containers, pairs and tuples: varint
//
// Header-only (static functions) because every test binary is built from one
// .c file plus the core objects.
#ifndef FX_FEATHER_H
#define FX_FEATHER_H

#if defined(__GNUC__)
#pragma GCC diagnostic ignored "-Wunused-function"
#endif

#include <string.h>

#include "test_framework.h"

#include "crypto/ed25519.h"
#include "crypto/hash.h"
#include "crypto/random.h"
#include "monero/bulletproof_plus.h"
#include "monero/clsag.h"
#include "monero/file_formats.h"
#include "monero/keys.h"
#include "monero/serialize.h"
#include "monero/tx.h"

// ------------------------------------------------------------ primitives
static void fx_varint(mw_writer_t* w, uint64_t v) { mw_write_varint(w, v); }
static void fx_u64(mw_writer_t* w, uint64_t v)    { mw_write_u64(w, v); }
static void fx_u32(mw_writer_t* w, uint32_t v)    { mw_write_u32(w, v); }
static void fx_u8(mw_writer_t* w, uint8_t v)      { mw_write_u8(w, v); }
static void fx_bool(mw_writer_t* w, int v)        { mw_write_u8(w, v ? 1 : 0); }
static void fx_blob(mw_writer_t* w, const void* p, size_t n) { mw_write_bytes(w, p, n); }

static void fx_amount_scalar(uint64_t v, mw_scalar_t* s)
{
    mw_sc_0(s);
    for (int i = 0; i < 8; ++i) s->b[i] = (uint8_t)(v >> (8 * i));
}

static void fx_random_point(mw_point_t* p)
{
    mw_scalar_t k;
    mw_sc_random(&k);
    mw_point_scalarmult_base(p, &k);
}

static void fx_account(mw_account_keys_t* keys, uint8_t seed_byte)
{
    uint8_t seed[32];
    for (int i = 0; i < 32; ++i) seed[i] = (uint8_t)(seed_byte + 7 * i);
    mw_keys_from_legacy_seed(seed, keys);
    CHECK_EQ_INT(mw_keys_derive_public(keys), MW_OK);
}

// ------------------------------------------------------------ outputs
typedef struct {
    mw_pubkey_t one_time;
    mw_pubkey_t tx_pub;          // main tx public key of the source tx
    int         n_add;           // additional keys listed in the record
    mw_pubkey_t add[16];
    uint32_t    idx;             // output index inside the source tx
    uint64_t    global;
    uint64_t    amount;
    uint32_t    major, minor;
    mw_scalar_t mask;
    mw_point_t  commitment;
} fx_output_t;

// An output paid to (major, minor) of `keys`, output `idx` of its tx:
//   main address:  R = r*G,            P = Hs(8*r*A || i)*G + B
//   subaddress:    additional[idx] = r*D, the main R is someone else's,
//                  P = Hs(8*r*C || i)*G + D  (C = a*D is its view key)
static void fx_make_output(const mw_account_keys_t* keys, uint32_t idx,
                           uint32_t major, uint32_t minor, uint64_t amount,
                           uint64_t global, fx_output_t* o)
{
    memset(o, 0, sizeof(*o));
    o->idx = idx;
    o->global = global;
    o->amount = amount;
    o->major = major;
    o->minor = minor;

    mw_address_t a;
    CHECK_EQ_INT(mw_get_subaddress(keys, major, minor, &a), MW_OK);
    mw_scalar_t r;
    mw_sc_random(&r);
    mw_point_t derivation;
    if (major == 0 && minor == 0) {
        mw_point_scalarmult_base(&o->tx_pub, &r);
    } else {
        fx_random_point(&o->tx_pub);
        o->n_add = (int)idx + 2;                 // more keys than needed
        for (int k = 0; k < o->n_add; ++k) fx_random_point(&o->add[k]);
        CHECK_EQ_INT(mw_point_scalarmult(&o->add[idx], &r, &a.spend), 0);
    }
    CHECK_EQ_INT(mw_generate_key_derivation(&a.view, &r, &derivation), MW_OK);
    CHECK_EQ_INT(mw_derive_public_key(&derivation, idx, &a.spend, &o->one_time), MW_OK);

    mw_scalar_t am;
    mw_sc_random(&o->mask);
    fx_amount_scalar(amount, &am);
    mw_commit(&o->commitment, &o->mask, &am);
}

// tools::wallet2::exported_transfer_details
static void fx_write_etd(mw_writer_t* w, const fx_output_t* o)
{
    fx_varint(w, 1);                     // VERSION_FIELD(1)
    fx_blob(w, o->one_time.b, 32);       // m_pubkey
    fx_varint(w, o->idx);                // m_internal_output_index
    fx_varint(w, o->global);             // m_global_output_index
    fx_blob(w, o->tx_pub.b, 32);         // m_tx_pubkey
    fx_u8(w, 0x04);                      // m_flags: m_rct
    fx_varint(w, o->amount);             // m_amount
    fx_varint(w, (uint64_t)o->n_add);    // m_additional_tx_keys
    for (int k = 0; k < o->n_add; ++k) fx_blob(w, o->add[k].b, 32);
    fx_varint(w, o->major);              // m_subaddr_index_major
    fx_varint(w, o->minor);              // m_subaddr_index_minor
}

// export_outputs_to_str() plaintext.
static size_t fx_outputs_plain(const mw_account_keys_t* keys, const fx_output_t* outs,
                               int n, uint64_t offset, uint64_t total,
                               uint8_t* buf, size_t cap)
{
    mw_writer_t w;
    mw_writer_init(&w, buf, cap);
    fx_blob(&w, keys->pub.spend.b, 32);
    fx_blob(&w, keys->pub.view.b, 32);
    fx_varint(&w, 3);                    // std::tuple<u64, u64, vector>
    fx_varint(&w, offset);
    fx_varint(&w, total);
    fx_varint(&w, (uint64_t)n);
    for (int i = 0; i < n; ++i) fx_write_etd(&w, &outs[i]);
    CHECK(!w.overflow);
    return w.pos;
}

// ------------------------------------------------------------ unsigned set
typedef struct {
    uint64_t    amount;
    mw_pubkey_t spend, view;
    int         is_sub, is_int;
} fx_dest_t;

// cryptonote::tx_destination_entry
static void fx_write_dest(mw_writer_t* w, const fx_dest_t* d)
{
    static const char original[] = "4Adestination";
    fx_varint(w, sizeof(original) - 1);  // std::string original
    fx_blob(w, original, sizeof(original) - 1);
    fx_varint(w, d->amount);             // VARINT_FIELD(amount)
    fx_blob(w, d->spend.b, 32);          // addr
    fx_blob(w, d->view.b, 32);
    fx_bool(w, d->is_sub);
    fx_bool(w, d->is_int);
}

#define FX_RING 16

typedef struct {
    fx_output_t real;
    int         real_pos;
    uint64_t    first_global;
    mw_ctkey_t  ring[FX_RING];           // what was written, for verification
    uint64_t    global[FX_RING];
} fx_source_t;

static void fx_make_source(fx_source_t* s, const fx_output_t* real, int real_pos,
                           uint64_t first_global)
{
    memset(s, 0, sizeof(*s));
    s->real = *real;
    s->real_pos = real_pos;
    s->first_global = first_global;
    for (int k = 0; k < FX_RING; ++k) {
        s->global[k] = first_global + 10u * (uint64_t)k;
        if (k == real_pos) {
            s->ring[k].dest = real->one_time;
            s->ring[k].mask = real->commitment;
        } else {
            mw_scalar_t m, a;
            fx_random_point(&s->ring[k].dest);
            mw_sc_random(&m);
            fx_amount_scalar(1000u + (uint64_t)k, &a);
            mw_commit(&s->ring[k].mask, &m, &a);
        }
    }
}

// cryptonote::tx_source_entry
static void fx_write_source(mw_writer_t* w, const fx_source_t* s)
{
    static const uint8_t zero128[128] = {0};
    fx_varint(w, FX_RING);                            // outputs
    for (int k = 0; k < FX_RING; ++k) {
        fx_varint(w, 2);                              // std::pair
        fx_varint(w, s->global[k]);                   //   u64 -> varint
        fx_blob(w, s->ring[k].dest.b, 32);            //   rct::ctkey
        fx_blob(w, s->ring[k].mask.b, 32);
    }
    fx_u64(w, (uint64_t)s->real_pos);                 // real_output (FIELD u64)
    fx_blob(w, s->real.tx_pub.b, 32);                 // real_out_tx_key
    fx_varint(w, (uint64_t)s->real.n_add);            // real_out_additional_tx_keys
    for (int k = 0; k < s->real.n_add; ++k) fx_blob(w, s->real.add[k].b, 32);
    fx_u64(w, s->real.idx);                           // real_output_in_tx_index
    fx_u64(w, s->real.amount);                        // amount
    fx_bool(w, 1);                                    // rct
    fx_blob(w, s->real.mask.b, 32);                   // mask
    fx_blob(w, zero128, sizeof zero128);              // multisig_kLRki
}

typedef struct {
    fx_source_t sources[8];
    int         n_sources;
    fx_dest_t   change;
    fx_dest_t   splitted[8];
    int         n_splitted;
    uint8_t     extra[64];
    int         extra_len;
    uint32_t    subaddr_account;
    uint32_t    subaddr_indices[4];
    int         n_indices;
    int         view_tags;
} fx_cd_t;

// tools::wallet2::tx_construction_data
static void fx_write_cd(mw_writer_t* w, const fx_cd_t* cd)
{
    fx_varint(w, (uint64_t)cd->n_sources);            // sources
    for (int i = 0; i < cd->n_sources; ++i) fx_write_source(w, &cd->sources[i]);
    fx_write_dest(w, &cd->change);                    // change_dts
    fx_varint(w, (uint64_t)cd->n_splitted);           // splitted_dsts
    for (int i = 0; i < cd->n_splitted; ++i) fx_write_dest(w, &cd->splitted[i]);
    fx_varint(w, 2);                                  // selected_transfers
    fx_varint(w, 3);
    fx_varint(w, 300);                                //   (varint > 127)
    fx_varint(w, (uint64_t)cd->extra_len);            // extra
    fx_blob(w, cd->extra, (size_t)cd->extra_len);
    fx_u64(w, 0);                                     // unlock_time (FIELD u64)
    fx_u8(w, (uint8_t)(1u | (cd->view_tags ? 2u : 0u)));   // construction_flags
    fx_varint(w, 0);                                  // rct_config VERSION_FIELD(0)
    fx_varint(w, 3);                                  //   RangeProofPaddedBulletproof
    fx_varint(w, 4);                                  //   bp_version 4 = BP+
    fx_varint(w, (uint64_t)(cd->n_splitted - 1));     // dests (w/o change)
    for (int i = 0; i + 1 < cd->n_splitted; ++i) fx_write_dest(w, &cd->splitted[i]);
    fx_u32(w, cd->subaddr_account);                   // subaddr_account (FIELD u32)
    fx_varint(w, (uint64_t)cd->n_indices);            // subaddr_indices (set<u32>)
    for (int i = 0; i < cd->n_indices; ++i) fx_varint(w, cd->subaddr_indices[i]);
}

// unsigned_tx_set, VERSION 2 (tuple) or 1 (pair).
static size_t fx_unsigned_set(const fx_cd_t* cds, int n_cds, const fx_output_t* nt,
                              int n_nt, int version, uint8_t* buf, size_t cap)
{
    mw_writer_t w;
    mw_writer_init(&w, buf, cap);
    fx_varint(&w, (uint64_t)version);
    fx_varint(&w, (uint64_t)n_cds);
    for (int i = 0; i < n_cds; ++i) fx_write_cd(&w, &cds[i]);
    if (version == 1) {
        fx_varint(&w, 2);                             // pair<size_t, vector>
        fx_varint(&w, 5);
    } else {
        fx_varint(&w, 3);                             // tuple<u64, u64, vector>
        fx_varint(&w, 5);
        fx_varint(&w, 5 + (uint64_t)n_nt);
    }
    fx_varint(&w, (uint64_t)n_nt);
    for (int i = 0; i < n_nt; ++i) fx_write_etd(&w, &nt[i]);
    CHECK(!w.overflow);
    return w.pos;
}

static void fx_dest_from_address(fx_dest_t* d, const mw_address_t* a, uint64_t amount)
{
    memset(d, 0, sizeof(*d));
    d->amount = amount;
    d->spend = a->spend;
    d->view = a->view;
    d->is_sub = (a->type == MW_ADDR_SUBADDRESS);
}

static void fx_foreign_address(mw_address_t* a)
{
    memset(a, 0, sizeof(*a));
    fx_random_point(&a->spend);
    fx_random_point(&a->view);
    a->type = MW_ADDR_STANDARD;
}

// Hybrid addresses an attacker who knows the victim's view key can build.
// (B_att, A): spendable by the attacker, seen by nobody.
static void fx_hybrid_view(mw_address_t* a, const mw_account_keys_t* victim)
{
    memset(a, 0, sizeof(*a));
    fx_random_point(&a->spend);
    a->view = victim->pub.view;
    a->type = MW_ADDR_STANDARD;
}

// (D', a*D'): looks like one of the victim's subaddresses, spend key foreign.
static void fx_hybrid_subaddr(mw_address_t* a, const mw_account_keys_t* victim)
{
    memset(a, 0, sizeof(*a));
    fx_random_point(&a->spend);
    CHECK_EQ_INT(mw_point_scalarmult(&a->view, &victim->sec.view, &a->spend), 0);
    a->type = MW_ADDR_SUBADDRESS;
}

// (B, A_att): the victim's spend key, nobody's view key - burned funds, and
// the same leading characters as the victim's main address.
static void fx_hybrid_spend(mw_address_t* a, const mw_account_keys_t* victim)
{
    memset(a, 0, sizeof(*a));
    a->spend = victim->pub.spend;
    fx_random_point(&a->view);
    a->type = MW_ADDR_STANDARD;
}

// ------------------------------------------------------------ signed tx
typedef struct {
    uint64_t      version, unlock;
    uint32_t      n_in;
    uint32_t      ring_size;
    uint64_t      abs_index[MW_MAX_INPUTS][MW_MAX_RING_SIZE];
    mw_keyimage_t ki[MW_MAX_INPUTS];
    uint32_t      n_out;
    mw_pubkey_t   out_key[MW_MAX_OUTPUTS];
    uint8_t       view_tag[MW_MAX_OUTPUTS];
    uint8_t       extra[MW_MAX_TX_EXTRA];
    size_t        extra_len;
    size_t        prefix_len;
    uint8_t       rct_type;
    uint64_t      fee;
    uint8_t       ecdh[MW_MAX_OUTPUTS][8];
    mw_point_t    out_pk[MW_MAX_OUTPUTS];
    size_t        base_off, base_len;
    mw_bpp_proof_t bpp;
    mw_clsag_t    cl[MW_MAX_INPUTS];
    mw_point_t    pseudo[MW_MAX_INPUTS];
    size_t        len;
} fx_tx_t;

// Decodes a serialized v2 BulletproofPlus transaction. 0 on success.
static int fx_decode_tx(const uint8_t* p, size_t len, fx_tx_t* t)
{
    mw_reader_t r;
    uint64_t v = 0;
    memset(t, 0, sizeof(*t));
    mw_reader_init(&r, p, len);
    if (!mw_read_varint(&r, &t->version) || !mw_read_varint(&r, &t->unlock)) return 1;
    if (!mw_read_varint(&r, &v) || v == 0 || v > MW_MAX_INPUTS) return 2;
    t->n_in = (uint32_t)v;
    for (uint32_t i = 0; i < t->n_in; ++i) {
        uint8_t tag = 0;
        uint64_t amount = 1, n = 0, acc = 0;
        if (!mw_read_u8(&r, &tag) || tag != 0x02) return 3;
        if (!mw_read_varint(&r, &amount) || amount != 0) return 4;
        if (!mw_read_varint(&r, &n) || n == 0 || n > MW_MAX_RING_SIZE) return 5;
        if (i == 0) t->ring_size = (uint32_t)n;
        else if (n != t->ring_size) return 6;
        for (uint64_t k = 0; k < n; ++k) {
            uint64_t off = 0;
            if (!mw_read_varint(&r, &off)) return 7;
            acc += off;
            t->abs_index[i][k] = acc;
        }
        if (!mw_read_point(&r, &t->ki[i])) return 8;
    }
    if (!mw_read_varint(&r, &v) || v == 0 || v > MW_MAX_OUTPUTS) return 9;
    t->n_out = (uint32_t)v;
    for (uint32_t i = 0; i < t->n_out; ++i) {
        uint64_t amount = 1;
        uint8_t tag = 0;
        if (!mw_read_varint(&r, &amount) || amount != 0) return 10;
        if (!mw_read_u8(&r, &tag) || tag != 0x03) return 11;    // tagged key
        if (!mw_read_point(&r, &t->out_key[i]) || !mw_read_u8(&r, &t->view_tag[i])) return 12;
    }
    if (!mw_read_varint(&r, &v) || v > MW_MAX_TX_EXTRA) return 13;
    t->extra_len = (size_t)v;
    if (!mw_read_bytes(&r, t->extra, t->extra_len)) return 14;
    t->prefix_len = r.pos;

    t->base_off = r.pos;
    if (!mw_read_u8(&r, &t->rct_type) || t->rct_type != 6) return 15;
    if (!mw_read_varint(&r, &t->fee)) return 16;
    for (uint32_t i = 0; i < t->n_out; ++i)
        if (!mw_read_bytes(&r, t->ecdh[i], 8)) return 17;
    for (uint32_t i = 0; i < t->n_out; ++i)
        if (!mw_read_point(&r, &t->out_pk[i])) return 18;
    t->base_len = r.pos - t->base_off;

    if (!mw_read_varint(&r, &v) || v != 1) return 19;          // nbp
    {
        mw_bpp_proof_t* b = &t->bpp;
        uint64_t nl = 0, nr = 0;
        if (!mw_read_point(&r, &b->A) || !mw_read_point(&r, &b->A1) ||
            !mw_read_point(&r, &b->B) || !mw_read_scalar(&r, &b->r1) ||
            !mw_read_scalar(&r, &b->s1) || !mw_read_scalar(&r, &b->d1)) return 20;
        if (!mw_read_varint(&r, &nl) || nl > MW_BPP_MAX_LOG_MN) return 21;
        for (uint64_t k = 0; k < nl; ++k) if (!mw_read_point(&r, &b->L[k])) return 22;
        if (!mw_read_varint(&r, &nr) || nr != nl) return 23;
        for (uint64_t k = 0; k < nr; ++k) if (!mw_read_point(&r, &b->R[k])) return 24;
        b->n_lr = (uint8_t)nl;
    }
    for (uint32_t i = 0; i < t->n_in; ++i) {
        mw_clsag_t* c = &t->cl[i];
        c->n = (uint8_t)t->ring_size;
        for (uint32_t k = 0; k < t->ring_size; ++k)
            if (!mw_read_scalar(&r, &c->s[k])) return 25;
        if (!mw_read_scalar(&r, &c->c1) || !mw_read_point(&r, &c->D)) return 26;
    }
    for (uint32_t i = 0; i < t->n_in; ++i)
        if (!mw_read_point(&r, &t->pseudo[i])) return 27;
    t->len = r.pos;
    return r.overflow ? 28 : 0;
}

// Verifies the decoded transaction the way a node would: the RCT message,
// every CLSAG against the ring it references (looked up in `sources` by
// global index), the BP+ range proof against outPk, and the balance.
static int fx_verify_tx(const uint8_t* p, const fx_tx_t* t, const fx_source_t* sources,
                        int n_sources)
{
    uint8_t prefix_hash[32], base_hash[32], bp_hash[32], buf[96], msg[32];
    mw_keccak256(p, t->prefix_len, prefix_hash);
    mw_keccak256(p + t->base_off, t->base_len, base_hash);
    {
        uint8_t kv[(6 + 2 * MW_BPP_MAX_LOG_MN) * 32];
        size_t n = 0;
        const mw_bpp_proof_t* b = &t->bpp;
        memcpy(kv + n, b->A.b, 32); n += 32;
        memcpy(kv + n, b->A1.b, 32); n += 32;
        memcpy(kv + n, b->B.b, 32); n += 32;
        memcpy(kv + n, b->r1.b, 32); n += 32;
        memcpy(kv + n, b->s1.b, 32); n += 32;
        memcpy(kv + n, b->d1.b, 32); n += 32;
        for (uint8_t k = 0; k < b->n_lr; ++k) { memcpy(kv + n, b->L[k].b, 32); n += 32; }
        for (uint8_t k = 0; k < b->n_lr; ++k) { memcpy(kv + n, b->R[k].b, 32); n += 32; }
        mw_keccak256(kv, n, bp_hash);
    }
    memcpy(buf, prefix_hash, 32);
    memcpy(buf + 32, base_hash, 32);
    memcpy(buf + 64, bp_hash, 32);
    mw_keccak256(buf, 96, msg);

    for (uint32_t i = 0; i < t->n_in; ++i) {
        // Find the source whose ring has these global indices.
        const fx_source_t* src = NULL;
        for (int s = 0; s < n_sources; ++s)
            if (sources[s].global[0] == t->abs_index[i][0]) src = &sources[s];
        if (!src) return 100;
        for (uint32_t k = 0; k < t->ring_size; ++k)
            if (src->global[k] != t->abs_index[i][k]) return 101;
        if (mw_clsag_verify(msg, src->ring, (uint8_t)t->ring_size, &t->pseudo[i],
                            &t->ki[i], &t->cl[i]) != MW_OK) return 102;
    }

    // BP+: V = outPk / 8 (the serialized form drops V).
    {
        mw_bpp_proof_t b = t->bpp;
        mw_scalar_t eight, inv8;
        mw_sc_0(&eight);
        eight.b[0] = 8;
        mw_sc_invert(&inv8, &eight);
        b.n_v = (uint8_t)t->n_out;
        for (uint32_t i = 0; i < t->n_out; ++i)
            if (mw_point_scalarmult(&b.V[i], &inv8, &t->out_pk[i]) != 0) return 103;
        if (mw_bpp_verify(&b) != MW_OK) return 104;
    }

    // sum(pseudo) == sum(outPk) + fee*H
    {
        mw_point_t sp = t->pseudo[0], so = t->out_pk[0], fh, want;
        mw_scalar_t fee;
        for (uint32_t i = 1; i < t->n_in; ++i) mw_point_add(&sp, &sp, &t->pseudo[i]);
        for (uint32_t i = 1; i < t->n_out; ++i) mw_point_add(&so, &so, &t->out_pk[i]);
        fx_amount_scalar(t->fee, &fee);
        mw_scalarmult_H(&fh, &fee);
        mw_point_add(&want, &so, &fh);
        if (!mw_point_eq(&sp, &want)) return 105;
    }
    return 0;
}

#endif
