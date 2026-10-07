// Transaction model for signing (TZ 12). Sized for ESP32-S3: the limits below
// are the hard caps enforced by the parser so a malformed file can never blow
// the heap. The structure is large (tens of KiB): the firmware keeps it in
// PSRAM, the tests in static storage.
#ifndef MW_TX_H
#define MW_TX_H

#include "monero_types.h"
#include "key_image.h"

#ifdef __cplusplus
extern "C" {
#endif

#define MW_MAX_INPUTS      32
#define MW_MAX_OUTPUTS     16      // consensus limit for BP+ transactions
#define MW_RING_SIZE       16      // CLSAG ring size (consensus: 16 since v15)
#define MW_MAX_RING_SIZE   32
#define MW_MAX_TX_EXTRA    1060    // MAX_TX_EXTRA_SIZE
#define MW_MAX_DESTINATIONS 16
// subaddr_indices hints kept per transaction (the inputs' minor indices).
#define MW_MAX_SUBADDR_HINTS 16
// Own subaddress indices the device already knows (key image cache), offered
// to the destination check as extra own-address candidates.
#define MW_MAX_OWN_HINTS   24
// Own-subaddress search for a destination tied to our view key (C == a*D):
// extra minors past the highest known one, extra accounts, total budget.
#define MW_OWN_LOOKAHEAD_MINOR  200
#define MW_OWN_LOOKAHEAD_MAJOR  50
#define MW_OWN_SEARCH_MAX       600
// Fee warning thresholds (atomic units): above 0.01 XMR or above 10% of
// what the transaction moves.
#define MW_TX_HIGH_FEE_ABS      10000000000ull

typedef struct {
    mw_pubkey_t dest;    // one-time public key P of the ring member
    mw_point_t  mask;    // commitment C of the ring member
} mw_ctkey_t;

typedef struct {
    uint64_t      amount;
    mw_keyimage_t key_image;
    uint64_t      key_offsets[MW_MAX_RING_SIZE];  // relative offsets on the wire
    uint8_t       ring_size;
    // Data supplied by the unsigned tx set:
    mw_ctkey_t    ring[MW_MAX_RING_SIZE];
    uint8_t       real_output_index;              // our index inside the ring
    mw_pubkey_t   real_out_tx_key;
    // real_out_additional_tx_keys[real_output_in_tx_index], when present:
    // outputs received on a subaddress are derived from it.
    mw_pubkey_t   real_out_additional_key;
    bool          has_additional_key;
    uint32_t      real_output_in_tx_index;
    mw_scalar_t   mask;                           // blinding of our real output
    bool          rct;
    // Subaddress of the real output. May be pre-set by the caller (e.g. from
    // the key image cache, subaddr_known = true); otherwise the signer finds
    // it among the wallet2 hints and fills it in.
    bool          subaddr_known;
    uint32_t      subaddr_major, subaddr_minor;
} mw_tx_source_t;

typedef struct {
    uint64_t     amount;
    mw_address_t addr;
    bool         is_subaddress;
    bool         is_integrated;
    // Set by mw_tx_check_destinations(), never taken from the file:
    // kind (mw_dest_kind_t), the own subaddress index for OWN and CHANGE, and
    // is_change == (kind == MW_DEST_CHANGE).
    bool         is_change;
    uint8_t      kind;
    uint32_t     own_major, own_minor;
} mw_tx_destination_t;

typedef enum {
    MW_DEST_FOREIGN = 0,   // someone else's address
    MW_DEST_OWN,           // an address of this wallet (re-derived)
    MW_DEST_CHANGE,        // the verified change, (subaddr_account, 0)
    MW_DEST_DUMMY          // wallet2's 0-amount dummy change (sweeps)
} mw_dest_kind_t;

// Why mw_tx_check_destinations() refused a transaction.
typedef enum {
    MW_TXR_NONE = 0,
    MW_TXR_BAD_POINT,          // a destination key is not a valid public key
    MW_TXR_INPUTS,             // an input was not matched to a subaddress
    MW_TXR_ACCOUNT,            // an input is outside subaddr_account
    MW_TXR_HYBRID_OUR_VIEW,    // our view key with a foreign spend key
    MW_TXR_HYBRID_OUR_SPEND,   // our spend key with a foreign view key
    MW_TXR_HYBRID_VIEW_LINKED, // view == a*spend but not a known subaddress
    MW_TXR_OWN_FLAG,           // own address with the wrong subaddress flag
    MW_TXR_CHANGE_NOT_OURS,    // change address is not ours
    MW_TXR_CHANGE_INDEX,       // change to an own address other than (acct, 0)
    MW_TXR_CHANGE_FLAG,        // change_dts subaddress flag inconsistent
    MW_TXR_CHANGE_UNPAID       // claimed change exceeds what the change gets
} mw_tx_refusal_t;

typedef struct {
    uint8_t  reason;           // mw_tx_refusal_t
    uint8_t  dest;             // destination (or input) index of the refusal
    uint32_t major, minor;     // index involved (own address, account)
    uint64_t claimed, paid;    // CHANGE_UNPAID amounts
    uint16_t searched;         // candidates tried by the own-subaddress search
} mw_tx_check_info_t;

typedef struct {
    mw_pubkey_t out_pubkey;     // one-time P
    uint64_t    amount;         // cleartext amount (0 on the wire for RCT)
    mw_point_t  commitment;     // outPk mask
    mw_scalar_t mask;           // secret blinding
    uint8_t     ecdh_amount[8];
    uint8_t     view_tag;
    bool        has_view_tag;
} mw_tx_output_t;

typedef struct {
    uint8_t             version;
    uint64_t            unlock_time;
    uint8_t             n_inputs;
    uint8_t             n_outputs;
    mw_tx_source_t      sources[MW_MAX_INPUTS];
    // splitted_dsts: what the transaction pays, change included
    mw_tx_destination_t destinations[MW_MAX_DESTINATIONS];
    uint8_t             n_destinations;
    mw_tx_output_t      outputs[MW_MAX_OUTPUTS];
    // output i pays destinations[out_dest[i]] - construct_tx shuffles them
    uint8_t             out_dest[MW_MAX_OUTPUTS];
    uint8_t             tx_extra[MW_MAX_TX_EXTRA];   // built by the signer
    uint16_t            tx_extra_len;
    // extra as the online wallet supplied it (plain payment id nonce)
    uint8_t             extra_in[MW_MAX_TX_EXTRA];
    uint16_t            extra_in_len;
    uint64_t            fee;
    mw_seckey_t         tx_secret_key;     // r
    mw_pubkey_t         tx_public_key;     // R
    uint8_t             rct_type;          // 6 = BulletproofPlus
    bool                use_view_tags;

    // change_dts of the construction data
    mw_address_t        change_addr;       // spend + view keys only
    bool                has_change_addr;
    bool                change_is_subaddress;
    uint64_t            change_amount;
    // Set by mw_tx_check_destinations(): change_addr equals change_derived,
    // the device's own (subaddr_account, 0) re-derived from the keys.
    bool                change_verified;
    uint32_t            change_major, change_minor;
    mw_address_t        change_derived;

    // Own subaddresses known to the device (key image cache), filled by the
    // caller after loading the tx. Candidates only: hints from the FILE
    // (subaddr_hints) never make an address own.
    uint32_t            own_hint_major[MW_MAX_OWN_HINTS];
    uint32_t            own_hint_minor[MW_MAX_OWN_HINTS];
    uint8_t             n_own_hints;
    uint32_t            own_max_major;       // highest known account
    uint32_t            own_max_minor_acct;  // highest known minor in subaddr_account
    uint32_t            own_max_minor_main;  // highest known minor in account 0
    // Result of the last mw_tx_check_destinations() (refusal details).
    mw_tx_check_info_t  check;

    // wallet2 hints for matching the inputs to a subaddress
    uint32_t            subaddr_account;
    uint32_t            subaddr_hints[MW_MAX_SUBADDR_HINTS];
    uint8_t             n_subaddr_hints;

    // Key images of the outputs that come back to this wallet (change), for
    // signed_tx_set.tx_key_images. Filled by the signer.
    mw_keyimage_t       out_ki[MW_MAX_OUTPUTS];
    bool                out_ki_valid[MW_MAX_OUTPUTS];

    // Tests only: keep the destination order instead of shuffling.
    bool                no_shuffle;
} mw_transaction_t;

// Aggregated view for the confirmation screen (TZ 4.2 / 12.3).
typedef struct {
    uint64_t total_out;              // sum sent to recipients (own ones included)
    uint64_t change;                 // the verified change amount
    uint64_t fee;
    uint64_t total_in;
    uint8_t  n_inputs;
    uint8_t  n_outputs;
    uint8_t  n_recipients;
    uint8_t  n_dummy;                // wallet2 0-amount dummy outputs
    bool     high_fee;               // fee above MW_TX_HIGH_FEE_ABS or 10%
    // Change: encoded from the device-derived keys, never from the file.
    bool     has_change;
    uint32_t change_major, change_minor;
    char     change_addr[MW_ADDRESS_STR_MAX];
    char     recipients[MW_MAX_DESTINATIONS][MW_ADDRESS_STR_MAX];
    uint64_t amounts[MW_MAX_DESTINATIONS];
    bool     recipient_own[MW_MAX_DESTINATIONS];
    uint32_t recipient_major[MW_MAX_DESTINATIONS];
    uint32_t recipient_minor[MW_MAX_DESTINATIONS];
} mw_tx_summary_t;

// Scans tx_extra for the 8-byte short payment id carried by a nonce field.
bool mw_tx_extra_find_payment_id(const uint8_t* extra, size_t len,
                                 uint8_t out[8]);

// Destination and change check (task 3, change address substitution
// protection). Precondition: every input is matched to its subaddress
// (sources[i].subaddr_known, e.g. by mw_sign_input_key_image).
//   * every destination key and change_dts must be valid public keys;
//   * every input must be in subaddr_account (wallet2 never mixes accounts);
//   * each destination is classified: OWN when spend AND view equal an
//     address re-derived from the keys - (0,0), (acct,0), the inputs'
//     subaddresses, own_hint_* and, for a view tied to our view key, a bounded
//     search; half-ours addresses (our view or our spend key with a foreign
//     other half, or a*D views of unknown subaddresses) are refused, as is an
//     own address with the wrong subaddress flag;
//   * change (wallet2 rules): only to (subaddr_account, 0) with the matching
//     flag, and the claimed change amount must not exceed what that address
//     is paid. A 0-amount change_dts that nothing pays marks the 0-amount
//     destinations at that address as DUMMY.
// MW_ERR_KEY_MISMATCH for every refusal (details in *info and tx->check),
// MW_ERR_SUBGROUP for a bad point.
mw_err_t mw_tx_check_destinations(const mw_account_keys_t* keys, mw_transaction_t* tx,
                                  mw_tx_check_info_t* info);

// Verifies sum(inputs) == sum(outputs) + fee (TZ 8.3 / 12.3).
mw_err_t mw_tx_check_balance(const mw_transaction_t* tx);
// Needs a tx that passed mw_tx_check_destinations(): a CHANGE destination
// that is not the verified change_derived is refused (MW_ERR_INVALID_ARG).
mw_err_t mw_tx_summarize(const mw_transaction_t* tx, mw_network_t net,
                         mw_tx_summary_t* out);

// Builds the transaction prefix and returns its keccak hash.
mw_err_t mw_tx_prefix_hash(const mw_transaction_t* tx, uint8_t out[32]);

// Full RCT message hash: keccak(prefix_hash || rct_base_hash || bp_hash).
mw_err_t mw_tx_rct_message(const mw_transaction_t* tx,
                           const uint8_t* bp_serialized, size_t bp_len,
                           uint8_t out[32]);

// tx_extra construction in sort_tx_extra() order: tx public key (0x01),
// additional public keys (0x04), then the nonce (0x02) when one is given.
mw_err_t mw_tx_extra_build(mw_transaction_t* tx,
                           const mw_pubkey_t* additional, uint8_t n_additional,
                           const uint8_t* nonce, size_t nonce_len);

#ifdef __cplusplus
}
#endif
#endif
