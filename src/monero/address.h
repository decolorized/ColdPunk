// Base58 (Monero flavour: 8-byte blocks -> 11 chars) and address encoding.
#ifndef MW_ADDRESS_H
#define MW_ADDRESS_H

#include "monero_types.h"

#ifdef __cplusplus
extern "C" {
#endif

// Monero base58: full 8-byte blocks -> 11 chars, remainder per lookup table.
size_t   mw_base58_encode(const uint8_t* data, size_t len, char* out, size_t out_len);
mw_err_t mw_base58_decode(const char* str, uint8_t* out, size_t out_len, size_t* out_written);
// With the 4-byte keccak checksum Monero appends to addresses.
size_t   mw_base58_encode_check(const uint8_t* data, size_t len, char* out, size_t out_len);
mw_err_t mw_base58_decode_check(const char* str, uint8_t* out, size_t out_len, size_t* out_written);

uint64_t mw_address_prefix(mw_network_t net, mw_address_type_t type);

mw_err_t mw_address_encode(const mw_address_t* addr, char* out, size_t out_len);
mw_err_t mw_address_decode(const char* str, mw_address_t* out);

// Builds the primary address (major=0, minor=0) for an account.
mw_err_t mw_address_from_keys(const mw_account_keys_t* keys, mw_network_t net,
                              mw_address_t* out);

// Shortened form for the confirmation screen: "48aBc...xyz89" (TZ 12.3 still
// requires the full address to be scrollable somewhere on screen).
void mw_address_shorten(const char* full, char* out, size_t out_len, int head, int tail);

#ifdef __cplusplus
}
#endif
#endif
