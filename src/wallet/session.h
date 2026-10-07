// Session state: the only place a decrypted key or a passphrase is allowed to
// live, and only for as long as one operation takes (TZ 5.2, 8.1).
#ifndef MW_SESSION_H
#define MW_SESSION_H

#include "../monero/monero_types.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef struct {
    mw_account_keys_t keys;
    uint32_t          wallet_id;
    bool              unlocked;
    uint32_t          last_activity_ms;
    mw_network_t      network;
} mw_session_t;

mw_session_t* mw_session(void);

mw_err_t mw_session_unlock(uint32_t wallet_id, const char* passphrase);
// Wipes keys and every scratch buffer. Called on autolock, on error and after
// every completed operation.
void     mw_session_lock(void);
void     mw_session_touch(void);
// Returns true when the autolock timeout has expired.
bool     mw_session_expired(void);

// Scratch buffer for the passphrase while it is being typed. Guaranteed to be
// wiped by mw_session_wipe_input().
char*    mw_session_input_buffer(size_t* cap);
void     mw_session_wipe_input(void);

#ifdef __cplusplus
}
#endif
#endif
