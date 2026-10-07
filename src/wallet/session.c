// Session state (TZ 5.2, 5.10, 8.1).
//
// This module is the ONLY place in the firmware where decrypted account keys or
// a typed passphrase are allowed to exist, and only for as long as one
// operation takes.  Everything else works from the sealed blobs in NVS.
//
// Memory placement note (ESP32):
//   The passphrase scratch buffer and the key material MUST live in internal
//   SRAM, never in PSRAM.  PSRAM is not covered by flash encryption, its
//   contents survive a warm reset (and, for a short while, a power cycle), and
//   the external bus is physically probeable.  Static/global objects land in
//   internal DRAM by default, but a build that enables
//   CONFIG_SPIRAM_ALLOW_BSS_SEG_EXTERNAL_MEMORY can move .bss out to PSRAM, so
//   the placement is made explicit with DRAM_ATTR below.

#include "session.h"
#include "wallet_store.h"
#include "secure_storage.h"
#include "../config/app_config.h"
#include "../crypto/memzero.h"

#include <string.h>

#ifdef ARDUINO
#  include <esp_attr.h>
#  include "../hal/hal.h"
#  ifndef DRAM_ATTR
#    define DRAM_ATTR __attribute__((section(".dram1")))
#  endif
#  define MW_INTERNAL_RAM DRAM_ATTR
#else
#  define MW_INTERNAL_RAM
#endif

// TZ 5.9: the passphrase has no length limit imposed by a wordlist, so the
// buffer is sized generously.  255 usable bytes + NUL.
#define MW_SESSION_INPUT_CAP 256

static MW_INTERNAL_RAM mw_session_t g_session;
static MW_INTERNAL_RAM char         g_input[MW_SESSION_INPUT_CAP];

// Cached copy of the autolock timeout so mw_session_expired() does not hit NVS
// on every UI tick.  Refreshed on unlock and on first use.
static uint16_t g_autolock_min   = MW_AUTOLOCK_DEFAULT_MIN;
static bool     g_autolock_valid = false;

// ---------------------------------------------------------------------------
// Time source
// ---------------------------------------------------------------------------
#ifdef MW_HOST_BUILD
// Host tests drive the clock explicitly so autolock behaviour is deterministic.
static uint32_t g_host_now_ms = 0;
void mw_session_test_set_time_ms(uint32_t ms);
void mw_session_test_advance_ms(uint32_t ms);
void mw_session_test_set_time_ms(uint32_t ms) { g_host_now_ms = ms; }
void mw_session_test_advance_ms(uint32_t ms)  { g_host_now_ms += ms; }
static uint32_t now_ms(void) { return g_host_now_ms; }
#else
static uint32_t now_ms(void) { return mw_millis(); }
#endif

static void refresh_autolock(void)
{
    mw_settings_t s;
    if (mw_settings_load(&s) == MW_OK) g_autolock_min = s.autolock_min;
    else                               g_autolock_min = MW_AUTOLOCK_DEFAULT_MIN;
    g_autolock_valid = true;
    mw_memzero(&s, sizeof s);
}

// ---------------------------------------------------------------------------
// API
// ---------------------------------------------------------------------------

mw_session_t* mw_session(void)
{
    return &g_session;
}

mw_err_t mw_session_unlock(uint32_t wallet_id, const char* passphrase)
{
    mw_account_keys_t keys;
    mw_settings_t     settings;
    mw_err_t          err;

    memset(&keys, 0, sizeof keys);

    if (!passphrase) { err = MW_ERR_INVALID_ARG; goto done; }

    // Never layer a new unlock on top of an old one.
    mw_session_lock();

    err = mw_wallet_load_keys(wallet_id, passphrase, &keys);
    if (err != MW_OK) goto done;

    g_session.keys             = keys;
    g_session.wallet_id        = wallet_id;
    g_session.unlocked         = true;
    g_session.last_activity_ms = now_ms();

    if (mw_settings_load(&settings) == MW_OK) {
        g_session.network = settings.network;
        g_autolock_min    = settings.autolock_min;
        g_autolock_valid  = true;
        mw_memzero(&settings, sizeof settings);
    } else {
        g_session.network = MW_DEFAULT_NETWORK;
        refresh_autolock();
    }

    err = MW_OK;

done:
    // The local copy of the keys dies here regardless of the outcome; the only
    // surviving copy is the one inside g_session (TZ 8.1).
    mw_memzero(&keys, sizeof keys);
    if (err != MW_OK) mw_session_lock();
    return err;
}

void mw_session_lock(void)
{
    // Wipe the key material first, then the rest of the state, then the typed
    // input (TZ 5.2: "the passphrase buffer is zeroed immediately").
    mw_memzero(&g_session.keys, sizeof g_session.keys);
    g_session.wallet_id        = 0;
    g_session.unlocked         = false;
    g_session.last_activity_ms = 0;
    mw_session_wipe_input();
}

void mw_session_touch(void)
{
    g_session.last_activity_ms = now_ms();
}

bool mw_session_expired(void)
{
    uint32_t timeout_ms, elapsed;

    if (!g_session.unlocked) return true;    // locked is "expired" by definition
    if (!g_autolock_valid) refresh_autolock();

    // 0 minutes means "never auto-lock" (an explicit settings choice, TZ 4.2).
    if (g_autolock_min == 0) return false;

    timeout_ms = (uint32_t)g_autolock_min * 60u * 1000u;
    // Unsigned arithmetic makes the 49-day mw_millis() wraparound a non-event.
    elapsed = now_ms() - g_session.last_activity_ms;
    return elapsed >= timeout_ms;
}

char* mw_session_input_buffer(size_t* cap)
{
    if (cap) *cap = sizeof g_input;
    return g_input;
}

void mw_session_wipe_input(void)
{
    mw_memzero(g_input, sizeof g_input);
}
