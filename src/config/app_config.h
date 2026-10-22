// Project-wide, board-independent settings.
#ifndef MW_APP_CONFIG_H
#define MW_APP_CONFIG_H

#define MW_FIRMWARE_VERSION      "0.3.5"
#define MW_FIRMWARE_NAME         "Monero Cold Wallet"

// TZ 7.1. Per user (multi-user, v9): every user has a directory of its own.
#define MAX_WALLETS              64
// Accounts with their own password (Settings > Add account). Each account
// only sees its own wallets; nothing shows how many exist (security.md §4a).
// The device holds MW_USERS_SLOTS slots; how many accounts it takes is
// MW_USERS_MIN..MW_USERS_SLOTS, fixed per chip by its eFuse key.
#define MW_USERS_MIN             16
#define MW_USERS_SLOTS           24
#define MW_USERS_MAX             MW_USERS_SLOTS
#define WALLET_NAME_LEN          32

// Typed into the password field, this erases the device (after one more
// confirmation). It can never be a password.
#ifndef MW_RESET_PHRASE
#define MW_RESET_PHRASE          "Reset My Device 1029384756"
#endif

// Wrong passwords (all accounts share one counter, security.md §4a):
//   up to MW_PW_FREE_TRIES        no delay
//   then                          1 min, doubling, at most MW_PW_MAX_DELAY_MS
//                                 (MW_PW_DELAY_AFTER_LOGIN_MS once any account
//                                 has logged in since the counter was cleared)
//   from MW_PW_CHILD_AT           a random PIN shown on screen must be typed
//                                 before each password
//   at MW_PW_WIPE_AT              everything is erased
// Any correct password clears the counter.
#ifndef MW_PW_WIPE_AT
#define MW_PW_WIPE_AT            50
#endif
#ifndef MW_PW_CHILD_AT
#define MW_PW_CHILD_AT           (MW_PW_WIPE_AT - 5)
#endif
#define MW_PW_FREE_TRIES         10
#define MW_PW_FIRST_DELAY_MS     (60u * 1000u)
#define MW_PW_MAX_DELAY_MS       (8u * 60u * 60u * 1000u)
#define MW_PW_DELAY_AFTER_LOGIN_MS (10u * 60u * 1000u)

// TZ 5.10: input buffers are wiped after this long without a keypress.
#define MW_INPUT_TIMEOUT_MS      (5 * 60 * 1000)
// TZ 4.2 settings screen: auto-lock timeout options (minutes).
#define MW_AUTOLOCK_DEFAULT_MIN  5

// TZ 11.3
#define MW_MAX_KEYIMAGE_RECORDS  1000

// TZ 6.4: dice entropy. log2(6) = 2.585 bits per d6 throw, so 100 throws give
// ~258 bits - comfortably above the 256 bits a Monero seed needs.
#define MW_DICE_ROLLS_REQUIRED   100
#define MW_DICE_BITS_PER_ROLL_Q8 662     // 2.585 bits in Q8 fixed point
#define MW_DICE_PBKDF2_ROUNDS    2048    // PBKDF2-HMAC-SHA512 over the throws

// TZ 4.1: FreeRTOS task layout. Crypto runs on core 1, LVGL on core 0.
#define MW_UI_TASK_STACK         8192
#define MW_UI_TASK_PRIO          7
#define MW_UI_TASK_CORE          0
#define MW_CRYPTO_TASK_STACK     32768
#define MW_CRYPTO_TASK_PRIO      3
#define MW_CRYPTO_TASK_CORE      1

// TZ 4.1: minimum frame rate / input latency targets used by the self-test.
#define MW_TARGET_FPS            20
#define MW_MAX_INPUT_LATENCY_MS  100

// TZ 8.1: the eFuse key block of the wallet key is chosen at provisioning
// (the highest free one, BLOCK_KEY5 down) - see secure_storage.cpp.

// ---------------------------------------------------------------------------
// Exchange interfaces with the PC, chosen at compile time. 1 = built in,
// 0 = left out entirely (no code, nothing listens). Change them here or pass
// -DMW_USE_SERIAL=0 etc. as a build flag. At least one must stay on.
//
//   MW_USE_SERIAL  mwlink over a USB CDC port: with TinyUSB and "USB CDC On
//                  Boot: Disabled" (the profiles) the link's own port,
//                  started after the password (0.3.5); with CDC On Boot the
//                  core's `Serial`; without TinyUSB UART0. For tools/mwlink
//                  --serial.
//   MW_USE_HID     mwlink over USB HID (needs "USB Mode: USB-OTG").
//                  Used by MoneroPunkSigner.
//   MW_USE_SD      microSD file exchange, on boards whose header has
//                  HAS_SD 1 (ES3C28P, Touch-LCD-2). 0 also gives the
//                  display its own SPI bus back on shared-bus boards.
//
// With MW_USE_SERIAL 0 (the default) and "USB CDC On Boot: Disabled" no COM
// port appears at all; UART0 carries the text log.
// ---------------------------------------------------------------------------
#ifndef MW_USE_SERIAL
#define MW_USE_SERIAL 0
#endif
#ifndef MW_USE_HID
#define MW_USE_HID    1
#endif
#ifndef MW_USE_SD
#define MW_USE_SD     1
#endif

// TZ 8.4: no networking is ever compiled in.
#if defined(MW_ENABLE_WIFI) || defined(MW_ENABLE_BT)
#error "Air-gapped build: Wi-Fi/BT must not be enabled"
#endif

// Default network. Switch to MW_NET_STAGENET for the TZ 13.6 test campaign.
#ifndef MW_DEFAULT_NETWORK
#define MW_DEFAULT_NETWORK MW_NET_MAINNET
#endif

// Seed input mode selector (referenced by board_config.h).
#define SEED_INPUT_AUTO      0
#define SEED_INPUT_FULL_KB   1
#define SEED_INPUT_SCROLL_KB 2

#endif
