// Project-wide, board-independent settings.
#ifndef MW_APP_CONFIG_H
#define MW_APP_CONFIG_H

#define MW_FIRMWARE_VERSION      "0.1.0"
#define MW_FIRMWARE_NAME         "Monero Cold Wallet"

// TZ 7.1
#define MAX_WALLETS              10
#define WALLET_NAME_LEN          32

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

// TZ 8.1: eFuse block holding the NVS encryption HMAC key.
#define MW_HMAC_EFUSE_KEY_ID     0

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
