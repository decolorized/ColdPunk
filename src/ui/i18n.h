// Two-language string table (RU/EN). LVGL needs a font with Cyrillic coverage
// (TZ 4.1); see ui/fonts/.
#ifndef MW_I18N_H
#define MW_I18N_H

#ifdef __cplusplus
extern "C" {
#endif

typedef enum { MW_LANG_RU = 0, MW_LANG_EN = 1 } mw_lang_t;

// ---------------------------------------------------------------------------
// Cyrillic font availability (TZ 4.1)
//
// The LVGL built-in Montserrat faces only cover Latin-1, so every Russian
// string renders as a row of boxes unless a Cyrillic face has been generated
// and compiled in (docs/ui_screens.md has the lv_font_conv command lines; drop
// the generated mw_font_ru_*.c into the sketch folder and build with
// -DMW_UI_HAS_CYRILLIC_FONT=1).
//
// The default language MUST follow the font, not the other way round: a stock
// build with no Cyrillic face would otherwise show the passphrase warning, the
// wallet-delete confirmation and the factory-reset confirmation as boxes, and
// a user cannot consent to an irreversible, key-destroying action they cannot
// read. theme.h picks up the same macro for the font tables.
// ---------------------------------------------------------------------------
#ifndef MW_UI_HAS_CYRILLIC_FONT
#define MW_UI_HAS_CYRILLIC_FONT 0
#endif

#if MW_UI_HAS_CYRILLIC_FONT
#define MW_UI_DEFAULT_LANG MW_LANG_RU
#else
#define MW_UI_DEFAULT_LANG MW_LANG_EN
#endif

typedef enum {
    STR_MAIN_SIGN_TX = 0, STR_MAIN_SYNC_KI, STR_MAIN_WALLETS, STR_MAIN_SETTINGS,
    STR_WALLET_LIST, STR_WALLET_CREATE, STR_WALLET_IMPORT, STR_WALLET_DELETE,
    STR_CONFIRM, STR_CANCEL, STR_BACK, STR_CLEAR, STR_NEXT, STR_DONE,
    STR_SEED_TYPE, STR_SEED_LEGACY25, STR_SEED_POLYSEED16,
    STR_ENTROPY_TRNG, STR_ENTROPY_DICE, STR_DICE_PROMPT,
    STR_PASSPHRASE, STR_PASSPHRASE_REPEAT, STR_PASSPHRASE_NONE,
    STR_PASSPHRASE_NONE_CONFIRM, STR_PASSPHRASE_MISMATCH,
    STR_WORD_OF, STR_PREFIX, STR_CHECKSUM_FAIL, STR_RESTORE_HEIGHT,
    STR_TX_AMOUNT, STR_TX_FEE, STR_TX_TO, STR_TX_INPUTS, STR_TX_OUTPUTS,
    STR_TX_SIGN, STR_SIGNING, STR_KI_SYNC, STR_KI_RECORDS, STR_SAVE,
    STR_SETTINGS_USB, STR_SETTINGS_KEYBOARD, STR_SETTINGS_BRIGHTNESS,
    STR_SETTINGS_AUTOLOCK, STR_SETTINGS_CALIBRATE, STR_SETTINGS_FORMAT_SD,
    STR_SETTINGS_RESET, STR_RESET_CONFIRM,
    STR_ERR_GENERIC, STR_NO_SD, STR_NO_FILE, STR_SUCCESS, STR_VERIFY_SEED,
    STR_COUNT
} mw_str_id_t;

void        mw_i18n_set(mw_lang_t lang);
mw_lang_t   mw_i18n_get(void);
const char* mw_str(mw_str_id_t id);
#define T(id) mw_str(id)

#ifdef __cplusplus
}
#endif
#endif
