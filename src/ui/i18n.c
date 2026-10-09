/* --------------------------------------------------------------------------
 *  RU/EN string table (TZ 4.1: "Кириллица и латиница").
 *
 *  Two tables are kept here:
 *    * mw_str()  - the frozen mw_str_id_t contract of i18n.h;
 *    * mw_strx() - the extended table declared in screen_common.h, because the
 *                  frozen enum cannot grow but the screens need more strings.
 *
 *  Both are plain const arrays of pointers to string literals, so they stay in
 *  flash (.rodata) and cost nothing but the pointer table in RAM-less builds.
 *  Entries that carry printf conversions are used with
 *  lv_label_set_text_fmt(); the RU and EN forms MUST keep the same conversions
 *  in the same order.
 *
 *  Every user-visible character is either ASCII (0x20..0x7E), Cyrillic
 *  (0x410..0x44F plus Ё 0x401 / ё 0x451) or an LVGL symbol glyph added by the
 *  screens themselves - see docs/ui_screens.md for the font converter ranges.
 * -------------------------------------------------------------------------- */
#include "i18n.h"

#define MW_UI_STRINGS_ONLY 1
#include "screen_common.h"

/* The default follows the compiled-in font coverage (see i18n.h): without a
 * Cyrillic face the Russian table would render as boxes, so a stock build
 * starts in English. The user can still switch in Settings.                */
static mw_lang_t s_lang = MW_UI_DEFAULT_LANG;

/* ------------------------------------------------------------------ */
/* Frozen table (i18n.h)                                              */
/* ------------------------------------------------------------------ */
static const char* const S_RU[STR_COUNT] = {
    [STR_MAIN_SIGN_TX]            = "Подписать транзакцию",
    [STR_MAIN_SYNC_KI]            = "Синхронизировать key images",
    [STR_MAIN_WALLETS]            = "Кошельки",
    [STR_MAIN_SETTINGS]           = "Настройки",

    [STR_WALLET_LIST]             = "Список кошельков",
    [STR_WALLET_CREATE]           = "Создать кошелёк",
    [STR_WALLET_IMPORT]           = "Импортировать кошелёк",
    [STR_WALLET_DELETE]           = "Удалить кошелёк",

    [STR_CONFIRM]                 = "Подтвердить",
    [STR_CANCEL]                  = "Отмена",
    [STR_BACK]                    = "Назад",
    [STR_CLEAR]                   = "Очистить",
    [STR_NEXT]                    = "Далее",
    [STR_DONE]                    = "Готово",

    [STR_SEED_TYPE]               = "Формат seed-фразы",
    [STR_SEED_LEGACY25]           = "Monero legacy, 25 слов",
    [STR_SEED_POLYSEED16]         = "Polyseed, 16 слов",

    [STR_ENTROPY_TRNG]            = "Аппаратный ГСЧ (TRNG)",
    [STR_ENTROPY_DICE]            = "Кубики (d6)",
    [STR_DICE_PROMPT]             = "Бросьте кубик и нажмите выпавшее число",

    [STR_PASSPHRASE]              = "Passphrase",
    [STR_PASSPHRASE_REPEAT]       = "Повторите passphrase",
    [STR_PASSPHRASE_NONE]         = "Без passphrase",
    [STR_PASSPHRASE_NONE_CONFIRM] = "Продолжить без passphrase?\n"
                                    "Кошелёк можно будет восстановить\n"
                                    "только с пустым passphrase.",
    [STR_PASSPHRASE_MISMATCH]     = "Passphrase не совпадают.\nПовторите ввод.",

    [STR_WORD_OF]                 = "Слово %d из %d",
    [STR_PREFIX]                  = "Префикс",
    [STR_CHECKSUM_FAIL]           = "Неверная контрольная сумма seed-фразы",
    [STR_RESTORE_HEIGHT]          = "Restore height",

    [STR_TX_AMOUNT]               = "Сумма",
    [STR_TX_FEE]                  = "Комиссия",
    [STR_TX_TO]                   = "Получатель",
    [STR_TX_INPUTS]               = "Входов",
    [STR_TX_OUTPUTS]              = "Выходов",
    [STR_TX_SIGN]                 = "Подписать",
    [STR_SIGNING]                 = "Подпись транзакции...",

    [STR_KI_SYNC]                 = "Синхронизация key images",
    [STR_KI_RECORDS]              = "Записей",
    [STR_SAVE]                    = "Сохранить",

    [STR_SETTINGS_USB]            = "Режим USB",
    [STR_SETTINGS_KEYBOARD]       = "Тип клавиатуры",
    [STR_SETTINGS_BRIGHTNESS]     = "Яркость",
    [STR_SETTINGS_AUTOLOCK]       = "Автоблокировка",
    [STR_SETTINGS_CALIBRATE]      = "Калибровка сенсора",
    [STR_SETTINGS_FORMAT_SD]      = "Форматировать SD",
    [STR_SETTINGS_RESET]          = "Сброс устройства",
    [STR_RESET_CONFIRM]           = "Стереть все кошельки и настройки?\n"
                                    "Действие необратимо.",

    [STR_ERR_GENERIC]             = "Ошибка",
    [STR_NO_SD]                   = "SD-карта не найдена",
    [STR_NO_FILE]                 = "Файл не найден",
    [STR_SUCCESS]                 = "Готово",
    [STR_VERIFY_SEED]             = "Проверка seed-фразы",
};

static const char* const S_EN[STR_COUNT] = {
    [STR_MAIN_SIGN_TX]            = "Sign transaction",
    [STR_MAIN_SYNC_KI]            = "Sync key images",
    [STR_MAIN_WALLETS]            = "Wallets",
    [STR_MAIN_SETTINGS]           = "Settings",

    [STR_WALLET_LIST]             = "Wallet list",
    [STR_WALLET_CREATE]           = "Create wallet",
    [STR_WALLET_IMPORT]           = "Import wallet",
    [STR_WALLET_DELETE]           = "Delete wallet",

    [STR_CONFIRM]                 = "Confirm",
    [STR_CANCEL]                  = "Cancel",
    [STR_BACK]                    = "Back",
    [STR_CLEAR]                   = "Clear",
    [STR_NEXT]                    = "Next",
    [STR_DONE]                    = "Done",

    [STR_SEED_TYPE]               = "Seed format",
    [STR_SEED_LEGACY25]           = "Monero legacy, 25 words",
    [STR_SEED_POLYSEED16]         = "Polyseed, 16 words",

    [STR_ENTROPY_TRNG]            = "Hardware RNG (TRNG)",
    [STR_ENTROPY_DICE]            = "Dice (d6)",
    [STR_DICE_PROMPT]             = "Roll the die and tap the result",

    [STR_PASSPHRASE]              = "Passphrase",
    [STR_PASSPHRASE_REPEAT]       = "Repeat passphrase",
    [STR_PASSPHRASE_NONE]         = "No passphrase",
    [STR_PASSPHRASE_NONE_CONFIRM] = "Continue without a passphrase?\n"
                                    "The wallet will only be recoverable\n"
                                    "with an empty passphrase.",
    [STR_PASSPHRASE_MISMATCH]     = "Passphrases do not match.\nTry again.",

    [STR_WORD_OF]                 = "Word %d of %d",
    [STR_PREFIX]                  = "Prefix",
    [STR_CHECKSUM_FAIL]           = "Seed phrase checksum failed",
    [STR_RESTORE_HEIGHT]          = "Restore height",

    [STR_TX_AMOUNT]               = "Amount",
    [STR_TX_FEE]                  = "Fee",
    [STR_TX_TO]                   = "To",
    [STR_TX_INPUTS]               = "Inputs",
    [STR_TX_OUTPUTS]              = "Outputs",
    [STR_TX_SIGN]                 = "Sign",
    [STR_SIGNING]                 = "Signing transaction...",

    [STR_KI_SYNC]                 = "Key image sync",
    [STR_KI_RECORDS]              = "Records",
    [STR_SAVE]                    = "Save",

    [STR_SETTINGS_USB]            = "USB mode",
    [STR_SETTINGS_KEYBOARD]       = "Keyboard type",
    [STR_SETTINGS_BRIGHTNESS]     = "Brightness",
    [STR_SETTINGS_AUTOLOCK]       = "Auto-lock",
    [STR_SETTINGS_CALIBRATE]      = "Touch calibration",
    [STR_SETTINGS_FORMAT_SD]      = "Format SD",
    [STR_SETTINGS_RESET]          = "Device reset",
    [STR_RESET_CONFIRM]           = "Erase every wallet and setting?\n"
                                    "This cannot be undone.",

    [STR_ERR_GENERIC]             = "Error",
    [STR_NO_SD]                   = "No SD card",
    [STR_NO_FILE]                 = "File not found",
    [STR_SUCCESS]                 = "Success",
    [STR_VERIFY_SEED]             = "Verify seed phrase",
};

/* ------------------------------------------------------------------ */
/* Extended table (screen_common.h)                                   */
/* ------------------------------------------------------------------ */
static const char* const X_RU[XSTR_COUNT] = {
    [XSTR_APP_NAME]          = "Monero Cold Wallet",
    [XSTR_VERSION]           = "Версия",
    [XSTR_BOOT]              = "Загрузка...",
    [XSTR_LOCKED]            = "Устройство заблокировано",
    [XSTR_YES]               = "Да",
    [XSTR_NO]                = "Нет",
    [XSTR_OK]                = "ОК",
    [XSTR_CLOSE]             = "Закрыть",
    [XSTR_MENU]              = "Меню",
    [XSTR_PROCESSING]        = "Обработка...",
    [XSTR_ABORTED]           = "Операция отменена",
    [XSTR_UNSUPPORTED]       = "Не поддерживается на этой плате",

    [XSTR_WALLET_ACTIVE]     = "Активный кошелёк",
    [XSTR_WALLET_NONE]       = "Кошелёк не выбран",
    [XSTR_WALLET_EMPTY]      = "Кошельков пока нет",
    [XSTR_WALLET_NAME]       = "Имя кошелька",
    [XSTR_WALLET_DELETE_Q]   = "Удалить кошелёк\n\"%s\"?\nSeed будет стёрт безвозвратно.",
    [XSTR_WALLET_DELETED]    = "Кошелёк удалён",
    [XSTR_WALLET_CREATED]    = "Кошелёк создан",
    [XSTR_WALLET_FULL]       = "Достигнут предел в 10 кошельков",
    [XSTR_WALLET_UNLOCK]     = "Разблокировка кошелька",
    [XSTR_WALLET_SELECTED]   = "Кошелёк выбран",

    [XSTR_CREATE_TITLE]      = "Новый кошелёк",
    [XSTR_IMPORT_TITLE]      = "Импорт кошелька",
    [XSTR_SEED_SOURCE_TITLE] = "Источник энтропии",
    [XSTR_ENTROPY_SOURCE]    = "Выберите источник энтропии",
    [XSTR_DICE_ROLLS]        = "Бросков: %d из %d",
    [XSTR_DICE_UNDO]         = "Отменить бросок",
    [XSTR_DICE_BITS]         = "~%d бит энтропии",
    [XSTR_DICE_NEED_MORE]    = "Нужно не менее %d бросков",

    [XSTR_SEED_WRITE_DOWN]   = "Запишите seed-фразу на бумаге.\n"
                               "Никогда не фотографируйте её.",
    [XSTR_SEED_WRITTEN_Q]    = "Seed-фраза записана?\n"
                               "Дальше устройство попросит\nввести несколько слов.",
    [XSTR_SEED_PAGE]         = "Слова %d-%d из %d",
    [XSTR_VERIFY_PROMPT]     = "Введите слово %d",
    [XSTR_VERIFY_FAIL]       = "Слово не совпадает.\nПроверьте запись.",
    [XSTR_VERIFY_OK]         = "Seed-фраза подтверждена",
    [XSTR_SEED_WORD_BAD]     = "Слово %d отсутствует в словаре",

    [XSTR_PASSPHRASE_ENTER]  = "Ввести passphrase",
    [XSTR_PASSPHRASE_HINT]   = "Passphrase запрашивается всегда.\n"
                               "Он не сохраняется на устройстве.",
    [XSTR_PASSPHRASE_EMPTY_Q]= "Вы уверены, что хотите\nпустой passphrase?",
    [XSTR_PASSPHRASE_OK]     = "Passphrase принят",

    [XSTR_ADDRESS]           = "Адрес",
    [XSTR_SHOW_QR]           = "Показать QR",
    [XSTR_RESTORE_HEIGHT_HINT] = "Введите высоту блока (0 - с начала)",

    [XSTR_CHANNEL]           = "Канал обмена",
    [XSTR_CHANNEL_SD]        = "SD-карта",
    [XSTR_CHANNEL_QR]        = "QR-код",
    [XSTR_WAITING_FILE]      = "Ожидание файла...",

    [XSTR_TX_CHANGE]         = "Сдача",
    [XSTR_TX_TOTAL]          = "Всего к отправке",
    [XSTR_TX_FULL_ADDR]      = "Полный адрес",
    [XSTR_TX_UNLOCK_TIME]    = "Блокировка до",
    [XSTR_TX_SIGNED]         = "Транзакция подписана",
    [XSTR_TX_BALANCE_FAIL]   = "Баланс не сходится:\nвходы != выходы + комиссия",
    [XSTR_TX_RECIPIENT]      = "Получатель %d из %d",

    [XSTR_KI_PROCESSED]      = "Обработано: %d из %d",
    [XSTR_KI_ERRORS]         = "Ошибок: %d",

    [XSTR_QR_PART]           = "Часть %d из %d",
    [XSTR_QR_PAUSE]          = "Пауза",
    [XSTR_QR_RESUME]         = "Продолжить",
    [XSTR_SCAN_TITLE]        = "Сканирование QR",
    [XSTR_SCAN_HINT]         = "Наведите камеру на QR-код",
    [XSTR_NO_CAMERA]         = "Камера не подключена",
    [XSTR_NO_QRCODE]         = "Модуль QR не собран в прошивке",

    [XSTR_KB_FULL]           = "Полная",
    [XSTR_KB_SCROLL]         = "Прокручиваемая",
    [XSTR_LETTERS]           = "абв",
    [XSTR_SHIFT]             = "Регистр",
    [XSTR_DIGITS]            = "123",
    [XSTR_SYMBOLS]           = "#+=",
    [XSTR_SPACE]             = "Пробел",

    [XSTR_SETTINGS_LANG]     = "Язык",
    [XSTR_SETTINGS_NETWORK]  = "Сеть",
    [XSTR_SETTINGS_ABOUT]    = "Об устройстве",
    [XSTR_SETTINGS_SAVED]    = "Настройки сохранены",
    [XSTR_FORMAT_SD_Q]       = "Отформатировать SD-карту?\nВсе файлы будут стёрты.",
    [XSTR_CALIB_PROMPT]      = "Нажмите на метку в углу экрана",
    [XSTR_CALIB_DONE]        = "Калибровка завершена",
    [XSTR_MINUTES]           = "%d мин",
    [XSTR_NET_MAIN]          = "Mainnet",
    [XSTR_NET_TEST]          = "Testnet",
    [XSTR_NET_STAGE]         = "Stagenet",
    [XSTR_LANG_RU]           = "Русский",
    [XSTR_LANG_EN]           = "English",
    [XSTR_EFUSE_MISSING]     = "HMAC-ключ eFuse не запрограммирован.\n"
                               "Seed не защищён аппаратно.",

    [XSTR_EFUSE_PROVISION]   = "Запрограммировать ключ eFuse",
    [XSTR_EFUSE_WARN1]       = "В eFuse BLOCK_KEY%d будет записан\n"
                               "случайный 256-битный HMAC-ключ,\n"
                               "после чего чтение блока будет\n"
                               "НАВСЕГДА запрещено.\n"
                               "Биты eFuse нельзя вернуть обратно:\n"
                               "ключ нельзя прочитать, изменить\n"
                               "или стереть - только заменой чипа.\n"
                               "Без этого ключа кошельки на этом\n"
                               "устройстве восстанавливаются только\n"
                               "из seed-фразы на бумаге.",
    [XSTR_EFUSE_WARN2]       = "Операция необратима и выполняется\n"
                               "один раз. Прожечь ключ сейчас?",
    [XSTR_EFUSE_DONE]        = "Ключ eFuse запрограммирован",
    [XSTR_EFUSE_NEEDED]      = "Кошелёк нельзя создать, пока не\n"
                               "запрограммирован ключ eFuse.\n"
                               "Сделать это сейчас?",
    [XSTR_EFUSE_FIRST]       = "Первый запуск. Устройство хранит\n"
                               "кошельки под секретным ключом,\n"
                               "записанным в сам чип (eFuse).\n"
                               "Без этого ключа оно не работает.",
    [XSTR_EFUSE_NO_BLOCK]    = "Нет свободного блока ключа eFuse:\n%s\n"
                               "Устройство не может защитить\n"
                               "кошельки и работать не будет.",
    [XSTR_EFUSE_BLOCKS]      = "Блоки ключей eFuse",
    [XSTR_EFUSE_BLOCKS_HINT] = "* ключ кошельков; R = чтение запрещено",

    [XSTR_TX_MULTI]          = "Набор содержит несколько транзакций.\n"
                               "Разбейте перевод на отдельные\n"
                               "операции в кошельке.",
    [XSTR_KI_FAIL_ITEM]      = "запись #%d: %s",
    [XSTR_INPUT_LIMIT]       = "Достигнут предел длины",
    [XSTR_SEED_FIX_WORD]     = "Проверьте слово %d",

    [XSTR_IMPORT_KEYS]       = "Ввод spend/view key",
    [XSTR_KEY_SPEND_SEC]     = "Секретный spend key (hex, 64)\n"
                               "пусто - только просмотр",
    [XSTR_KEY_VIEW_SEC]      = "Секретный view key (hex, 64)",
    [XSTR_KEY_SPEND_PUB]     = "Публичный spend key (hex, 64)",
    [XSTR_KEY_HEX_BAD]       = "Нужно 64 hex-символа\n"
                               "и корректное значение ключа",
    [XSTR_KEY_VIEW_ONLY]     = "Кошелёк только для просмотра:\n"
                               "подпись и key images недоступны.",

    [XSTR_CHANNEL_LINK]      = "USB (программа на ПК)",
    [XSTR_LINK_WAIT_HINT]    = "Отправьте файл программой на ПК",
    [XSTR_LINK_READY]        = "Файл готов.\n"
                               "Заберите его программой на ПК.",

    [XSTR_KB_LAYOUT]         = "Раскладка",
    [XSTR_KB_QWERTY]         = "QWERTY",
    [XSTR_KB_ABC]            = "ABC",
    [XSTR_WORD_START]        = "Начало слова",
    [XSTR_INPUT]             = "Ввод",

    [XSTR_DEBUG_LOG]         = "Отладочный лог",
    [XSTR_ON]                = "Вкл",
    [XSTR_OFF]               = "Выкл",

    [XSTR_CODE_TITLE]        = "Подтверждение",
    [XSTR_CODE_PROMPT]       = "Для подтверждения введите число:\n\n%s",
    [XSTR_CODE_ENTER]        = "Введите число %s",
    [XSTR_CODE_WRONG]        = "Число не совпало. Действие отменено.",

    [XSTR_PW_TITLE]          = "Пароль устройства",
    [XSTR_PW_SET_HINT]       = "Задайте пароль устройства.\n"
                               "Он запрашивается при каждом включении\n"
                               "и вместе с ключом eFuse шифрует seed.",
    [XSTR_PW_ENTER]          = "Введите пароль устройства",
    [XSTR_PW_REPEAT]         = "Повторите пароль",
    [XSTR_PW_MISMATCH]       = "Пароли не совпадают",
    [XSTR_PW_WRONG]          = "Неверный пароль (попытка %d)",
    [XSTR_PW_LOCKED]         = "Слишком много попыток.\nПодождите %d с.",
    [XSTR_PW_RULES]          = "Пароль: от 8 до 64 символов",
    [XSTR_PW_CHANGE]         = "Сменить пароль устройства",
    [XSTR_PW_OLD]            = "Текущий пароль",
    [XSTR_PW_NEW]            = "Новый пароль",
    [XSTR_PW_CHANGED]        = "Пароль изменён,\nкошельки перешифрованы",
    [XSTR_PW_REQUIRED]       = "Сначала задайте пароль устройства",

    [XSTR_WL_SET_ACTIVE]     = "Сделать активным",
    [XSTR_WL_SHOW_ADDR]      = "Показать адрес",
    [XSTR_WL_SHOW_VIEWKEY]   = "Показать private view key",
    [XSTR_VIEWKEY_TITLE]     = "Private view key",
    [XSTR_VIEWKEY_WARN]      = "Private view key раскрывает все\n"
                               "входящие транзакции кошелька.\n"
                               "Показать его на экране?",

    [XSTR_GAME_TITLE]        = "Сапёр",
    [XSTR_GAME_WON]          = "Победа!",
    [XSTR_GAME_LOST]         = "Бум!",
    [XSTR_GAME_MINES]        = "Мин: %d",
    [XSTR_MAIN_LOCK]         = "Заблокировать",
    [XSTR_WL_ADDR_TEXT]      = "Адрес",
    [XSTR_WL_ADDR_QR]        = "Адрес (QR)",
    [XSTR_WL_VK_TEXT]        = "Private view key",
    [XSTR_WL_VK_QR]          = "Private view key (QR)",
    [XSTR_WL_RENAME]         = "Переименовать",
    [XSTR_WL_RENAMED]        = "Кошелёк переименован",
    [XSTR_WL_CLOSE]          = "Закрыть кошелёк",
    [XSTR_WL_VARIANT_BASE]   = "Без passphrase",
    [XSTR_WL_VARIANT_PP]     = "С passphrase",
    [XSTR_WL_READY]          = "Готов к приёму файлов с ПК",
    [XSTR_WL_NO_LINK]        = "ПК не подключён",
    [XSTR_WL_PP_MARK]        = "* - кошелёк с passphrase",
    [XSTR_PP_OPEN_HINT]      = "Введите passphrase.\n"
                               "Пустое поле откроет кошелёк\n"
                               "без passphrase.",
    [XSTR_PP_WRONG]          = "Неверная passphrase",
    [XSTR_PP_UNVERIFIED]     = "Кошелёк создан старой прошивкой:\n"
                               "passphrase проверить нельзя.\n"
                               "Сверьте адрес с Feather.",
    [XSTR_FILE_ERROR]        = "Файл отклонён",
    [XSTR_KI_REFUSED]        = "Экспорт key images невозможен",
    [XSTR_KI_CONFIRM]        = "Сгенерировать key images\n"
                               "для %u выходов?\n"
                               "(уже известны устройству: %u)",
    [XSTR_KI_DONE]           = "Key images (%u) отправлены на ПК",
    [XSTR_TX_REFUSED]        = "Транзакция не может быть подписана",
    [XSTR_TX_SPENT_WARN]     = "Внимание: входов уже потрачено\n"
                               "ранее подписанной транзакцией: %u.\n"
                               "Если та транзакция отправлена в сеть,\n"
                               "эта будет отклонена.",
    [XSTR_TX_OF]             = "Транзакция %u из %u",
    [XSTR_TX_DONE]           = "Подписанная транзакция\n"
                               "отправлена на ПК",
    [XSTR_REQ_ADDR_Q]        = "ПК запрашивает адрес кошелька.\n"
                               "Отправить?",
    [XSTR_REQ_VK_Q]          = "ПК запрашивает данные для\n"
                               "view-only кошелька: адрес и\n"
                               "PRIVATE VIEW KEY. С ними ПК увидит\n"
                               "все входящие платежи.",
    [XSTR_REQ_SENT]          = "Данные отправлены на ПК",
    [XSTR_REQ_DENIED]        = "Запрос отклонён",
    // v5:change RU
    [XSTR_TX_CHANGE_ROW]     = "Сдача -> этот кошелек %u/%u",
    [XSTR_TX_CHANGE_NONE]    = "нет",
    [XSTR_TX_CHANGE_ADDR]    = "Адрес сдачи",
    [XSTR_TX_OWNED_BY]       = "Принадлежит этому кошельку:\nсчет %u, индекс %u",
    [XSTR_TX_OWN_MARK]       = "этот кошелек %u/%u",
    [XSTR_TX_DUMMY]          = "Фиктивных выходов: %u, 0 XMR",
    [XSTR_TX_IN_OUT]         = "Входов / выходов",
    [XSTR_TX_HIGH_FEE_TITLE] = "Высокая комиссия",
    [XSTR_TX_HIGH_FEE_BODY]  = "Комиссия %s XMR: больше 0.01 XMR\n"
                               "или 10%% от суммы перевода.\n"
                               "Если сдача пропала из файла,\n"
                               "она уйдет майнерам.\n"
                               "Все равно подписать?",
    // end v5:change RU

    // v5:auth RU
    [XSTR_PW_FAILED_SINCE]   = "Неудачных попыток с последнего входа: %d",
    [XSTR_PW_CHECKING]       = "Проверка пароля",
    [XSTR_PW_EMPTY]          = "Пароль не введён",
    // end v5:auth RU

    // v5:touch RU
    [XSTR_TOUCH_TEST]        = "Проверка сенсора",
    [XSTR_TOUCH_TEST_HINT]   = "Коснитесь крестиков: точка должна быть под пальцем",
    [XSTR_TOUCH_TEST_WAIT]   = "Коснитесь экрана",
    [XSTR_CALIB_FAILED]      = "Калибровка не удалась: касания далеко от меток. Повторите.",
    // end v5:touch RU

    // v5:ui RU
    // end v5:ui RU

    // v5:game RU
    // end v5:game RU

    // v5:crash RU
    [XSTR_LAST_CRASH]        = "Прошлый запуск завершился сбоем\n"
                               "(операция %u, этап %u). Подробности\n"
                               "в журнале на ПК.",
    // end v5:crash RU

    // v6 RU
    [XSTR_PW_CORRUPT] = "Запись пароля устройства повреждена\nили утеряна, а кошельки на месте.\nНовый пароль их не откроет.\nНастройки > Сброс к заводским, затем\nвосстановите кошельки из seed.",
    [XSTR_DICE_MIXED] = "Броски кубика объединены с аппаратным\nГСЧ: seed не слабее лучшего из двух\nисточников. По одним броскам его\nповторить нельзя - запишите слова.",
    [XSTR_BIRTH_MONTH] = "Год и месяц сейчас (2026-10)",
    [XSTR_BIRTH_MONTH_BAD] = "Введите год и месяц, например 2026-10.\nПусто - пропустить (сканирование с 2021).",
    [XSTR_KI_CACHE_FULL] = "Кэш key images кошелька заполнен\n(%u выходов): %u не записаны.\nТранзакции с этими выходами\nустройство отклонит.",
    [XSTR_KI_ROLLBACK] = "Кэш key images этого кошелька заменён\nстарой копией и не загружен. Отметки\nо потраченных выходах могли пропасть.\nВыгрузите outputs из Feather заново.",
    [XSTR_PW_STAGE_CHECK] = "Проверка пароля",
    [XSTR_PW_STAGE_UPGRADE] = "Усиление защиты пароля (один раз)",
    [XSTR_PW_STAGE_NEW] = "Вычисление ключа нового пароля",
    [XSTR_PW_STAGE_REKEY] = "Перешифровка кошельков",
    [XSTR_SEED_CAKE] = "Фраза зашифрована passphrase\n(формат Cake Wallet / Cupcake).\nНа следующем шаге введите\nэту passphrase.",
    [XSTR_PP_REQUIRED] = "Для этой фразы passphrase\nобязательна.",
    [XSTR_PP_OPEN_CAKE] = "Кошелёк Cake / Cupcake.\nВведите passphrase:\nбез неё он не откроется.",
    [XSTR_WL_SD] = "Файлы на SD-карте",
    [XSTR_SD_TITLE] = "SD-карта",
    [XSTR_SD_NO_CARD] = "Карта не найдена.\nВставьте microSD (FAT32)\nи повторите.",
    [XSTR_SD_EMPTY] = "В корне карты нет файлов\nFeather: outputs или\nнеподписанных транзакций.",
    [XSTR_SD_SAVED] = "Записано на карту:\n%s",
    [XSTR_SD_OUTPUTS] = "Outputs -> key images",
    [XSTR_SD_UNSIGNED] = "Неподписанная транзакция",
    [XSTR_SD_DONE] = "обработан",
    [XSTR_SD_INSERT] = "Вставьте microSD (FAT32).\nСписок файлов появится сам.",
    [XSTR_WL_SD_VK] = "View key на SD-карту",
    [XSTR_SD_VK_WARN] = "В файл на карте попадут адрес\nи private view key: любой, кто\nпрочтёт карту, увидит все\nвходящие платежи. Записать?",
    [XSTR_SD_VK_NONE] = "У этого кошелька нет\nprivate view key.",
    [XSTR_PW_WEAK] = "Слабый пароль: только цифры\nили одинаковые символы.\nУстройство в чужих руках\nподберёт его. Оставить?",
    // end v6 RU
};

static const char* const X_EN[XSTR_COUNT] = {
    [XSTR_APP_NAME]          = "Monero Cold Wallet",
    [XSTR_VERSION]           = "Version",
    [XSTR_BOOT]              = "Starting...",
    [XSTR_LOCKED]            = "Device locked",
    [XSTR_YES]               = "Yes",
    [XSTR_NO]                = "No",
    [XSTR_OK]                = "OK",
    [XSTR_CLOSE]             = "Close",
    [XSTR_MENU]              = "Menu",
    [XSTR_PROCESSING]        = "Working...",
    [XSTR_ABORTED]           = "Operation cancelled",
    [XSTR_UNSUPPORTED]       = "Not supported on this board",

    [XSTR_WALLET_ACTIVE]     = "Active wallet",
    [XSTR_WALLET_NONE]       = "No wallet selected",
    [XSTR_WALLET_EMPTY]      = "No wallets yet",
    [XSTR_WALLET_NAME]       = "Wallet name",
    [XSTR_WALLET_DELETE_Q]   = "Delete wallet\n\"%s\"?\nThe seed is erased for good.",
    [XSTR_WALLET_DELETED]    = "Wallet deleted",
    [XSTR_WALLET_CREATED]    = "Wallet created",
    [XSTR_WALLET_FULL]       = "Limit of 10 wallets reached",
    [XSTR_WALLET_UNLOCK]     = "Unlocking wallet",
    [XSTR_WALLET_SELECTED]   = "Wallet selected",

    [XSTR_CREATE_TITLE]      = "New wallet",
    [XSTR_IMPORT_TITLE]      = "Import wallet",
    [XSTR_SEED_SOURCE_TITLE] = "Entropy source",
    [XSTR_ENTROPY_SOURCE]    = "Choose the entropy source",
    [XSTR_DICE_ROLLS]        = "Rolls: %d of %d",
    [XSTR_DICE_UNDO]         = "Undo roll",
    [XSTR_DICE_BITS]         = "~%d bits of entropy",
    [XSTR_DICE_NEED_MORE]    = "At least %d rolls are required",

    [XSTR_SEED_WRITE_DOWN]   = "Write the seed phrase down on paper.\n"
                               "Never photograph it.",
    [XSTR_SEED_WRITTEN_Q]    = "Seed phrase written down?\n"
                               "The device will now ask you\nto type a few words back.",
    [XSTR_SEED_PAGE]         = "Words %d-%d of %d",
    [XSTR_VERIFY_PROMPT]     = "Enter word %d",
    [XSTR_VERIFY_FAIL]       = "Word does not match.\nCheck your copy.",
    [XSTR_VERIFY_OK]         = "Seed phrase verified",
    [XSTR_SEED_WORD_BAD]     = "Word %d is not in the dictionary",

    [XSTR_PASSPHRASE_ENTER]  = "Enter passphrase",
    [XSTR_PASSPHRASE_HINT]   = "The passphrase is always asked for.\n"
                               "It is never stored on the device.",
    [XSTR_PASSPHRASE_EMPTY_Q]= "Are you sure you want\nan empty passphrase?",
    [XSTR_PASSPHRASE_OK]     = "Passphrase accepted",

    [XSTR_ADDRESS]           = "Address",
    [XSTR_SHOW_QR]           = "Show QR",
    [XSTR_RESTORE_HEIGHT_HINT] = "Block height (0 = from the start)",

    [XSTR_CHANNEL]           = "Transfer channel",
    [XSTR_CHANNEL_SD]        = "SD card",
    [XSTR_CHANNEL_QR]        = "QR code",
    [XSTR_WAITING_FILE]      = "Waiting for a file...",

    [XSTR_TX_CHANGE]         = "Change",
    [XSTR_TX_TOTAL]          = "Total sent",
    [XSTR_TX_FULL_ADDR]      = "Full address",
    [XSTR_TX_UNLOCK_TIME]    = "Locked until",
    [XSTR_TX_SIGNED]         = "Transaction signed",
    [XSTR_TX_BALANCE_FAIL]   = "Balance mismatch:\ninputs != outputs + fee",
    [XSTR_TX_RECIPIENT]      = "Recipient %d of %d",

    [XSTR_KI_PROCESSED]      = "Processed: %d of %d",
    [XSTR_KI_ERRORS]         = "Errors: %d",

    [XSTR_QR_PART]           = "Part %d of %d",
    [XSTR_QR_PAUSE]          = "Pause",
    [XSTR_QR_RESUME]         = "Resume",
    [XSTR_SCAN_TITLE]        = "Scan QR",
    [XSTR_SCAN_HINT]         = "Point the camera at the QR code",
    [XSTR_NO_CAMERA]         = "No camera on this board",
    [XSTR_NO_QRCODE]         = "QR widget not compiled into the firmware",

    [XSTR_KB_FULL]           = "Full",
    [XSTR_KB_SCROLL]         = "Scroll",
    [XSTR_LETTERS]           = "abc",
    [XSTR_SHIFT]             = "Shift",
    [XSTR_DIGITS]            = "123",
    [XSTR_SYMBOLS]           = "#+=",
    [XSTR_SPACE]             = "Space",

    [XSTR_SETTINGS_LANG]     = "Language",
    [XSTR_SETTINGS_NETWORK]  = "Network",
    [XSTR_SETTINGS_ABOUT]    = "About",
    [XSTR_SETTINGS_SAVED]    = "Settings saved",
    [XSTR_FORMAT_SD_Q]       = "Format the SD card?\nEvery file will be erased.",
    [XSTR_CALIB_PROMPT]      = "Tap the marker in the corner",
    [XSTR_CALIB_DONE]        = "Calibration finished",
    [XSTR_MINUTES]           = "%d min",
    [XSTR_NET_MAIN]          = "Mainnet",
    [XSTR_NET_TEST]          = "Testnet",
    [XSTR_NET_STAGE]         = "Stagenet",
    [XSTR_LANG_RU]           = "Русский",
    [XSTR_LANG_EN]           = "English",
    [XSTR_EFUSE_MISSING]     = "eFuse HMAC key is not provisioned.\n"
                               "Seeds are not sealed in hardware.",

    [XSTR_EFUSE_PROVISION]   = "Provision the eFuse key",
    [XSTR_EFUSE_WARN1]       = "A random 256-bit HMAC key will be\n"
                               "burned into eFuse BLOCK_KEY%d and\n"
                               "reading that block will then be\n"
                               "disabled FOREVER.\n"
                               "eFuse bits cannot be taken back:\n"
                               "the key can never be read, changed\n"
                               "or erased - only by replacing the chip.\n"
                               "Without this key the wallets on this\n"
                               "device can only be restored from the\n"
                               "seed phrase on paper.",
    [XSTR_EFUSE_WARN2]       = "This is irreversible and happens\n"
                               "once. Burn the key now?",
    [XSTR_EFUSE_DONE]        = "eFuse key provisioned",
    [XSTR_EFUSE_NEEDED]      = "A wallet cannot be created until the\n"
                               "eFuse key has been provisioned.\n"
                               "Do it now?",
    [XSTR_EFUSE_FIRST]       = "First start. The device keeps its\n"
                               "wallets under a secret key burned\n"
                               "into the chip itself (eFuse).\n"
                               "It does not work without that key.",
    [XSTR_EFUSE_NO_BLOCK]    = "No free eFuse key block:\n%s\n"
                               "The device cannot protect wallets\n"
                               "and will not work.",
    [XSTR_EFUSE_BLOCKS]      = "eFuse key blocks",
    [XSTR_EFUSE_BLOCKS_HINT] = "* wallet key; R = read-protected",

    [XSTR_TX_MULTI]          = "The set contains several transactions.\n"
                               "Split the transfer into separate\n"
                               "operations in your wallet.",
    [XSTR_KI_FAIL_ITEM]      = "record #%d: %s",
    [XSTR_INPUT_LIMIT]       = "Maximum length reached",
    [XSTR_SEED_FIX_WORD]     = "Check word %d",

    [XSTR_IMPORT_KEYS]       = "Enter spend/view key",
    [XSTR_KEY_SPEND_SEC]     = "Secret spend key (64 hex)\n"
                               "empty - view-only wallet",
    [XSTR_KEY_VIEW_SEC]      = "Secret view key (64 hex)",
    [XSTR_KEY_SPEND_PUB]     = "Public spend key (64 hex)",
    [XSTR_KEY_HEX_BAD]       = "64 hex characters and a valid\n"
                               "key value are required",
    [XSTR_KEY_VIEW_ONLY]     = "View-only wallet: signing and key\n"
                               "images are not available.",

    [XSTR_CHANNEL_LINK]      = "USB (host program)",
    [XSTR_LINK_WAIT_HINT]    = "Send the file from the host program",
    [XSTR_LINK_READY]        = "File is ready.\n"
                               "Fetch it with the host program.",

    [XSTR_KB_LAYOUT]         = "Layout",
    [XSTR_KB_QWERTY]         = "QWERTY",
    [XSTR_KB_ABC]            = "ABC",
    [XSTR_WORD_START]        = "Word starts with",
    [XSTR_INPUT]             = "Input",

    [XSTR_DEBUG_LOG]         = "Debug log",
    [XSTR_ON]                = "On",
    [XSTR_OFF]               = "Off",

    [XSTR_CODE_TITLE]        = "Confirmation",
    [XSTR_CODE_PROMPT]       = "To confirm, type this number:\n\n%s",
    [XSTR_CODE_ENTER]        = "Type the number %s",
    [XSTR_CODE_WRONG]        = "Number did not match. Cancelled.",

    [XSTR_PW_TITLE]          = "Device password",
    [XSTR_PW_SET_HINT]       = "Set a device password.\n"
                               "It is asked at every power-on and,\n"
                               "together with the eFuse key, encrypts the seeds.",
    [XSTR_PW_ENTER]          = "Enter the device password",
    [XSTR_PW_REPEAT]         = "Repeat the password",
    [XSTR_PW_MISMATCH]       = "Passwords do not match",
    [XSTR_PW_WRONG]          = "Wrong password (attempt %d)",
    [XSTR_PW_LOCKED]         = "Too many attempts.\nWait %d s.",
    [XSTR_PW_RULES]          = "Password: 8 to 64 characters",
    [XSTR_PW_CHANGE]         = "Change device password",
    [XSTR_PW_OLD]            = "Current password",
    [XSTR_PW_NEW]            = "New password",
    [XSTR_PW_CHANGED]        = "Password changed,\nwallets re-encrypted",
    [XSTR_PW_REQUIRED]       = "Set the device password first",

    [XSTR_WL_SET_ACTIVE]     = "Make active",
    [XSTR_WL_SHOW_ADDR]      = "Show address",
    [XSTR_WL_SHOW_VIEWKEY]   = "Show private view key",
    [XSTR_VIEWKEY_TITLE]     = "Private view key",
    [XSTR_VIEWKEY_WARN]      = "The private view key reveals every\n"
                               "incoming transaction of this wallet.\n"
                               "Show it on screen?",

    [XSTR_GAME_TITLE]        = "Minesweeper",
    [XSTR_GAME_WON]          = "You win!",
    [XSTR_GAME_LOST]         = "Boom!",
    [XSTR_GAME_MINES]        = "Mines: %d",
    [XSTR_MAIN_LOCK]         = "Lock device",
    [XSTR_WL_ADDR_TEXT]      = "Address",
    [XSTR_WL_ADDR_QR]        = "Address (QR)",
    [XSTR_WL_VK_TEXT]        = "Private view key",
    [XSTR_WL_VK_QR]          = "Private view key (QR)",
    [XSTR_WL_RENAME]         = "Rename",
    [XSTR_WL_RENAMED]        = "Wallet renamed",
    [XSTR_WL_CLOSE]          = "Close wallet",
    [XSTR_WL_VARIANT_BASE]   = "No passphrase",
    [XSTR_WL_VARIANT_PP]     = "With passphrase",
    [XSTR_WL_READY]          = "Ready for files from the PC",
    [XSTR_WL_NO_LINK]        = "PC not connected",
    [XSTR_WL_PP_MARK]        = "* - wallet with a passphrase",
    [XSTR_PP_OPEN_HINT]      = "Enter the passphrase.\n"
                               "Leave it empty to open the wallet\n"
                               "without a passphrase.",
    [XSTR_PP_WRONG]          = "Wrong passphrase",
    [XSTR_PP_UNVERIFIED]     = "Wallet made by an older firmware:\n"
                               "the passphrase cannot be verified.\n"
                               "Compare the address with Feather.",
    [XSTR_FILE_ERROR]        = "File rejected",
    [XSTR_KI_REFUSED]        = "Key image export refused",
    [XSTR_KI_CONFIRM]        = "Generate key images\n"
                               "for %u outputs?\n"
                               "(already known to the device: %u)",
    [XSTR_KI_DONE]           = "%u key images sent to the PC",
    [XSTR_TX_REFUSED]        = "The transaction cannot be signed",
    [XSTR_TX_SPENT_WARN]     = "Warning: inputs already spent by\n"
                               "a transaction signed earlier: %u.\n"
                               "If that one was broadcast,\n"
                               "this one will be rejected.",
    [XSTR_TX_OF]             = "Transaction %u of %u",
    [XSTR_TX_DONE]           = "Signed transaction\nsent to the PC",
    [XSTR_REQ_ADDR_Q]        = "The PC asks for the wallet address.\n"
                               "Send it?",
    [XSTR_REQ_VK_Q]          = "The PC asks for view-only wallet\n"
                               "data: the address and the PRIVATE\n"
                               "VIEW KEY. With it the PC sees every\n"
                               "incoming payment.",
    [XSTR_REQ_SENT]          = "Data sent to the PC",
    [XSTR_REQ_DENIED]        = "Request declined",
    // v5:change EN
    [XSTR_TX_CHANGE_ROW]     = "Change -> this wallet %u/%u",
    [XSTR_TX_CHANGE_NONE]    = "none",
    [XSTR_TX_CHANGE_ADDR]    = "Change address",
    [XSTR_TX_OWNED_BY]       = "Belongs to this wallet:\naccount %u, index %u",
    [XSTR_TX_OWN_MARK]       = "this wallet %u/%u",
    [XSTR_TX_DUMMY]          = "%u dummy output(s), 0 XMR",
    [XSTR_TX_IN_OUT]         = "Inputs / outputs",
    [XSTR_TX_HIGH_FEE_TITLE] = "High fee",
    [XSTR_TX_HIGH_FEE_BODY]  = "The fee is %s XMR: more than\n"
                               "0.01 XMR or 10%% of the amount.\n"
                               "If the change was dropped from\n"
                               "the file, it goes to the miners.\n"
                               "Sign anyway?",
    // end v5:change EN

    // v5:auth EN
    [XSTR_PW_FAILED_SINCE]   = "Failed attempts since last unlock: %d",
    [XSTR_PW_CHECKING]       = "Checking password",
    [XSTR_PW_EMPTY]          = "No password entered",
    // end v5:auth EN

    // v5:touch EN
    [XSTR_TOUCH_TEST]        = "Touch test",
    [XSTR_TOUCH_TEST_HINT]   = "Touch the crosses: the dot must sit under the finger",
    [XSTR_TOUCH_TEST_WAIT]   = "Touch the screen",
    [XSTR_CALIB_FAILED]      = "Calibration failed: taps too far from the targets. Try again.",
    // end v5:touch EN

    // v5:ui EN
    // end v5:ui EN

    // v5:game EN
    // end v5:game EN

    // v5:crash EN
    [XSTR_LAST_CRASH]        = "The previous run crashed\n"
                               "(operation %u, stage %u). Details\n"
                               "are in the PC log.",
    // end v5:crash EN

    // v6 EN
    [XSTR_PW_CORRUPT] = "The device password record is damaged\nor missing while wallets exist.\nA new password would not open them.\nSettings > Factory reset, then restore\nthe wallets from their seeds.",
    [XSTR_DICE_MIXED] = "The dice rolls were combined with the\nhardware TRNG: the seed is at least as\nstrong as the better source. It cannot\nbe recreated from the rolls alone -\nwrite the words down.",
    [XSTR_BIRTH_MONTH] = "Current year and month (2026-10)",
    [XSTR_BIRTH_MONTH_BAD] = "Type the year and month, e.g. 2026-10.\nEmpty - skip (scan from 2021).",
    [XSTR_KI_CACHE_FULL] = "The key image cache of this wallet is\nfull (%u outputs): %u not recorded.\nTransactions spending those outputs\nwill be refused.",
    [XSTR_KI_ROLLBACK] = "The key image cache of this wallet was\nreplaced by an older copy and was not\nloaded. Spent marks may be missing.\nExport the outputs from Feather again.",
    [XSTR_PW_STAGE_CHECK] = "Checking the password",
    [XSTR_PW_STAGE_UPGRADE] = "Strengthening the password (once)",
    [XSTR_PW_STAGE_NEW] = "Deriving the new password key",
    [XSTR_PW_STAGE_REKEY] = "Re-sealing the wallets",
    [XSTR_SEED_CAKE] = "The phrase is encrypted with a\npassphrase (Cake Wallet / Cupcake).\nEnter that passphrase\nin the next step.",
    [XSTR_PP_REQUIRED] = "This phrase needs\nits passphrase.",
    [XSTR_PP_OPEN_CAKE] = "Cake / Cupcake wallet.\nEnter the passphrase:\nit does not open without it.",
    [XSTR_WL_SD] = "SD card files",
    [XSTR_SD_TITLE] = "SD card",
    [XSTR_SD_NO_CARD] = "No card found.\nInsert a microSD card (FAT32)\nand try again.",
    [XSTR_SD_EMPTY] = "No Feather files in the card\nroot: outputs exports or\nunsigned transactions.",
    [XSTR_SD_SAVED] = "Saved to the card:\n%s",
    [XSTR_SD_OUTPUTS] = "Outputs -> key images",
    [XSTR_SD_UNSIGNED] = "Unsigned transaction",
    [XSTR_SD_DONE] = "done",
    [XSTR_SD_INSERT] = "Insert a microSD card (FAT32).\nThe file list appears by itself.",
    [XSTR_WL_SD_VK] = "View key to SD card",
    [XSTR_SD_VK_WARN] = "The file will hold the address\nand the private view key: anyone\nwho reads the card sees every\nincoming payment. Write it?",
    [XSTR_SD_VK_NONE] = "This wallet has no\nprivate view key.",
    [XSTR_PW_WEAK] = "Weak password: digits only or\none repeated character. A stolen\ndevice can guess it.\nKeep it anyway?",
    // end v6 EN
};

/* ------------------------------------------------------------------ */
void mw_i18n_set(mw_lang_t lang) {
    s_lang = (lang == MW_LANG_EN) ? MW_LANG_EN : MW_LANG_RU;
}

mw_lang_t mw_i18n_get(void) { return s_lang; }

const char* mw_str(mw_str_id_t id) {
    const char* s;
    if ((unsigned)id >= (unsigned)STR_COUNT) return "?";
    s = (s_lang == MW_LANG_EN) ? S_EN[id] : S_RU[id];
    if (!s) s = S_EN[id];          /* never return NULL to LVGL */
    return s ? s : "?";
}

const char* mw_strx(mw_xstr_id_t id) {
    const char* s;
    if ((unsigned)id >= (unsigned)XSTR_COUNT) return "?";
    s = (s_lang == MW_LANG_EN) ? X_EN[id] : X_RU[id];
    if (!s) s = X_EN[id];
    return s ? s : "?";
}
