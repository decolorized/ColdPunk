# Справочник API

Справочник составлен **по заголовкам** в `src/`, `boards/` и `test/`.
Функций, которых нет в заголовках, здесь нет. Реализация может отставать от
контракта — статус см. в `docs/compliance_matrix.md`.

Соглашения по именам:

| Префикс | Слой |
| :--- | :--- |
| `mw_sc_*`, `mw_ge_*`, `mw_fe` | скалярная и групповая арифметика ed25519 |
| `mw_point_*` | операции над сжатыми точками |
| `mw_keccak_*`, `mw_sha*`, `mw_hmac_*`, `mw_pbkdf2_*` | хеши |
| `mw_hal_*`, `mw_display_*`, `mw_touch_*`, `mw_sd_*` | HAL |
| `mw_ui_*`, `mw_kb_*`, `mw_flow_*` | UI |
| `mw_wallet_*`, `mw_settings_*`, `mw_seal`/`mw_unseal`, `mw_session_*` | хранилище |
| `mw_file_*`, `mw_parse_*`, `mw_build_*` | форматы файлов |

Почти всё возвращает `mw_err_t` (`MW_OK` = 0, ошибки отрицательные).
Суффикс `_vartime` означает «работает за переменное время, применять только
к публичным данным».

---

## `src/config/app_config.h`

Настройки уровня проекта, не зависящие от платы. Только макросы.

| Макрос | Значение | Назначение |
| :--- | :--- | :--- |
| `MW_FIRMWARE_VERSION` | `"0.1.0"` | версия прошивки |
| `MW_FIRMWARE_NAME` | `"Monero Cold Wallet"` | имя |
| `MAX_WALLETS` | 10 | ТЗ 7.1 |
| `WALLET_NAME_LEN` | 32 | ТЗ 7.1 |
| `MW_INPUT_TIMEOUT_MS` | 5·60·1000 | ТЗ 5.10, очистка буфера ввода |
| `MW_AUTOLOCK_DEFAULT_MIN` | 5 | автоблокировка по умолчанию |
| `MW_MAX_KEYIMAGE_RECORDS` | 1000 | ТЗ 11.3 |
| `MW_UI_TASK_STACK/PRIO/CORE` | 8192 / 2 / 0 | задача LVGL |
| `MW_CRYPTO_TASK_STACK/PRIO/CORE` | 32768 / 3 / 1 | криптозадача |
| `MW_TARGET_FPS` | 20 | цель ТЗ 4.1 |
| `MW_MAX_INPUT_LATENCY_MS` | 100 | цель ТЗ 4.1 |
| `MW_HMAC_EFUSE_KEY_ID` | 0 | блок eFuse для ключа NVS |
| `MW_DEFAULT_NETWORK` | `MW_NET_MAINNET` | переопределяется на `MW_NET_STAGENET` для ТЗ 13.6 |
| `SEED_INPUT_AUTO/FULL_KB/SCROLL_KB` | 0/1/2 | значения `DEFAULT_SEED_INPUT_MODE` |

Файл содержит защиту сборки (ТЗ 8.4):

```c
#if defined(MW_ENABLE_WIFI) || defined(MW_ENABLE_BT)
#error "Air-gapped build: Wi-Fi/BT must not be enabled"
#endif
```

---

## `src/crypto/hash.h`

Хеш-примитивы. Платформонезависимый код, компилируется и для ESP32, и для
хостового тестового раннера.

### Keccak-256

Оригинальный padding Keccak, **не** SHA-3. Это `cn_fast_hash` Monero.

| Тип / макрос | Описание |
| :--- | :--- |
| `MW_KECCAK_DIGEST` | 32 |
| `mw_keccak_ctx` | `state[25]`, `buf[136]`, `buf_len` |

| Функция | Описание |
| :--- | :--- |
| `mw_keccak_init(ctx)` | инициализация контекста |
| `mw_keccak_update(ctx, data, len)` | дозапись |
| `mw_keccak_final(ctx, out[32])` | завершение |
| `mw_keccak256(data, len, out[32])` | одношаговый хеш |
| `mw_cn_fast_hash` | макрос-алиас для `mw_keccak256` |
| `mw_keccak_xof(data, len, out, out_len)` | Keccak с произвольной длиной вывода, для транскрипта Bulletproofs+ |

### SHA-256 / SHA-512

| Тип / макрос | Значение |
| :--- | :--- |
| `MW_SHA256_DIGEST` / `MW_SHA256_BLOCK` | 32 / 64 |
| `MW_SHA512_DIGEST` / `MW_SHA512_BLOCK` | 64 / 128 |
| `mw_sha256_ctx`, `mw_sha512_ctx` | контексты |

| Функция | Описание |
| :--- | :--- |
| `mw_sha256_init/update/final` | потоковый SHA-256 |
| `mw_sha256(data, len, out)` | одношаговый |
| `mw_sha512_init/update/final` | потоковый SHA-512 |
| `mw_sha512(data, len, out)` | одношаговый |

### HMAC и PBKDF2

| Функция | Описание |
| :--- | :--- |
| `mw_hmac_sha256(key, key_len, msg, msg_len, out)` | HMAC-SHA-256 |
| `mw_hmac_sha512(key, key_len, msg, msg_len, out)` | HMAC-SHA-512 |
| `mw_pbkdf2_sha256(pw, pw_len, salt, salt_len, iterations, out, out_len)` | нужен Polyseed: 10000 итераций (ТЗ 6.3) |
| `mw_pbkdf2_sha512(pw, pw_len, salt, salt_len, iterations, out, out_len)` | нужен энтропии из кубиков: 2048 раундов (ТЗ 6.4) |
| `mw_crc32(data, len)` | CRC32 (IEEE), контрольная сумма seed Monero legacy |

---

## `src/crypto/ed25519.h`

Арифметика ed25519 в том виде, в каком её требует Monero: модель ref10
(`fe` / `ge_p3` / `ge_p2` / `ge_p1p1` / `ge_cached`) плюс надстройки Monero.

### Типы

| Тип | Описание |
| :--- | :--- |
| `mw_scalar_t` | `uint8_t b[32]`, little-endian, всегда приведён mod `l` |
| `mw_point_t` | `uint8_t b[32]`, сжатая точка Эдвардса |
| `mw_fe` | `int32_t[10]`, элемент поля, radix 25.5 |
| `mw_ge_p3` | `X, Y, Z, T` — расширенные координаты |
| `mw_ge_p2` | `X, Y, Z` — проективные |
| `mw_ge_p1p1`, `mw_ge_cached`, `mw_ge_precomp` | промежуточные представления ref10 |

### Константы

| Константа | Значение |
| :--- | :--- |
| `MW_SC_ZERO`, `MW_SC_ONE` | 0 и 1 |
| `MW_SC_L` | порядок группы `l` (не приведён!) |
| `MW_POINT_G` | базовая точка |
| `MW_POINT_H` | `H = 8·to_point(keccak(G))` — второй генератор Monero |
| `MW_POINT_IDENTITY` | нейтральный элемент |
| `MW_GE_P3_H` | `H` в расширенной форме |

### Скаляры (mod l)

| Функция | Описание |
| :--- | :--- |
| `mw_sc_reduce32(s)` | приведение на месте, 32 байта |
| `mw_sc_reduce64(out, in[64])` | приведение 64 байт в скаляр |
| `mw_sc_add/sub/mul(r, a, b)` | сложение / вычитание / умножение mod `l` |
| `mw_sc_muladd(r, a, b, c)` | `r = (a·b + c) mod l` |
| `mw_sc_mulsub(r, a, b, c)` | `r = (c − a·b) mod l` (Monero `sc_mulsub`) |
| `mw_sc_invert(r, a)` | `a^(l−2) mod l` |
| `mw_sc_is_zero(s)` | 1, если ноль |
| `mw_sc_check(s)` | 1, если канонический (`s < l`) |
| `mw_sc_eq(a, b)` | равенство |
| `mw_sc_0(s)`, `mw_sc_1(s)` | присвоить 0 / 1 |
| `mw_sc_random(s)` | равномерно в `[1, l−1]`, через `mw_random` |
| `mw_hash_to_scalar(data, len, out)` | `sc_reduce32(keccak256(data))` |

### Точки

| Функция | Описание |
| :--- | :--- |
| `mw_ge_frombytes_vartime(h, p)` | декомпрессия, 0 = успех |
| `mw_ge_p3_tobytes(out, h)`, `mw_ge_p2_tobytes(out, h)` | компрессия |
| `mw_ge_p3_to_cached(r, p)` | в `cached`-форму |
| `mw_ge_p1p1_to_p3(r, p)`, `mw_ge_p1p1_to_p2(r, p)` | конверсии |
| `mw_ge_p3_0(h)` | нейтральный элемент |
| `mw_ge_add(r, p, q)`, `mw_ge_sub(r, p, q)` | сложение / вычитание |
| `mw_ge_p3_dbl(r, p)` | удвоение |
| `mw_ge_mul8(r, p)` | умножение на кофактор |
| `mw_ge_scalarmult_base(r, a)` | `a·G`, постоянное время |
| `mw_ge_scalarmult(r, a, p)` | `a·P`, постоянное время (для секретных скаляров) |
| `mw_ge_double_scalarmult_base_vartime(r, a, p, b)` | `a·P + b·G`, только публичные данные |
| `mw_ge_double_scalarmult_vartime(r, a, p, b, q)` | `a·P + b·Q`, только публичные данные |

Байтовые обёртки над сжатыми точками:

| Функция | Описание |
| :--- | :--- |
| `mw_point_add(r, a, b)`, `mw_point_sub(r, a, b)` | сложение / вычитание |
| `mw_point_scalarmult(r, a, p)` | `a·P` |
| `mw_point_scalarmult_base(r, a)` | `a·G` |
| `mw_point_is_identity(p)`, `mw_point_eq(a, b)` | сравнения |

### Проверки (ТЗ 8.3)

| Функция | Описание |
| :--- | :--- |
| `mw_point_is_valid(p)` | точка декодируется в точку кривой |
| `mw_point_in_main_subgroup(p)` | `l·P == identity`. **Обязательно для каждой точки, пришедшей извне** |
| `mw_point_check_public(p)` | обе проверки сразу |

### Специфика Monero

| Функция | Описание |
| :--- | :--- |
| `mw_hash_to_ec(data, len, out)` | `ge_fromfe_frombytes_vartime` + `mul8`, результат `ge_p3` |
| `mw_hash_to_point(data, len, out)` | то же, результат — сжатая точка; используется для key images |
| `mw_commit(out, mask, amount)` | коммитмент Педерсена `C = a·G + b·H` |
| `mw_scalarmult_H(out, b)` | `b·H` |
| `mw_bp_get_exponent(out, idx)` | детерминированная цепочка генераторов Bulletproofs+: `hash_to_point(H_bytes ‖ "bulletproof" ‖ varint(idx))` |

---

## `src/crypto/memzero.h`

Затирание, которое компилятор не выбросит, и сравнение за постоянное время.
Нужны по ТЗ 5.2 / 5.10 / 8.1.

| Функция / макрос | Описание |
| :--- | :--- |
| `mw_memzero(p, len)` | гарантированное обнуление |
| `MW_ZERO(x)` | `mw_memzero(&(x), sizeof(x))` |
| `mw_ct_equal(a, b, len)` | равенство за постоянное время, 1 = равны |
| `mw_ct_is_zero(a, len)` | «все байты нулевые» за постоянное время |

---

## `src/crypto/random.h`

Слой ГСЧ. ТЗ 8.2: `bootloader_random_enable()` первым в `setup()`,
самотестирование при загрузке, хеджирование нонсов CLSAG.

| Значение `mw_rng_status_t` | Смысл |
| :--- | :--- |
| `MW_RNG_OK` | 0 |
| `MW_RNG_ERR_NOT_INIT` | −1 |
| `MW_RNG_ERR_SELFTEST` | −2, не прошёл repetition / adaptive-proportion тест |
| `MW_RNG_ERR_STUCK` | −3, возвращает одинаковые блоки |

| Функция | Описание |
| :--- | :--- |
| `mw_random_init()` | включает аппаратный TRNG и прогоняет самотест. **Должна быть первым вызовом в `setup()`** |
| `mw_random_selftest()` | тесты здоровья в стиле NIST SP 800-90B по свежей выборке |
| `mw_random_bytes(out, len)` | случайные байты |
| `mw_random_hedged_scalar(scalar_out, context, context_len)` | `k = hash_to_scalar(TRNG(32) ‖ детерминированный контекст)`; не слабее любого из источников по отдельности (ТЗ 8.2) |
| `mw_random_set_test_source(stream, len)` | **только для хостовых тестов**: детерминированный поток вместо энтропии, чтобы подписи стали воспроизводимыми. На устройстве — пустая операция |

---

## `src/crypto/chacha.h`

ChaCha20 в варианте Monero плюс `cn_slow_hash`, которым Monero выводит ключ
из view key перед шифрованием файлов обмена (ТЗ 9, 11.3).

| Тип / макрос | Значение |
| :--- | :--- |
| `MW_CHACHA_KEY_SIZE` | 32 |
| `MW_CHACHA_IV_SIZE` | 8 (8-байтовый IV, 8-байтовый счётчик) |
| `mw_chacha_key`, `mw_chacha_iv` | обёртки над массивами |

| Функция | Описание |
| :--- | :--- |
| `mw_chacha20(in, len, key, iv, out)` | 20 раундов, 64-битный nonce, счётчик с нуля. Шифрование и расшифровка — одна операция |
| `mw_generate_chacha_key(data, len, key, iterations)` | `generate_chacha_key` Monero: `cn_slow_hash` (вариант 0) над материалом. `iterations` — это `kdf_rounds` Monero, для файлов кошелька 1 |
| `mw_cn_slow_hash(data, len, hash[32])` | CryptoNight вариант 0. Нужен scratchpad 2 МиБ; на ESP32-S3 обязан быть в PSRAM. 0 — успех, −1 — не удалось выделить scratchpad |
| `mw_cn_slow_hash_init()` | резервирует 2 МиБ один раз при старте, чтобы подпись не падала на поздней аллокации. 0 — успех |
| `mw_cn_slow_hash_free()` | освобождает scratchpad |

---

## `src/data/wordlist.h`

Доступ к словарям. На ESP32 массивы лежат во flash (`.rodata`) и **никогда
не копируются в RAM** — указатели разыменовываются напрямую по
memory-mapped flash. Это и есть выполнение ТЗ 5.1.

| Тип | Описание |
| :--- | :--- |
| `mw_wordlist_id_t` | `MW_WL_MONERO_EN` = 0 (1626 слов, префикс 3 символа), `MW_WL_POLYSEED_EN` = 1 (2048 слов, префикс 4 символа, отсортирован) |
| `mw_wordlist_t` | `id`, `words`, `count`, `prefix_len`, `is_sorted`, `name` |
| `MW_WORDLIST_STORAGE` | квалификатор размещения таблиц; по умолчанию пуст |

| Функция | Описание |
| :--- | :--- |
| `mw_wordlist(id)` | дескриптор словаря |
| `mw_wordlist_find(wl, word)` | точный поиск; принимает и полное слово, и уникальный префикс. Индекс или −1 (не найдено / неоднозначно) |
| `mw_wordlist_prefix_matches(wl, prefix, out, max, total_out)` | поиск по префиксу для экранных клавиатур (ТЗ 5.7). Возвращает число записанных индексов; `total_out` — общее число совпадений, даже если больше `max` |
| `mw_wordlist_next_letters(wl, prefix)` | 26-битная маска букв, которыми префикс ещё можно продолжить (`'a'` = бит 0). Для гашения «мёртвых» клавиш |
| `mw_wordlist_word(wl, index)` | слово по индексу |

Сгенерированные таблицы: `src/data/wordlist_monero_en.h`
(`monero_en_words[1626]`, `MONERO_EN_PREFIX_LEN` 3) и
`src/data/wordlist_polyseed_en.h` (`polyseed_en_words[2048]`,
`POLYSEED_EN_PREFIX_LEN` 4). Генератор — `tools/gen_wordlists.py`,
править вручную нельзя.

---

## `src/monero/monero_types.h`

Базовые типы, общие для всех модулей.

| Тип | Описание |
| :--- | :--- |
| `mw_seckey_t` | = `mw_scalar_t`, всегда приведён mod `l` |
| `mw_pubkey_t`, `mw_keyimage_t` | = `mw_point_t` |
| `mw_ecdh_mask_t` | = `mw_scalar_t` |
| `mw_keypair_sec_t` | `spend` (m), `view` (n = Hs(m)) |
| `mw_keypair_pub_t` | `spend` (M = m·G), `view` (N = n·G) |
| `mw_account_keys_t` | `sec`, `pub`, `view_only` |
| `mw_network_t` | `MW_NET_MAINNET` 0, `MW_NET_TESTNET` 1, `MW_NET_STAGENET` 2 |
| `mw_address_type_t` | `MW_ADDR_STANDARD`, `MW_ADDR_INTEGRATED`, `MW_ADDR_SUBADDRESS` |
| `mw_address_t` | `spend`, `view`, `type`, `network`, `payment_id[8]`, `has_payment_id`, `major`, `minor` |
| `mw_seed_type_t` | `MW_SEED_MONERO_LEGACY` 0, `MW_SEED_POLYSEED` 1 |

| Макрос | Значение |
| :--- | :--- |
| `MW_ADDRESS_STR_MAX` | 128 (самый длинный адрес — integrated, 106 символов) |
| `MW_LEGACY_SEED_WORDS` | 25 |
| `MW_POLYSEED_WORDS` | 16 |
| `MW_MAX_SEED_WORDS` | 25 |
| `MW_ATOMIC_UNITS` | 1e12 (1 XMR) |

### Коды ошибок `mw_err_t`

| Код | Значение | Смысл |
| :--- | ---: | :--- |
| `MW_OK` | 0 | успех |
| `MW_ERR_INVALID_ARG` | −1 | неверный аргумент |
| `MW_ERR_CHECKSUM` | −2 | не сошлась контрольная сумма seed |
| `MW_ERR_NUM_WORDS` | −3 | неверное число слов |
| `MW_ERR_UNKNOWN_WORD` | −4 | слова нет в словаре |
| `MW_ERR_FORMAT` | −5 | формат данных |
| `MW_ERR_MAGIC` | −6 | не та magic-строка |
| `MW_ERR_VERSION` | −7 | неподдерживаемая версия формата |
| `MW_ERR_SIGNATURE` | −8 | подпись не сошлась |
| `MW_ERR_DECRYPT` | −9 | ошибка расшифровки |
| `MW_ERR_MEMORY` | −10 | нет памяти |
| `MW_ERR_NOT_SUPPORTED` | −11 | не поддерживается |
| `MW_ERR_SUBGROUP` | −12 | точка не прошла `l·P == 0` |
| `MW_ERR_BALANCE` | −13 | входы ≠ выходы + комиссия |
| `MW_ERR_KEY_MISMATCH` | −14 | `x·G != P` |
| `MW_ERR_TOO_MANY` | −15 | превышен лимит записей |
| `MW_ERR_IO` | −16 | ошибка ввода-вывода |
| `MW_ERR_ABORTED` | −17 | отменено пользователем |
| `MW_ERR_RANGE` | −18 | значение вне диапазона |

| Функция | Описание |
| :--- | :--- |
| `mw_err_str(err)` | текстовое описание кода |
| `mw_format_amount(amount, out, out_len)` | форматирует piconero как `"12.345678901234"`; буфер ≥ 32 байт |

---

## `src/monero/keys.h`

Вывод ключей: seed → ключи аккаунта, одноразовые ключи и ECDH для подписи.

| Функция | Описание |
| :--- | :--- |
| `mw_keys_from_legacy_seed(seed[32], out)` | `spend = sc_reduce32(seed)`, `view = Hs(spend)` |
| `mw_keys_from_polyseed_key(key[32], out)` | 32 байта из `polyseed_keygen()` становятся материалом spend key |
| `mw_keys_derive_public(keys)` | достраивает публичные половины, перепроверяет `x·G == P` (ТЗ 8.3), иначе `MW_ERR_KEY_MISMATCH` |
| `mw_generate_key_derivation(pub, sec, derivation_out)` | `D = 8·r·A` (отправитель) или `8·a·R` (получатель) |
| `mw_derivation_to_scalar(derivation, output_index, out)` | `Hs(D ‖ varint(index))` |
| `mw_derive_public_key(derivation, output_index, base, out)` | `P = Hs(D‖i)·G + B` |
| `mw_derive_secret_key(derivation, output_index, base, out)` | `x = Hs(D‖i) + b` |
| `mw_get_subaddress_secret_key(view, major, minor, out)` | `m = Hs("SubAddr\0" ‖ a ‖ major ‖ minor)` |
| `mw_get_subaddress(keys, major, minor, out)` | субадрес как `mw_address_t` |
| `mw_ecdh_hash(shared, out[32])` | хеш общего секрета для RCT |
| `mw_ecdh_decode(shared, amount_inout, mask_out)` | расшифровка суммы и маски (короткая форма «v2») |
| `mw_ecdh_encode(shared, amount, amount_out[8], mask_out)` | шифрование суммы и маски |
| `mw_check_key_pair(sec, pub)` | проверяет, что `sec` — дискретный логарифм `pub` (ТЗ 8.3) |

---

## `src/monero/mnemonic.h`

Кодирование и декодирование seed-фраз обоих форматов (ТЗ 5.1, 6.2, 6.3).

### Monero legacy, 25 слов

24 слова несут 32 байта (3 слова на 4 байта), 25-е — контрольное слово
CRC32 по склеенным 3-символьным префиксам.

| Функция | Описание |
| :--- | :--- |
| `mw_legacy_seed_encode(seed[32], wl, indices_out[25])` | seed → индексы слов |
| `mw_legacy_seed_decode(indices[25], wl, seed_out[32])` | индексы → seed, с проверкой контрольной суммы |
| `mw_legacy_checksum_index(indices[24], wl)` | индекс (0..23) слова, которому должно быть равно контрольное слово |

### Polyseed, 16 слов

| Макрос | Значение |
| :--- | :--- |
| `MW_POLYSEED_SECRET_BITS` | 150 |
| `MW_POLYSEED_SECRET_SIZE` | 19 |
| `MW_POLYSEED_FEATURE_BITS` | 5 |
| `MW_POLYSEED_DATE_BITS` | 10 |
| `MW_POLYSEED_EPOCH` | 1635768000 (2021-11-01 12:00 UTC) |
| `MW_POLYSEED_TIME_STEP` | 2629746 (1/12 григорианского года) |
| `MW_POLYSEED_COIN_MONERO` | 0 |

| Тип | Поля |
| :--- | :--- |
| `mw_polyseed_t` | `birthday` (10 бит), `features` (5 бит), `secret[32]` (значимы 150 бит), `checksum` (элемент GF(2048)) |

| Функция | Описание |
| :--- | :--- |
| `mw_polyseed_create(entropy, entropy_len, unix_time, features, out)` | новый polyseed; нужно ≥ 19 байт энтропии; `unix_time` = 0 → birthday 0 («неизвестно») |
| `mw_polyseed_encode(seed, wl, indices_out[16])` | → индексы слов |
| `mw_polyseed_decode(indices[16], wl, out)` | ← индексы, с проверкой кода |
| `mw_polyseed_keygen(seed, coin, key_out[32])` | PBKDF2-HMAC-SHA256, 10000 итераций, соль `"POLYSEED key"` + coin/birthday/features → 32 байта spend key |
| `mw_polyseed_crypt(seed, password)` | собственное шифрование фразы Polyseed (feature bit 16). **Это не passphrase сессии по ТЗ 5.2** |
| `mw_polyseed_is_encrypted(seed)` | признак зашифрованной фразы |
| `mw_polyseed_birthday_time(seed)` | метка времени из birthday |
| `mw_polyseed_restore_height(seed, net)` | приблизительная высота восстановления (ТЗ 6.3) |

### Passphrase (ТЗ 5.2)

```c
mw_err_t mw_seed_to_keys(mw_seed_type_t type, const uint8_t* seed_material,
                         size_t seed_len, const char* passphrase,
                         mw_account_keys_t* keys_out);
```

По комментарию в заголовке:

- **legacy:** при непустом passphrase `spend = sc_reduce32(keccak256(seed ‖ passphrase))`;
  пустой passphrase воспроизводит обычный seed Monero один в один;
- **polyseed:** используется `mw_polyseed_crypt` — штатная схема upstream.

> Схема для legacy не совпадает с «seed offset» в Monero
> (`sc_add(seed, hash_to_scalar(passphrase))`). См. `docs/compliance_matrix.md`,
> раздел 5.2.

---

## `src/monero/address.h`

Base58 в варианте Monero (блоки по 8 байт → 11 символов) и кодирование
адресов.

| Функция | Описание |
| :--- | :--- |
| `mw_base58_encode(data, len, out, out_len)` | кодирование, возвращает длину |
| `mw_base58_decode(str, out, out_len, out_written)` | декодирование |
| `mw_base58_encode_check(data, len, out, out_len)` | с 4-байтовой контрольной суммой keccak |
| `mw_base58_decode_check(str, out, out_len, out_written)` | с проверкой контрольной суммы |
| `mw_address_prefix(net, type)` | префикс сети и типа адреса |
| `mw_address_encode(addr, out, out_len)` | `mw_address_t` → строка |
| `mw_address_decode(str, out)` | строка → `mw_address_t` |
| `mw_address_from_keys(keys, net, out)` | основной адрес (major = 0, minor = 0) |
| `mw_address_shorten(full, out, out_len, head, tail)` | краткая форма `"48aBc...xyz89"` для экрана подтверждения. ТЗ 12.3 при этом требует, чтобы полный адрес был где-то доступен прокруткой |

---

## `src/monero/key_image.h`

Вывод key images и поток `outputs.bin` → `keyimages.bin` (ТЗ 11).

| Функция | Описание |
| :--- | :--- |
| `mw_generate_key_image(pub, sec, out)` | `I = x·Hp(P)`. Сначала проверяет `x·G == P`, иначе `MW_ERR_KEY_MISMATCH` (ТЗ 8.3) |
| `mw_generate_key_image_signature(pub, sec, image, sig_out)` | подпись экспорта key image, которую ждёт `import_key_images` Monero |
| `mw_check_key_image_signature(pub, image, sig)` | проверка этой подписи |

| Тип | Поля |
| :--- | :--- |
| `mw_ring_sig_t` | `c`, `r` — два скаляра |
| `mw_exported_output_t` | `tx_pub_key`, `internal_output_index`, `global_output_index`, `one_time_pubkey`, `subaddr_major`, `subaddr_minor`, `amount`, `flags`, `rct`, `has_additional`, `additional_tx_pub` (дополнительный ключ именно этого выхода), `additional_count` |
| `mw_exported_key_image_t` | `image`, `sig` |

```c
mw_err_t mw_key_image_from_output(const mw_account_keys_t* keys,
                                  const mw_exported_output_t* out,
                                  mw_exported_key_image_t* ki_out);
```

Восстанавливает одноразовый секрет экспортированного выхода, выводит key
image и подпись. `mw_output_secret(keys, P, R, R_add, i, major, minor, x)` —
общий вывод секрета выхода (основной ключ транзакции, затем дополнительный).
Прошивка прерывает экспорт на первой чужой записи (задача 3);
`mw_key_image_batch()` с учётом отказов оставлен для тестов.

---

## `src/monero/serialize.h`

Примитивы бинарных архивов Monero: varint, раскладка
`portable_binary_archive` и байтовый курсор, которым пользуются все парсеры.

| Тип | Поля |
| :--- | :--- |
| `mw_reader_t` | `data`, `len`, `pos`, `overflow` (липкий флаг чтения за границу) |
| `mw_writer_t` | `data`, `cap`, `pos`, `overflow` |

| Функция | Описание |
| :--- | :--- |
| `mw_reader_init(r, data, len)` / `mw_writer_init(w, buf, cap)` | инициализация |
| `mw_read_bytes/u8/u16/u32/u64` | чтение (целые — little-endian) |
| `mw_read_varint(r, out)` | varint Monero (LEB128), максимум 10 байт |
| `mw_read_point(r, out)`, `mw_read_scalar(r, out)` | чтение 32-байтовых значений |
| `mw_skip(r, n)`, `mw_remaining(r)` | пропуск и остаток |
| `mw_write_bytes/u8/u32/u64/varint/point/scalar` | запись |
| `mw_varint_encode(v, out[10])` | самостоятельное кодирование varint; возвращает длину |
| `mw_varint_size(v)` | длина varint без кодирования |

### boost portable_binary_archive (не используется текущим парсером)

Monero сериализует `unsigned_tx_set` через
`boost::archive::portable_binary_oarchive` — так были устроены версии 3 и 4
набора. Версия 5, единственная, которую принимает эта прошивка,
сериализуется собственным `binary_archive` Monero (обычные varint), и
`mw_parse_unsigned_tx()` разбирает именно её. Функции ниже оставлены и
покрыты тестами на случай поддержки старых наборов; сейчас их не вызывает
ни один файл в `src/`. Целые в этом формате хранятся как: 1 байт
размера (бит 7 — знак «отрицательное») + little-endian байты.

| Функция | Описание |
| :--- | :--- |
| `mw_pba_read_u64/u32/i64/size` | чтение целых в формате portable_binary |
| `mw_pba_write_u64/u32` | запись |
| `mw_pba_read_header(r, version_out)` | чтение и проверка сигнатуры и версии архива |
| `mw_pba_write_header(w, version)` | запись заголовка |

---

## `src/monero/tx.h`

Модель транзакции для подписи (ТЗ 12). Ограничения ниже — жёсткие лимиты,
которые парсер обязан проверять, чтобы битый файл не разнёс кучу.

| Макрос | Значение |
| :--- | :--- |
| `MW_MAX_INPUTS` | 16 |
| `MW_MAX_OUTPUTS` | 16 |
| `MW_RING_SIZE` | 16 (консенсус с v15) |
| `MW_MAX_RING_SIZE` | 32 |
| `MW_MAX_TX_EXTRA` | 1024 |
| `MW_MAX_DESTINATIONS` | 16 |

| Тип | Ключевые поля |
| :--- | :--- |
| `mw_ctkey_t` | `dest` (P члена кольца), `mask` (C члена кольца) |
| `mw_tx_source_t` | `amount`, `key_image`, `key_offsets[]`, `ring_size`, `ring[]`, `real_output_index`, `real_out_tx_key`, `real_output_in_tx_index`, `mask`, `subaddr_major/minor` |
| `mw_tx_destination_t` | `amount`, `addr`, `is_subaddress`, `is_change` |
| `mw_tx_output_t` | `out_pubkey`, `amount`, `commitment`, `mask`, `ecdh_amount[8]`, `view_tag`, `has_view_tag` |
| `mw_transaction_t` | `version`, `unlock_time`, `n_inputs`, `n_outputs`, `sources[]`, `destinations[]`, `n_destinations`, `outputs[]`, `tx_extra[]`, `tx_extra_len`, `fee`, `tx_secret_key` (r), `tx_public_key` (R), `rct_type` (6 = BulletproofPlus), `change_dst_index` (0xFFFFFFFF = нет сдачи), `use_view_tags` |
| `mw_tx_summary_t` | `total_out`, `change`, `fee`, `total_in`, `n_inputs`, `n_outputs`, `n_recipients`, `recipients[][MW_ADDRESS_STR_MAX]`, `amounts[]` |

| Функция | Описание |
| :--- | :--- |
| `mw_tx_check_balance(tx)` | `sum(inputs) == sum(outputs) + fee` (ТЗ 8.3 / 12.3) |
| `mw_tx_summarize(tx, net, out)` | сводка для экрана подтверждения |
| `mw_tx_prefix_hash(tx, out[32])` | сборка префикса и его keccak-хеш |
| `mw_tx_rct_message(tx, bp_serialized, bp_len, out[32])` | `keccak(prefix_hash ‖ rct_base_hash ‖ bp_hash)` |
| `mw_tx_extra_build(tx, additional, n_additional, encrypted_payment_id)` | сборка `tx_extra`: публичный ключ, дополнительные ключи, payment id (8 байт или `NULL`) |

---

## `src/monero/clsag.h`

Кольцевые подписи CLSAG. Постоянное время по секретному индексу.

| Тип | Поля |
| :--- | :--- |
| `mw_clsag_t` | `s[MW_MAX_RING_SIZE]`, `n` (размер кольца), `c1`, `D` (key image / 8), `I` (не сериализуется — берётся из входа) |

```c
mw_err_t mw_clsag_sign(const uint8_t message[32], const mw_ctkey_t* ring, uint8_t n,
                       uint8_t real_idx, const mw_seckey_t* p, const mw_scalar_t* z,
                       const mw_point_t* C_offset, const mw_keyimage_t* I,
                       mw_clsag_t* sig_out);
```

| Параметр | Смысл |
| :--- | :--- |
| `message` | хеш сообщения RCT |
| `ring`, `n` | члены кольца `(P_i, C_i)` и размер |
| `real_idx` | индекс нашего члена в кольце |
| `p` | одноразовый секретный ключ реального члена |
| `z` | разность масок (`real_mask − pseudo_out_mask`) |
| `C_offset` | коммитмент pseudoOut |

`mw_clsag_verify(message, ring, n, C_offset, I, sig)` — самопроверка:
устройство всегда проверяет то, что только что подписало, прежде чем
записать результат.

---

## `src/monero/bulletproof_plus.h`

Доказательства диапазона Bulletproofs+ (ТЗ 12, RCT type 6). Таблицы
генераторов и рабочие векторы на устройстве размещаются в PSRAM.

| Макрос | Значение |
| :--- | :--- |
| `MW_BPP_MAX_OUTPUTS` | 16 |
| `MW_BPP_MAX_M` | 16 (число выходов, дополненное до степени двойки) |
| `MW_BPP_N` | 64 (бит на диапазон) |
| `MW_BPP_MAX_MN` | 1024 |
| `MW_BPP_MAX_LOG_MN` | 10 |

| Тип | Поля |
| :--- | :--- |
| `mw_bpp_proof_t` | `A`, `A1`, `B`, `r1`, `s1`, `d1`, `L[]`, `R[]`, `n_lr` (= log2(M·N)), `V[]` (коммитменты / 8), `n_v` |

| Функция | Описание |
| :--- | :--- |
| `mw_bpp_prove(amounts, masks, n, proof_out)` | доказывает, что каждое `amounts[i]` в `[0, 2^64)` при `C_i = masks[i]·G + amounts[i]·H` |
| `mw_bpp_verify(proof)` | проверка; устройство проверяет собственный вывод до подписи (защита от инъекции сбоев) |
| `mw_bpp_check_commitments(proof, out_commitments, n)` | ТЗ 8.3: `V[i]·8 == outPk[i].mask` для каждого выхода |
| `mw_bpp_serialize(p, out, out_len)` | сериализация, возвращает длину |
| `mw_bpp_deserialize(in, len, out)` | разбор |
| `mw_bpp_init()` | кеш генераторов в PSRAM; вызывается один раз при старте |
| `mw_bpp_free()` | освобождение |
| `mw_bpp_set_progress_cb(cb, user)` | колбэк прогресса `mw_progress_cb(int permille, void* user)`, `permille` 0..1000 |

> Комментарий в шапке заголовка ссылается на `mw_bpp_set_allocator()`,
> которого в заголовке нет. Отмечено в `docs/compliance_matrix.md`.

---

## `src/monero/file_formats.h`

Четыре файла обмена ТЗ раздела 9. Общий конверт:
`magic ‖ iv(8) ‖ chacha20(plaintext) ‖ signature(64)`.

| Макрос | Значение |
| :--- | :--- |
| `MW_MAGIC_OUTPUTS` / `_LEN` | `"Monero output export\004"` / 21 |
| `MW_MAGIC_KEYIMAGES` / `_LEN` | `"Monero key image export\003"` / 26 (фактическая длина строки 24 — см. `docs/file_formats.md`) |
| `MW_MAGIC_UNSIGNED_TX` / `_LEN` | `"Monero unsigned tx set"` / 22 |
| `MW_MAGIC_SIGNED_TX` / `_LEN` | `"Monero signed tx set"` / 20 |
| `MW_UNSIGNED_TX_VERSION` | 0x05 |
| `MW_SIG_LEN` | 64 |
| `MW_IV_LEN` | 8 |
| `MW_MAX_EXPORTED_OUTPUTS` | 2700 (помещается в 256 КиБ линка) |
| `MW_MAX_TXES_PER_SET` | 4 |

| Тип / константа | Описание |
| :--- | :--- |
| `mw_file_kind_t` | `magic`, `magic_len`, `version`, `has_version` |
| `MW_FILE_OUTPUTS`, `MW_FILE_KEYIMAGES`, `MW_FILE_UNSIGNED_TX`, `MW_FILE_SIGNED_TX` | готовые дескрипторы |
| `mw_outputs_iter_t` | потоковое чтение выходов: `offset`, `total`, `count`, `next` |
| `mw_unsigned_set_t`, `mw_utx_entry_t` | разобранный неподписанный набор: спаны частей каждой `tx_construction_data`, `new_transfers` |
| `mw_signed_ptx_t`, `mw_ki_pair_t` | вклад устройства в `pending_tx` и записи `tx_key_images` |
| `mw_ff_diag_t` | смещение и текст причины отказа (без ключей) |

| Функция | Описание |
| :--- | :--- |
| `mw_file_open(kind, file, file_len, keys, plaintext, cap, plaintext_len)` | проверяет magic/версию, выводит ключ, расшифровывает и проверяет подпись Schnorr. `plaintext` может алиасить ciphertext |
| `mw_file_seal(kind, plaintext, plaintext_len, keys, out, out_cap, out_len)` | шифрование + подпись в конверт |
| `mw_schnorr_sign(hash[32], pub, sec, sig_out[64])` | подпись над 32-байтовым хешем, как `generate_signature` Monero |
| `mw_schnorr_verify(hash[32], pub, sig[64])` | проверка |
| `mw_file_detect(data, len)`, `mw_file_format_name(f)` | вид файла по magic, независимо от имени |
| `mw_outputs_begin(it, plaintext, len, keys, diag)`, `mw_outputs_next(it, out, done, diag)` | экспорт выходов Feather (формат 4) |
| `mw_build_keyimages(keys, items, count, offset, out, out_cap, out_len)` | payload экспорта key images |
| `mw_unsigned_set_parse(plaintext, len, set, diag)` | разбор и проверка неподписанного набора v1/v2 |
| `mw_unsigned_set_load_tx(set, i, tx, diag)` | транзакция `i` в модель подписи |
| `mw_unsigned_set_new_transfers(set, it)` | чтение `new_transfers` |
| `mw_build_signed_set(set, ptx, n, kis, n_kis, out, cap, len)` | payload `signed_tx_set` как у `sign_tx()` Feather |
| `mw_build_signed_tx(tx, rct_blob, rct_len, out, out_cap, out_len)` | сериализованная транзакция (префикс + RCT) |

Подробные раскладки — `docs/file_formats.md`.

---

## `src/monero/sign.h`

Оркестрация подписи целиком (ТЗ 12.2). Выполняется на криптозадаче FreeRTOS,
чтобы задача LVGL продолжала перерисовывать экран (ТЗ 4.1).

| `mw_sign_stage_t` | Стадия |
| :--- | :--- |
| `MW_SIGN_STAGE_PARSE` | разбор входного файла |
| `MW_SIGN_STAGE_VERIFY_INPUTS` | проверки входов |
| `MW_SIGN_STAGE_OUTPUT_KEYS` | ключи и маски выходов |
| `MW_SIGN_STAGE_BULLETPROOF` | генерация доказательства диапазона |
| `MW_SIGN_STAGE_CLSAG` | кольцевые подписи |
| `MW_SIGN_STAGE_SERIALIZE` | сериализация результата |
| `MW_SIGN_STAGE_DONE` | завершено |

| Тип | Поля |
| :--- | :--- |
| `mw_signed_data_t` | `clsag[MW_MAX_INPUTS]`, `pseudo_outs[MW_MAX_INPUTS]`, `bpp`, `message[32]`, `prefix_hash[32]` |
| `mw_sign_progress_cb` | `void (*)(mw_sign_stage_t stage, int permille, void* user)` |

| Функция | Описание |
| :--- | :--- |
| `mw_sign_transaction(keys, tx, out, cb, user)` | полный конвейер подписи; предполагает, что пользователь уже подтвердил сводку |
| `mw_serialize_rct(tx, sd, out, out_cap)` | сериализация блока подписей RCT для `signed_tx_set.bin` |

---

## `src/hal/hal.h`

Слой абстракции от железа. Всё специфичное для платы достигается через этот
заголовок; `board_config.h` даёт только номера пинов и флаги (ТЗ 2.1 — без
автоопределения).

### Константы драйверов

`DISPLAY_ILI9341` 1, `DISPLAY_ST7789` 2, `DISPLAY_ST7701S` 3,
`DISPLAY_GC9A01` 4, `DISPLAY_ILI9488` 5, `DISPLAY_SSD1306` 6,
`DISPLAY_SH1106` 7.

`TOUCH_NONE` 0, `TOUCH_FT6336G` 1, `TOUCH_FT6236` 2, `TOUCH_CST816S` 3,
`TOUCH_GT911` 4, `TOUCH_XPT2046` 5.

### Возможности платы

| Тип | Поля |
| :--- | :--- |
| `mw_hal_caps_t` | `width`, `height`, `rotation`, `monochrome`, `has_touch`, `has_buttons`, `has_encoder`, `has_sd`, `has_camera`, `has_usb`, `has_psram`, `psram_size_mb`, `board_name` |

| Функция | Описание |
| :--- | :--- |
| `mw_hal_caps()` | указатель на возможности текущей платы |
| `mw_hal_init()` | такты, PSRAM, TRNG, дисплей, ввод |
| `mw_hal_deinit()` | деинициализация |

### Дисплей

| Функция | Описание |
| :--- | :--- |
| `mw_display_init()` | инициализация панели |
| `mw_display_backlight(percent)` | подсветка 0..100 |
| `mw_display_blit(x, y, w, h, pixels)` | сырой вывод прямоугольника; плюмбинг flush-колбэка LVGL живёт в `ui/lvgl_port.cpp`, чтобы порт не зависел от драйвера |
| `mw_display_wait_dma()` | ожидание окончания DMA |

### Ввод

| Тип | Значения |
| :--- | :--- |
| `mw_button_t` | `MW_BTN_NONE`, `MW_BTN_UP`, `MW_BTN_DOWN`, `MW_BTN_LEFT`, `MW_BTN_RIGHT`, `MW_BTN_SELECT`, `MW_BTN_BACK` |
| `mw_touch_state_t` | `pressed`, `x`, `y` |

| Функция | Описание |
| :--- | :--- |
| `mw_touch_init()` | инициализация тача |
| `mw_touch_read(out)` | текущее состояние |
| `mw_touch_calibrate(coeffs[6])` | калибровка, коэффициенты сохраняются в NVS |
| `mw_buttons_init()` | инициализация кнопок |
| `mw_buttons_read()` | битовая маска нажатых, номер бита = значение `mw_button_t` |
| `mw_encoder_read()` | дельта энкодера с прошлого вызова (0, если энкодера нет) |

### Хранилище

| Функция | Описание |
| :--- | :--- |
| `mw_sd_init()` | монтирование карты |
| `mw_sd_present()` | карта вставлена |
| `mw_sd_read_file(path, buf, cap, len)` | чтение файла |
| `mw_sd_write_file(path, buf, len)` | запись файла |
| `mw_sd_list(dir, names, max, count)` | список имён (буфер `char[][64]`) |
| `mw_sd_format()` | форматирование карты |

### Питание и прочее

| Функция | Описание |
| :--- | :--- |
| `mw_battery_percent()` | заряд, −1 если нет топливомера |
| `mw_usb_connected()` | подключён ли USB |
| `mw_millis()` | миллисекунды с запуска |
| `mw_delay_ms(ms)` | задержка |
| `mw_reboot()` | перезагрузка |
| `mw_factory_reset()` | стирает NVS со всеми кошельками и перезагружается (ТЗ 4.2) |

> В заголовке **нет** функций работы с камерой, хотя `mw_hal_caps()`
> содержит `has_camera`. Контракт драйвера камеры не зафиксирован.

---

## `src/wallet/wallet_store.h`

Хранилище нескольких кошельков в зашифрованном NVS (ТЗ 7, 8.1).

| Тип | Поля |
| :--- | :--- |
| `wallet_entry_t` | `id`, `name[WALLET_NAME_LEN]`, `encrypted_seed[64]`, `seed_iv[16]`, `seed_tag[16]`, `restore_height`, `wallet_type` (0 = legacy, 1 = polyseed), `is_view_only`, `is_hidden` |
| `wallet_store_t` | `wallets[MAX_WALLETS]`, `count`, `active_wallet_id` |

Раскладка сохранена байт-в-байт по ТЗ 7.1.

| Функция | Описание |
| :--- | :--- |
| `mw_wallet_store_init()` | инициализация хранилища |
| `mw_wallet_store_load(out)` | чтение всего хранилища |
| `mw_wallet_store_save(store)` | запись |
| `mw_wallet_create(name, type, seed_material, seed_len, restore_height, id_out)` | запечатывает seed ключом eFuse HMAC (AES-GCM) и добавляет кошелёк. `seed_len` = 32 для legacy, 19..32 для polyseed |
| `mw_wallet_unseal_seed(id, out, cap, len)` | расшифровывает seed (вызывающий обязан затереть буфер). Требует разблокированного устройства; открытый seed не живёт дольше одной операции |
| `mw_wallet_load_keys(id, passphrase, keys_out)` | полный конвейер: распечатать → вывести ключи с passphrase → затереть seed |
| `mw_wallet_delete(id)` | ТЗ 7.2, безопасное удаление: запись в NVS перезаписывается перед удалением |
| `mw_wallet_rename(id, name)` | переименование |
| `mw_wallet_set_active(id)` | выбор активного кошелька |
| `mw_wallet_get(id)` | запись по идентификатору |
| `mw_wallet_create_pp(name, type, seed, len, height, pp_keys, id_out)` | создание с вариантом passphrase: `pp_keys` — ключи с passphrase (NULL — без него); в запечатанной записи сохраняется 14-байтовая метка для проверки |
| `mw_wallet_pp_state(id)` | `MW_PP_NONE` (не спрашивать), `MW_PP_SET` (спросить и проверить), `MW_PP_UNKNOWN` (старая запись: спросить, проверить нельзя) |
| `mw_wallet_open(id, passphrase, keys, verified)` | пустая строка — кошелёк без passphrase; иначе вариант с passphrase, при `MW_PP_SET` неверная — `MW_ERR_DECRYPT` |

`wallet_entry_t.pp_state` хранится в байте 139 записи каталога (раньше не
использовался), формат каталога не менялся.

---

## `src/wallet/wallet_ops.h` (задача 3)

Операции над файлами Feather, платформонезависимые и покрытые
`test_feather_flow`. Отказ всегда объяснён в `mw_ops_error_t.text`.

| Функция | Описание |
| :--- | :--- |
| `mw_ops_outputs_inspect(keys, file, len, plain_len, info, er)` | расшифровка на месте, проверка кошелька и структуры, число выходов и уже известных |
| `mw_ops_outputs_to_keyimages(keys, plain, len, out, cap, out_len, cb, er)` | key images всех выходов (отказ на первом чужом), запись в кэш, запечатанный файл |
| `mw_ops_unsigned_inspect(keys, net, file, len, session, require_known_ki, review, er)` | разбор, проверка входов (принадлежность, кэш key images), адреса сдачи, сводки для экрана |
| `mw_ops_unsigned_sign(keys, session, out, cap, out_len, cb, er)` | подпись всех транзакций, `tx_key_images`, запечатанный подписанный набор, обновление кэша |
| `mw_ops_wallet_export(keys, net, name, height, with_view_key, out, cap, len)` | JSON для ПК: адрес, restore height, view key только по флагу |
| `mw_ops_set_allocator(a)` | куда брать большие буферы (PSRAM на устройстве) |

## `src/wallet/ki_cache.h` (задача 3)

Кэш выданных key images на кошелёк и вариант passphrase: запечатанный файл
на разделе FAT. `mw_ki_cache_open/close/save`, `find_pub`, `find_image`,
`put` (флаги `MW_KI_F_EXPORTED`, `MW_KI_F_SPENT`, `MW_KI_F_CHANGE`),
`mark_spent`, `erase_wallet`. До 4096 записей.

## `src/wallet/file_store.h` (задача 3)

Файлы, не помещающиеся в NVS: `mw_fstore_init/write/size/read/remove/wipe_all`.
Устройство — FFat на разделе `storage`, хост — файлы в каталоге тестового
хранилища. Писать сюда можно только запечатанные данные.

---

## `src/wallet/secure_storage.h`

Ключ eFuse HMAC, зашифрованный NVS и настройки устройства (ТЗ 8.1, 4.2).

| Тип | Значения / поля |
| :--- | :--- |
| `keyboard_type_t` | `KEYBOARD_FULL` 0, `KEYBOARD_SCROLL` 1 |
| `usb_mode_t` | `USB_MODE_MSC` 0, `USB_MODE_MTP`, `USB_MODE_FLOPPY`, `USB_MODE_COMPOSITE` |
| `mw_settings_t` | `keyboard`, `usb_mode`, `brightness` (0..100), `autolock_min`, `touch_calib[6]`, `touch_calibrated`, `network`, `version` |

| Функция | Описание |
| :--- | :--- |
| `mw_settings_load(out)` / `mw_settings_save(s)` | настройки в NVS |
| `mw_settings_default_keyboard()` | правило AUTO из ТЗ 5.5, применяется один раз при первом запуске |
| `mw_secure_key_status()` | `MW_OK`, если HMAC-ключ есть и защищён от чтения |
| `mw_secure_key_provision()` | одноразовая прошивка: записывает TRNG-ключ в `HMAC_KEY0` с назначением `HMAC_UP` и ставит read-protect. **Необратимо** (ТЗ 8.1) |
| `mw_seal(label, pt, pt_len, iv16, tag16, ct, ct_cap)` | AES-256-GCM на ключе, выведенном из eFuse HMAC по `label` |
| `mw_unseal(label, ct, ct_len, iv16, tag16, pt, pt_cap)` | обратная операция |

---

## `src/wallet/session.h`

Единственное место, где законно живут расшифрованный ключ или passphrase, и
только на время одной операции (ТЗ 5.2, 8.1).

| Тип | Поля |
| :--- | :--- |
| `mw_session_t` | `keys`, `wallet_id`, `unlocked`, `last_activity_ms`, `network` |

| Функция | Описание |
| :--- | :--- |
| `mw_session()` | указатель на единственную сессию |
| `mw_session_unlock(wallet_id, passphrase)` | разблокировка кошелька |
| `mw_session_lock()` | затирает ключи и все временные буферы. Вызывается при автоблокировке, при ошибке и после каждой завершённой операции |
| `mw_session_touch()` | отметка активности |
| `mw_session_expired()` | истёк ли таймаут автоблокировки |
| `mw_session_input_buffer(cap)` | буфер для набираемого passphrase; гарантированно затирается `mw_session_wipe_input()` |
| `mw_session_wipe_input()` | затереть буфер ввода |

---

## `src/transfer/transfer.h`

Единый слой обмена данными (ТЗ 3). Экран просит «следующий входной файл» и
не знает, придёт он по SD, USB или QR.

| Тип | Значения |
| :--- | :--- |
| `mw_channel_t` | `MW_CHANNEL_SD` 0, `MW_CHANNEL_QR`, `MW_CHANNEL_USB_LINK` (программа на ПК, `link.h`), `MW_CHANNEL_AUDIO` (резерв) |
| `mw_file_kind_id_t` | `MW_FILE_KIND_OUTPUTS` 0, `MW_FILE_KIND_KEYIMAGES`, `MW_FILE_KIND_UNSIGNED_TX`, `MW_FILE_KIND_SIGNED_TX`, `MW_FILE_KIND_WALLET_EXPORT` (JSON по запросу ПК), `MW_FILE_KIND_COUNT` |
| `MW_FILENAME[MW_FILE_KIND_COUNT]` | имена файлов на SD, индексируются `mw_file_kind_id_t` |
| `MW_TRANSFER_MAX_FILE` | 256 КиБ |

| Функция | Описание |
| :--- | :--- |
| `mw_transfer_init()` | инициализация слоя |
| `mw_transfer_available(ch)` | доступен ли канал |
| `mw_transfer_receive(ch, kind, buf, cap, len)` | чтение файла. Для QR крутит экран сканера, пока последовательность UR не собрана или пользователь не отменил |
| `mw_transfer_send(ch, kind, buf, len)` | отдача файла |

---

## `src/transfer/ur.h`

Uniform Resources (Blockchain Commons) — транспорт анимированных QR
(ТЗ 3.7). Реализует bytewords (minimal), обёртку CBOR и фонтанный
(многочастный) кодек, который используют Feather и ANON/NERO.

| Макрос | Значение |
| :--- | :--- |
| `MW_UR_MAX_FRAGMENT` | 200 байт на фрагмент до bytewords |
| `MW_UR_DEFAULT_FRAGMENT` | 50 (ТЗ 3.7) |
| `MW_UR_MAX_PARTS` | 512 |
| `MW_UR_TYPE_BYTES` | `"bytes"` |
| `MW_UR_TYPE_KEYIMAGE` | `"crypto-keyimage"` |

### Кодер

| Функция | Описание |
| :--- | :--- |
| `mw_ur_encoder_new(ur_type, payload, len, max_fragment)` | создать кодер |
| `mw_ur_encoder_free(e)` | освободить |
| `mw_ur_encoder_next(e, out, out_cap)` | следующая строка вида `ur:bytes/1-7/lpamchcf...`; циклится бесконечно |
| `mw_ur_encoder_seq_len(e)` | длина последовательности |
| `mw_ur_encoder_is_single_part(e)` | помещается ли в один QR |

### Декодер

| Функция | Описание |
| :--- | :--- |
| `mw_ur_decoder_new(buffer, buffer_cap)` | создать декодер поверх буфера вызывающего |
| `mw_ur_decoder_free(d)` | освободить |
| `mw_ur_decoder_receive(d, part)` | скормить одну распознанную строку: `MW_OK` — принято, `MW_ERR_FORMAT` — мусор |
| `mw_ur_decoder_complete(d)` | собрано ли целиком |
| `mw_ur_decoder_progress_permille(d)` | прогресс 0..1000 |
| `mw_ur_decoder_result(d, data, len, type_out, type_cap)` | результат и тип UR |

### Bytewords

| Функция | Описание |
| :--- | :--- |
| `mw_bytewords_encode_minimal(in, len, out, out_cap)` | кодирование minimal |
| `mw_bytewords_decode_minimal(in, out, out_cap, out_len)` | декодирование |
| `mw_ur_crc32(data, len)` | CRC32, как того требует UR |

---

## `src/ui/ui.h`

Слой LVGL (ТЗ 4). Экраны создаются лениво и уничтожаются при выходе, чтобы
плата 240×320 не держала в памяти больше двух экранов объектов.

### Экраны

`mw_screen_id_t`: `MW_SCREEN_BOOT`, `MW_SCREEN_MAIN_MENU`,
`MW_SCREEN_WALLET_LIST`, `MW_SCREEN_WALLET_CREATE`,
`MW_SCREEN_WALLET_IMPORT`, `MW_SCREEN_SEED_DISPLAY`, `MW_SCREEN_SEED_INPUT`,
`MW_SCREEN_SEED_VERIFY`, `MW_SCREEN_PASSPHRASE`, `MW_SCREEN_DICE`,
`MW_SCREEN_TX_REVIEW`, `MW_SCREEN_KEYIMAGE_SYNC`, `MW_SCREEN_QR_DISPLAY`,
`MW_SCREEN_QR_SCAN`, `MW_SCREEN_SETTINGS`, `MW_SCREEN_PROGRESS`,
`MW_SCREEN_MESSAGE`.

| Функция | Описание |
| :--- | :--- |
| `mw_ui_init()` | инициализация LVGL и портирующего слоя |
| `mw_ui_tick()` | вызывается из цикла задачи LVGL |
| `mw_ui_show(id)` | переключение экрана |
| `mw_ui_current()` | текущий экран |
| `mw_ui_set_status(battery_percent, sd, usb)` | индикаторы статусной строки (ТЗ 4.2) |

### Блокирующие помощники

Вызываются из криптозадачи, исполняются задачей LVGL через очередь:

| Функция | Описание |
| :--- | :--- |
| `mw_ui_confirm(title, body, ok, cancel)` | диалог подтверждения, возвращает `bool` |
| `mw_ui_message(title, body)` | сообщение |
| `mw_ui_progress(title, permille, detail)` | прогресс |

### Клавиатура (ТЗ 5.4)

| Тип | Значения / поля |
| :--- | :--- |
| `mw_kb_mode_t` | `MW_KB_MODE_SEED_LEGACY` (только 1626 слов), `MW_KB_MODE_SEED_POLYSEED` (только 2048 слов), `MW_KB_MODE_FREE_TEXT` (passphrase, имя кошелька) |
| `mw_kb_ctx_t` | `mode`, `type` (FULL/SCROLL), `title`, `word_index` (с 1), `word_total`, `allow_back` |

`mw_kb_run(ctx, out, out_cap)` — ввод одного слова или одной строки.
`MW_OK` и заполненный `out`, либо `MW_ERR_ABORTED` при отмене.

### Высокоуровневые сценарии

| Функция | Описание |
| :--- | :--- |
| `mw_shell_run()` | вся жизнь криптозадачи: «Сапёр» → пароль → главное меню → кошельки → меню кошелька; обработка файлов и запросов с ПК; блокировка (задача 3) |
| `mw_shell_link_install()` | классификатор файлов и «будильник» для USB-линка |
| `mw_shell_info(name, cap, variant, network)` | открытый кошелёк для INFO линка |
| `mw_ui_menu_run(menu)` | общая страница меню, `MW_MENU_BACK` / `MW_MENU_WAKE` |
| `mw_screen_game_run()` | «Сапёр» до тройного касания взорванной мины |
| `mw_screen_passphrase_open_run(name, out, cap)` | один ввод passphrase при открытии кошелька |
| `mw_flow_passphrase(out, out_cap)` | ТЗ 5.2: спрашивается всегда, с явным подтверждением «без passphrase» и двойным вводом. Пишет в буфер сессии и затирает при ошибке |

---

## `src/ui/i18n.h`

Двухъязычная таблица строк (RU/EN). LVGL нужен шрифт с покрытием кириллицы
(ТЗ 4.1), см. `ui/fonts/`.

| Тип | Значения |
| :--- | :--- |
| `mw_lang_t` | `MW_LANG_RU` 0, `MW_LANG_EN` 1 |
| `mw_str_id_t` | перечисление идентификаторов строк, оканчивается `STR_COUNT` |

| Функция / макрос | Описание |
| :--- | :--- |
| `mw_i18n_set(lang)` | выбор языка |
| `mw_i18n_get()` | текущий язык |
| `mw_str(id)` | строка по идентификатору |
| `T(id)` | сокращение для `mw_str(id)` |

Группы идентификаторов: главное меню (`STR_MAIN_*`), кошельки
(`STR_WALLET_*`), общие кнопки (`STR_CONFIRM`, `STR_CANCEL`, `STR_BACK`,
`STR_CLEAR`, `STR_NEXT`, `STR_DONE`), seed (`STR_SEED_*`, `STR_WORD_OF`,
`STR_PREFIX`, `STR_CHECKSUM_FAIL`, `STR_RESTORE_HEIGHT`, `STR_VERIFY_SEED`),
энтропия (`STR_ENTROPY_TRNG`, `STR_ENTROPY_DICE`, `STR_DICE_PROMPT`),
passphrase (`STR_PASSPHRASE`, `STR_PASSPHRASE_REPEAT`,
`STR_PASSPHRASE_NONE`, `STR_PASSPHRASE_NONE_CONFIRM`,
`STR_PASSPHRASE_MISMATCH`), транзакция (`STR_TX_*`, `STR_SIGNING`),
key images (`STR_KI_SYNC`, `STR_KI_RECORDS`, `STR_SAVE`), настройки
(`STR_SETTINGS_*`, `STR_RESET_CONFIRM`), ошибки (`STR_ERR_GENERIC`,
`STR_NO_SD`, `STR_NO_FILE`, `STR_SUCCESS`).

---

## `boards/es3c28p.h`

Референсная плата ТЗ 2.2: ESP32-S3 + 2.8" ILI9341 240×320 + тач FT6336G +
microSD. Определяет `BOARD_CONFIG_H`. Полный список макросов и правила
заполнения — `docs/adding_boards.md`.

Существенное отличие от ТЗ: пины пересчитаны под ESP32-S3, поскольку
таблица ТЗ 2.2 приводит номера классического ESP32; `HAS_CAMERA` = 0,
тогда как ТЗ 2.2 указывает 1. Обоснование — в шапке файла.

---

## `test/test_framework.h`

Минимальный хостовый тест-фреймворк, зависимостей кроме libc нет.

| Макрос / функция | Описание |
| :--- | :--- |
| `MW_TEST(name)` | объявление теста (`static void name(void)`) |
| `RUN_TEST(fn)` | запуск с печатью `ok` / `FAIL` |
| `CHECK(cond)` | проверка условия |
| `CHECK_EQ_INT(a, b)` | равенство целых с печатью значений |
| `CHECK_EQ_MEM(a, b, n)` | равенство буферов с hex-дампом обеих сторон |
| `CHECK_EQ_STR(a, b)` | равенство строк |
| `mw_test_hexdump(label, data, len)` | hex-дамп |
| `mw_test_hex(hex, out, cap)` | разбор hex-строки в байты; возвращает длину |
| `mw_test_summary()` | итог; код возврата для `main` |
| `mw_test_failures`, `mw_test_checks`, `mw_test_current` | счётчики и имя текущего теста |

Сборка и запуск — `docs/testing.md`.
