# Форматы файлов обмена (Feather / Monero)

Задача 3 п. 4. Устройство читает и пишет те же файлы, что Feather Wallet в
режиме офлайн-подписи: экспорт выходов, экспорт key images, неподписанный и
подписанный наборы транзакций. Раскладки взяты из исходников форка wallet2,
который поставляет Feather (`feather-wallet/monero`), и сверены с
`monero-project/monero` release-v0.18: `export_outputs_to_str()`,
`export_key_images_for_outputs_from_str()`, `parse_unsigned_tx_from_str()`,
`sign_tx()`, `parse_tx_from_str()` в `src/wallet/wallet2.cpp`, структуры в
`wallet2.h`, `cryptonote_tx_utils.h`, правила `src/serialization/*.h`.

Реализация: `src/monero/file_formats.{h,c}`, операции над файлами —
`src/wallet/wallet_ops.{h,c}`, независимый тестовый кодировщик —
`test/fx_feather.h`, тесты `test/test_file_formats.c`,
`test/test_feather_flow.c`.

---

## 1. Распознавание файла

Устройство определяет вид файла по началу содержимого, а не по имени
(Feather сохраняет файлы без расширения):

| Magic | Вид | Что делает устройство |
| :--- | :--- | :--- |
| `Monero output export\x04` | выходы | считает key images |
| `Monero unsigned tx set` + `\x05` | неподписанный набор | подписывает |
| `Monero key image export\x03` | key images | отказ: «этот файл делает устройство» |
| `Monero signed tx set` + `\x05` | подписанный набор | отказ: «загрузите его в Feather» |
| `Monero multisig unsigned tx set` | multisig | отказ: не поддерживается |
| та же строка с другой версией | старый формат | отказ: «обновите кошелёк» |

## 2. Конверт

```
file = magic [версия] || iv(8) || chacha20(plaintext) || signature(64)
```

- ключ ChaCha20 = `cn_slow_hash(private view key)`, `kdf_rounds = 1`;
- подпись — `crypto::generate_signature(keccak256(iv || ciphertext),
  view_public, view_secret)`, то есть ключом просмотра кошелька.

Следствие, важное для пользователя: файл, сделанный другим кошельком или
**другим вариантом passphrase** того же seed, не проходит проверку подписи.
Устройство отвечает «file was made by a different wallet … (wrong wallet or
passphrase variant?)» и ничего не расшифровывает.

## 3. Правила сериализации (binary_archive)

| Конструкция | Кодирование |
| :--- | :--- |
| `FIELD(u64)`, `FIELD(u32)`, `FIELD(u8)` | фиксированная ширина, little endian (8/4/1 байт) |
| `VARINT_FIELD`, `VERSION_FIELD` | varint (LEB128, до 10 байт, без незначащих нулей) |
| `bool` | 1 байт, только 0 или 1 |
| `std::string`, `std::vector`, `std::set`, `serializable_map` | varint число элементов, затем элементы |
| элемент контейнера — беззнаковое целое шире байта | varint |
| `std::pair` | varint `2`, затем оба элемента (`u64`/`size_t` — varint) |
| `std::tuple<3>` | varint `3`, затем элементы (`u64` — varint) |
| ключи, `rct::ctkey`, `multisig_kLRki` | сырые байты (32 / 64 / 128) |
| `variant` | 1 байт тега, затем альтернатива |

## 4. Экспорт выходов (`Monero output export\x04`)

```
plaintext = spend_public(32) || view_public(32) ||
            tuple< varint offset, varint total, vector<exported_transfer_details> >
```

`offset` — индекс первого выхода в кошельке Feather, `total` — сколько
выходов в кошельке всего. Запись `exported_transfer_details`:

| Поле | Кодирование |
| :--- | :--- |
| версия | varint, ≥ 1 |
| `m_pubkey` | 32 |
| `m_internal_output_index` | varint (< 65536) |
| `m_global_output_index` | varint |
| `m_tx_pubkey` | 32 |
| `m_flags` | 1 байт (бит 2 — RingCT) |
| `m_amount` | varint |
| `m_additional_tx_keys` | varint n, n × 32 |
| `m_subaddr_index_major`, `_minor` | varint, varint |

Устройство проверяет, что `spend_public`/`view_public` — ключи открытого
кошелька, читает записи потоково, для каждой восстанавливает одноразовый
секрет (`Hs(8·a·R ‖ i) + b` + ключ подадреса; основной ключ транзакции, затем
дополнительный ключ этого выхода) и отказывает весь файл на первой чужой
записи — частичный экспорт опаснее отказа.

## 5. Экспорт key images (`Monero key image export\x03`)

```
plaintext = u32 offset (LE) || spend_public(32) || view_public(32) ||
            N × ( key_image(32) || signature(64) )
```

Подпись — кольцевая подпись над `{P}` с key image в роли и образа, и
«хеша префикса» (`generate_ring_signature(ki, ki, {P}, x, 0)`). Форк Feather
при импорте сопоставляет key image с выходом перебором по этой подписи,
поэтому `offset` для него не важен; устройство всё равно пишет offset из
файла выходов, как это делает `export_key_images_for_outputs_from_str()`.

## 6. Неподписанный набор (`Monero unsigned tx set\x05`)

```
unsigned_tx_set:
  VERSION_FIELD           varint 2 (1 тоже принимается, 0 — нет)
  txes                    vector<tx_construction_data>, до 4 транзакций
  new_transfers           v2: tuple<u64 offset, u64 total, vector<exported_transfer_details>>
                          v1: pair<size_t offset, vector<exported_transfer_details>>
```

`tx_construction_data` (версии у записи нет):

| Поле | Кодирование |
| :--- | :--- |
| `sources` | vector<`tx_source_entry`>, 1..32 |
| `change_dts` | `tx_destination_entry` |
| `splitted_dsts` | vector<`tx_destination_entry`>, 1..16 (со сдачей) |
| `selected_transfers` | vector<size_t> (varint) |
| `extra` | vector<u8> |
| `unlock_time` | u64 **фиксированные 8 байт**, должно быть 0 |
| `construction_flags` | u8: бит 0 RingCT, бит 1 view tags |
| `rct_config` | varint версия, varint `range_proof_type`, varint `bp_version` |
| `dests` | vector<`tx_destination_entry`> (без сдачи) |
| `subaddr_account` | u32 **фиксированные 4 байта** |
| `subaddr_indices` | set<u32> (varint) |

`tx_source_entry`:

| Поле | Кодирование |
| :--- | :--- |
| `outputs` | vector< pair<u64 глобальный индекс, ctkey(64)> >, кольцо |
| `real_output` | u64, 8 байт |
| `real_out_tx_key` | 32 |
| `real_out_additional_tx_keys` | vector<ключ> |
| `real_output_in_tx_index` | u64, 8 байт |
| `amount` | u64, 8 байт |
| `rct` | bool |
| `mask` | 32 |
| `multisig_kLRki` | 128 |

`tx_destination_entry`: `original` (строка), `amount` (varint), адрес
(spend 32, view 32), `is_subaddress` (bool), `is_integrated` (bool).

Поддерживаются только транзакции RingCT с Bulletproofs+ (`range_proof_type ≠
0`, `bp_version` 0 или ≥ 4), без unlock time, с одинаковым размером кольца у
всех входов.

## 7. Подписанный набор (`Monero signed tx set\x05`)

Так же, как `sign_tx()` форка Feather для холодного кошелька:

```
signed_tx_set:
  VERSION_FIELD     varint 0
  ptx               vector<pending_tx>, по одной на неподписанную транзакцию
  key_images        vector<key_image> — пустой (Feather так и пишет)
  tx_key_images     map<public_key, key_image>: varint n, n × (varint 2, 32, 32)
```

`pending_tx` (`VERSION_FIELD` 1):

| Поле | Что пишет устройство |
| :--- | :--- |
| `tx` | транзакция целиком: префикс, rct base, rct prunable |
| `dust`, `fee` | u64 по 8 байт; fee = входы − выходы |
| `dust_added_to_fee` | 0 |
| `change_dts`, `selected_transfers`, `dests`, `construction_data` | байты из неподписанного набора без изменений |
| `key_images` | строка `"<hex> "` на каждый вход |
| `tx_key` | единица (`rct::identity()`): ключ транзакции онлайн-кошельку не отдаётся |
| `additional_tx_keys` | пустой вектор |
| `multisig_sigs` | пустой вектор |
| `multisig_tx_key_entropy` | 32 нулевых байта |

`tx_key_images` — key images выходов сдачи новой транзакции и всех выходов
из `new_transfers`: так Feather узнаёт, что эти выходы принадлежат кошельку и
не потрачены.

## 8. Как устройство строит транзакцию

Повторяет `construct_tx_and_get_tx_key()` / `construct_tx_with_tx_key()`:

1. Для каждого входа восстанавливается одноразовый секрет. Подадрес входа
   ищется среди `subaddr_indices` и `subaddr_account` набора и среди
   подадресов, известных из экспорта выходов (кэш key images); проверяется
   `x·G == P` и то, что коммитмент открывается в `(mask, amount)`.
2. Входы сортируются по key image по убыванию.
3. **Проверка адреса сдачи**: адрес из `change_dts` должен совпасть с
   основным адресом кошелька, подадресом `(subaddr_account, 0)` или
   подадресом из подсказок — **по spend key**. Одного view key мало:
   онлайн-кошелёк знает view key и может составить «подадрес» со своим
   spend key. Выход с ненулевой суммой на неподтверждённый адрес сдачи —
   отказ («possible change address substitution»).
4. Выходы перемешиваются; `classify_addresses()` без адреса сдачи решает, нужен
   ли `R = r·D` (один получатель-подадрес) или дополнительные ключи.
5. Сдача получает деривацию `a·R`, остальные — `r·A` (или `s·C`).
6. Payment id: восьмибайтный из `extra` шифруется для единственного
   получателя; если id нет и выходов не больше двух — добавляется «пустой»
   зашифрованный id, как у wallet2.
7. `extra` в порядке `sort_tx_extra()`: ключ транзакции, дополнительные ключи,
   nonce.
8. Bulletproofs+ по всем выходам, CLSAG по каждому входу; устройство
   проверяет свои подписи перед отправкой.

## 9. Кэш key images на устройстве

`src/wallet/ki_cache.{h,c}`. На каждый кошелёк и вариант passphrase —
зашифрованный файл (AES-GCM ключом устройства) на разделе FAT `storage`:
для каждого выхода — его публичный ключ, key image, подадрес и флаги
(экспортирован, потрачен транзакцией этого устройства, сдача). При подписи:

- вход, чей key image устройство не выдавало, означает, что Feather не
  синхронизировал key images и может тратить уже потраченное: **отказ** с
  подсказкой «export ALL outputs … import the key images»;
- вход, уже потраченный ранее подписанной транзакцией, — предупреждение на
  экране перед подписью.

Кэш стирается вместе с кошельком и при сбросе устройства.

## 10. Проверено и не проверено

| Что | Как |
| :--- | :--- |
| Раскладки всех четырёх файлов, распознавание, усечение на каждой длине, границы | `test_file_formats.c` против независимого кодировщика `fx_feather.h` |
| Полный цикл: кошелёк с passphrase → выходы → key images → неподписанный набор → подписанный набор; подписи CLSAG, BP+ и баланс проверены декодером как у узла | `test_feather_flow.c` |
| Правила construct_tx (перемешивание, сдача, payment id, extra, подадреса) | `test_sign.c` |
| Файлы, сделанные настоящим Feather, и приём подписанного набора Feather | **не проверено** — в этой среде нет Feather и узла Monero; первый реальный обмен стоит сделать на stagenet |
