# Сборка в Arduino IDE

ТЗ 1.3 фиксирует среду разработки: Arduino IDE с ESP32 Core for Arduino,
LVGL 8.x/9.x, бэкенд дисплея Arduino_GFX (или LovyanGFX / TFT_eSPI),
USB-стек TinyUSB. Документ описывает процедуру для Arduino IDE 2.x.

Проверенных версий пока нет: прошивка не собрана целиком, поэтому
конкретные номера версий ниже — рекомендация, а не подтверждённая связка.

## 0. Быстрый путь: arduino-cli и sketch.yaml

В папке скетча лежит `sketch.yaml` с профилем сборки: точная версия ядра
ESP32 (3.3.11), библиотеки (`lvgl` 9.6.0, `GFX Library for Arduino` 1.6.9),
все пункты меню Tools и путь к `lv_conf.h`. Нужен только arduino-cli:

```
arduino-cli compile                 # собрать (профиль coldpunk)
arduino-cli compile -u -p COM5      # собрать и прошить
arduino-cli compile --profile coldpunk-debug   # лог ядра на уровне Info
```

При первой сборке arduino-cli сам скачает ядро и библиотеки в свой кэш; Boards
Manager, Library Manager и копия `lv_conf.h` рядом с библиотеками не нужны.
Порт — USB-UART мост платы (UART0), его показывает `arduino-cli board list`;
чтобы не писать `-p`, раскомментируйте `port:` в `sketch.yaml`. Плата
по-прежнему выбирается в `board_config.h`.

Arduino IDE 2 профили не читает — для неё разделы ниже.

---

## 1. Что поставить

| Компонент | Что именно | Где взять |
| :--- | :--- | :--- |
| Arduino IDE | 2.x | arduino.cc |
| Пакет плат | `esp32` by Espressif Systems, 3.x | Boards Manager |
| LVGL | `lvgl` by kisvegabor (8.3.x или 9.x) | Library Manager |
| Драйвер дисплея | `GFX Library for Arduino` by moononournation | Library Manager |
| TinyUSB | **не ставить отдельно** — входит в пакет `esp32` | — |

TinyUSB в ESP32 Arduino Core уже есть (`USBMSC`, `USBCDC`, `USB.h`). Ставить
внешнюю библиотеку `Adafruit TinyUSB` не нужно и вредно — получите конфликт
символов.

### Boards Manager URL

В `File → Preferences → Additional boards manager URLs`:

```
https://espressif.github.io/arduino-esp32/package_esp32_index.json
```

Затем `Tools → Board → Boards Manager…` → `esp32` → Install.

---

## 2. Настройки платы

Плата: `ESP32S3 Dev Module` (или конкретная плата вашего модуля, если она
есть в списке — тогда часть пунктов зафиксирована и недоступна).

| Пункт меню Tools | Значение | Почему |
| :--- | :--- | :--- |
| Board | ESP32S3 Dev Module | ТЗ 1.4: только S3 |
| USB CDC On Boot | **Enabled** (рекомендуется; собирается при любом значении) | `Serial` = USB CDC несёт протокол программы на ПК, консоль уходит на UART0. При Disabled протокол идёт по UART0, а консоль UART0 отключается. Таблица режимов — `usb_link_protocol.md` §1 |
| CPU Frequency | 240 MHz | Bulletproofs+ упирается в CPU |
| Core Debug Level | None (для релиза) / Info (при отладке) | лог не должен содержать секретов |
| USB DFU On Boot | Disabled | конфликтует с MSC |
| Erase All Flash Before Sketch Upload | Disabled | иначе стираются NVS и раздел `storage` с кошельками |
| Events Run On | Core 1 | — |
| Flash Mode | QIO 80MHz | — |
| Flash Size | **8MB (64Mb)** или 16MB | зависит от модуля |
| JTAG Adapter | Disabled | ТЗ 8: отладочный доступ к устройству с ключами не нужен |
| Arduino Runs On | Core 1 | `loop()` не используется под тяжёлое — см. ниже |
| USB Firmware MSC On Boot | Disabled | это отдельный встроенный MSC, не наш |
| Partition Scheme | см. раздел 4 | нужен большой app-раздел |
| PSRAM | **OPI PSRAM** или **QSPI PSRAM** | см. ниже |
| Upload Mode | UART0 / Hardware CDC | — |
| Upload Speed | 921600 | — |
| USB Mode | **USB-OTG (TinyUSB)** (рекомендуется; собирается и с Hardware CDC) | только с TinyUSB есть HID-транспорт; MSC/MTP/Floppy из проекта убраны (task2) |

### PSRAM: OPI или QSPI

Выбор определяется модулем, а не желанием:

| Модуль | PSRAM | Пункт меню |
| :--- | :--- | :--- |
| ESP32-S3-WROOM-1 **N16R8**, **N8R8** | 8 МБ octal | `OPI PSRAM` |
| ESP32-S3-WROOM-1 **N8R2**, **N4R2** | 2 МБ quad | `QSPI PSRAM` — **не годится**, нужно ≥ 8 МБ |
| ESP32-S3-WROOM-2 | octal | `OPI PSRAM` |

Неправильный выбор даёт либо «PSRAM not found», либо загрузку, при которой
`ESP.getPsramSize()` возвращает 0. Проверка в скетче:

```cpp
Serial.printf("PSRAM: %u bytes, largest block: %u\n",
              (unsigned)ESP.getPsramSize(),
              (unsigned)heap_caps_get_largest_free_block(MALLOC_CAP_SPIRAM));
```

Если наибольший непрерывный блок меньше 2 МиБ, `mw_cn_slow_hash_init()`
вернёт ошибку и открыть ни один файл обмена не получится (ключ ChaCha
выводится через `cn_slow_hash`, см. `src/crypto/chacha.h`).

Важно: при OPI PSRAM выводы GPIO 35, 36, 37 заняты шиной PSRAM и
использовать их для дисплея/тача **нельзя**. Это одна из причин, по которой
пины в `boards/es3c28p.h` отличаются от таблицы ТЗ 2.2.

---

## 3. Библиотеки и `lv_conf.h`

### Куда класть `lv_conf.h`

LVGL ищет конфиг на **уровень выше** своей папки:

```
~/Arduino/libraries/
    lv_conf.h        <-- сюда
    lvgl/
    GFX_Library_for_Arduino/
```

В `lvgl/lv_conf_template.h` есть образец: скопируйте его в
`~/Arduino/libraries/lv_conf.h`, замените первую строку `#if 0` на `#if 1`.

### Настройки `lv_conf.h`

**Готовый `lv_conf.h` лежит в корне репозитория** — скопируйте его рядом с
папкой библиотеки (`~/Arduino/libraries/lv_conf.h`) и больше ничего менять не
нужно. Он собран из `lv_conf_template.h` версии 9.6.0; ниже — что в нём
изменено и почему.

| Опция | Значение | Причина |
| :--- | :--- | :--- |
| `LV_MEM_SIZE` | `48 * 1024` | только объекты виджетов; буферы отрисовки берутся из PSRAM в `lvgl_port.cpp` |
| `LV_USE_OS` | `LV_OS_FREERTOS` | ТЗ 4.1: UI на ядре 0, крипто на ядре 1 — нужны настоящие мьютексы |
| `LV_DEF_REFR_PERIOD` | `30` мс | ≈33 FPS; ТЗ 4.1 требует ≥20 |
| `LV_USE_QRCODE` | `1` | ТЗ 3.7, 4.2: анимированный QR |
| `LV_FONT_MONTSERRAT_10…28` | `1` | размеры, которые выбирает `theme.cpp` на разрешениях от 128×64 до 480×480 |

**Что изменилось в LVGL 9 по сравнению с 8 — не переносите старые рецепты:**

- **`LV_COLOR_DEPTH` в 9.6 больше не задаётся.** `lv_conf_internal.h` выводит
  её обратно из `LV_COLOR_FORMAT_DEFAULT`, и она равна 16 и для `RGB565`, и
  для `RGB565_SWAPPED`. Явная установка вызывает предупреждение компилятора.
- **Порядок байт задаётся `LV_COLOR_FORMAT_DEFAULT`**: `LV_COLOR_FORMAT_RGB565`
  (little-endian, стоит в нашем `lv_conf.h`) либо `LV_COLOR_FORMAT_RGB565_SWAPPED`
  (big-endian).
- **`LV_COLOR_16_SWAP` задавать не нужно и не следует.** В 9.6 он остался
  только как слой совместимости с v8 и печатает предупреждение об
  устаревании. `src/hal/display.cpp` читает конфигурацию LVGL напрямую и
  выводит порядок байт сам, поэтому синхронизировать две настройки вручную
  больше не требуется — рассогласование теперь даёт ошибку компиляции
  (`static_assert`), а не молча переставленные цвета.
- `LV_MEM_CUSTOM` и `LV_TICK_CUSTOM` в 9.x не существуют: аллокатор
  выбирается через `LV_USE_STDLIB_MALLOC`, а тик подаётся из
  `lvgl_port.cpp`.

### Кириллический шрифт

Встроенные Montserrat-шрифты LVGL содержат только latin. Для ТЗ 4.1 нужен
шрифт с диапазоном U+0400–U+04FF. Варианты:

1. Онлайн-конвертер LVGL (`lvgl.io/tools/fontconverter`): указать диапазон
   `0x20-0x7F,0x400-0x4FF`, получить `.c`, положить в `src/ui/fonts/`.
2. `lv_font_conv` из npm — то же самое офлайн.

Не включайте весь Unicode: таблица глифов вырастет на сотни килобайт флеша.
Оценка размера здесь не приводится — она зависит от начертания и кегля.

---

## 4. Таблица разделов

Стандартные схемы Arduino IDE не рассчитаны на прошивку с криптоядром +
LVGL + шрифтами. Ориентир — `Huge APP (3MB No OTA/1MB SPIFFS)` или своя
таблица.

### Своя таблица разделов — это точка трения

Arduino IDE 2.x **не даёт выбрать произвольный CSV** через интерфейс. Способы:

1. **Готовая схема из списка.** Самый простой путь. `Huge APP` даёт 3 МБ на
   приложение и отключает OTA — для air-gapped устройства OTA не нужна.
2. **`partitions.csv` рядом со скетчем.** ESP32 Arduino Core 3.x подхватывает
   файл `partitions.csv` из папки скетча. Пункт меню при этом должен стоять
   в «Custom» — он появляется в списке не для всех плат.
3. **Свой вариант в `boards.txt`.** Правка
   `~/.arduino15/packages/esp32/hardware/esp32/<версия>/boards.txt` —
   работает, но затирается при обновлении пакета.

Пример таблицы под 8 МБ флеша без OTA:

```
# Name,   Type, SubType, Offset,  Size,    Flags
nvs,      data, nvs,     0x9000,  0x5000,
otadata,  data, ota,     0xe000,  0x2000,
app0,     app,  ota_0,   0x10000, 0x500000,
storage,  data, fat,     0x510000,0x2E0000,
```

Раздел `storage` типа `fat` нужен, если USB MSC/Floppy отдаёт внутренний том,
а не SD-карту (`transfer.h`: `MW_CHANNEL_USB` — «shares the SD/internal FAT
volume»).

---

## 5. Шифрование NVS — главная точка трения

ТЗ 8.1 требует:

- HMAC-ключ в eFuse (старший свободный блок, обычно `BLOCK_KEY5`; назначение
  `ESP_EFUSE_KEY_PURPOSE_HMAC_UP`),
  read-protected;
- зашифрованный NVS с `CONFIG_NVS_ENCRYPTION=y` и
  `CONFIG_NVS_SEC_HMAC_EFUSE_KEY_ID=0`.

**Это опции sdkconfig ESP-IDF, а Arduino IDE поставляет уже собранные
статические библиотеки IDF.** Изменить `CONFIG_NVS_ENCRYPTION` из Arduino IDE
нельзя. Возможные пути, честно, со всеми минусами:

| Путь | Что даёт | Чего стоит |
| :--- | :--- | :--- |
| Приложение шифрует данные само | Работает в стоковом Arduino IDE | NVS остаётся незашифрованным контейнером; защищено только содержимое записей |
| Пересобрать библиотеки IDF с нужным sdkconfig | Полное соответствие ТЗ 8.1 | Нужен `esp32-arduino-lib-builder`, ESP-IDF, час-два сборки; результат надо класть в пакет вручную |
| Перейти на ESP-IDF / PlatformIO | Всё из коробки | Противоречит ТЗ 1.3 |

В текущих заголовках выбран **первый** путь: `src/wallet/secure_storage.h`
объявляет собственное запечатывание

```c
mw_err_t mw_seal(const char* label, const uint8_t* pt, size_t pt_len,
                 uint8_t* iv16, uint8_t* tag16, uint8_t* ct, size_t ct_cap);
mw_err_t mw_unseal(const char* label, const uint8_t* ct, size_t ct_len,
                   const uint8_t* iv16, const uint8_t* tag16,
                   uint8_t* pt, size_t pt_cap);
```

— «AES-256-GCM using a key derived from the eFuse HMAC over `label`», а
`wallet_entry_t` хранит уже зашифрованный `encrypted_seed[64]` с `seed_iv[16]`
и `seed_tag[16]`. То есть seed защищён независимо от того, зашифрован ли сам
NVS. Это осознанный компромисс, а не выполнение ТЗ 8.1 дословно (см. также
`security.md`).

### Прошивка eFuse-ключа

`mw_secure_key_provision()` записывает ключ из TRNG в старший свободный блок
ключей eFuse (обычно `BLOCK_KEY5`) с назначением HMAC_UP и запрещает его
чтение. Это необратимо. Соответственно:

- вызывается один раз, при первом включении — до задания пароля; без ключа
  устройство не работает;
- после этого ключ нельзя ни прочитать, ни перезаписать — ТЗ 8.1:
  «обновление — только замена чипа»;
- проверка состояния — `mw_secure_key_status()`.

Альтернатива вне прошивки — `espefuse.py burn_key BLOCK_KEY5 key.bin HMAC_UP`
(прошивка найдёт ключ HMAC_UP в любом блоке).
Описание процедуры с точки зрения безопасности выходит за рамки этого
документа.

---

## 2a. Какие интерфейсы обмена собирать

Каждый способ обмена с ПК можно исключить из прошивки целиком. Настройки —
в `src/config/app_config.h` (или флагом сборки `-DMW_USE_SERIAL=0` и т. п.):

| Настройка | По умолчанию | Что это | Кто пользуется |
| :--- | :---: | :--- | :--- |
| `MW_USE_SERIAL` | 1 | протокол mwlink через `Serial`: USB CDC при *CDC On Boot = Enabled*, иначе UART0 | `mwlink --serial`, терминалы |
| `MW_USE_HID` | 1 | протокол mwlink через USB HID (нужен *USB Mode = USB-OTG*) | MoneroPunkSigner, `mwlink` (по умолчанию) |
| `MW_USE_SD` | 1 | обмен файлами на microSD — только на платах с `HAS_SD 1` | — |

Правила:

- Выключенный интерфейс не компилируется: нет кода, ничего не слушает,
  в ответе INFO он не объявляется.
- Хотя бы один должен остаться. Если выключены все (или SD выключен, а у
  платы нет других), сборка останавливается на `#error` в
  `src/hal/display_drivers.h`.
- `MW_USE_SERIAL 0`: UART0 всегда отдаётся под текстовый лог. Чтобы COM-порт
  не появлялся вовсе, поставьте ещё *USB CDC On Boot = Disabled* — тогда на
  USB виден только HID. Готовый профиль arduino-cli: `coldpunk-hid`.
- `MW_USE_HID 1` без TinyUSB (*USB Mode = Hardware CDC and JTAG*) HID не даёт;
  если при этом `MW_USE_SERIAL 0`, сборка предупреждает: USB-связи не будет.
- `MW_USE_SD 0` на Touch-LCD-2 (карта на общей с дисплеем шине) возвращает
  дисплею отдельную, более быструю шину SPI.
- Прошивка по USB выполняется загрузчиком в ROM чипа и от этих настроек не
  зависит.

Типовые варианты:

| Вариант | SERIAL | HID | SD | CDC On Boot |
| :--- | :---: | :---: | :---: | :--- |
| Всё (по умолчанию, профиль `coldpunk`) | 1 | 1 | 1 | Enabled |
| Только HID, без COM-порта (профиль `coldpunk-hid`) | 0 | 1 | 1 | Disabled |
| Без USB-обмена, только SD-карта | 0 | 0 | 1 | Disabled |
| Без SD | 1 | 1 | 0 | Enabled |

## 2b. Хэш коммита в About

«Настройки → About» и лог загрузки показывают, из какого коммита собрана
прошивка: `commit c50033e`, с `-dirty`, если были незакоммиченные изменения.
Хэш берётся из `src/config/build_commit.h` (в `.gitignore`), его пишут git-хуки
из `.githooks/` после каждого коммита, checkout, merge и rebase. Включить один
раз в своей копии репозитория:

```
git config core.hooksPath .githooks
sh .githooks/update-build-commit
```

Git for Windows выполняет хуки своим `sh`, так что это работает и в Windows, и
для Arduino IDE (заголовок лежит в исходниках). Без хуков About показывает
`commit unknown`. Время сборки не вшивается намеренно: один и тот же коммит
даёт один и тот же бинарный файл (воспроизводимая сборка).

## 6. Выбор платы для сборки

Автоопределения нет (ТЗ 2.1). Плата выбирается на этапе компиляции —
подключением нужного файла из `boards/`. Способ:

```cpp
// в главном .ino, до любых включений проекта
#include "../boards/es3c28p.h"
```

или через флаг компилятора, если вы используете `platform.local.txt`:

```
build.extra_flags=-DMW_BOARD_HEADER="\"../boards/es3c28p.h\""
```

Проверка того, что подключилось, — во время выполнения через
`mw_hal_caps()->board_name` (`src/hal/hal.h`).

Добавление своей платы — `boards/README.md`.

---

## 7. Порядок инициализации в `setup()`

Порядок задан ТЗ 8.2 и комментариями в заголовках:

```cpp
void setup() {
    mw_random_init();        // ТЗ 8.2: ПЕРВЫМ. bootloader_random_enable() + selftest
    mw_hal_init();           // clocks, PSRAM, TRNG, display, inputs
    mw_cn_slow_hash_init();  // 2 МиБ PSRAM резервируем сразу
    mw_bpp_init();           // генераторы Bulletproofs+ в PSRAM
    mw_settings_load(&settings);
    mw_wallet_store_init();
    mw_ui_init();
    // создать задачи UI (core 0) и crypto (core 1) по константам app_config.h
}
```

`mw_random_init()` возвращает `mw_rng_status_t`; `MW_RNG_ERR_SELFTEST` или
`MW_RNG_ERR_STUCK` должны приводить к отказу работать, а не к предупреждению.

---

## 8. Типичные грабли

| Симптом | Причина | Что делать |
| :--- | :--- | :--- |
| `PSRAM not found` / `getPsramSize()` = 0 | выбран QSPI вместо OPI или наоборот | сверить с маркировкой модуля (N16R8 → OPI) |
| `mw_cn_slow_hash_init()` возвращает −1 | нет 2 МиБ непрерывного PSRAM | вызывать до всего остального; проверить `heap_caps_get_largest_free_block(MALLOC_CAP_SPIRAM)` |
| Скетч не влезает во флеш | схема разделов по умолчанию | `Huge APP` или своя таблица |
| Нет HID-устройства, только COM-порт | `USB Mode` = `Hardware CDC and JTAG` — TinyUSB не линкуется | поставить `USB-OTG (TinyUSB)`; протокол по COM-порту работает и так |
| Нет COM-порта на USB | `USB CDC On Boot` = Disabled — `Serial` ушёл на UART0 | включить, либо подключать программу к UART0 через USB-UART |
| COM-порт есть, но устройство не отвечает | собрано с `MW_USE_SERIAL 0` (§2a) | подключаться по HID (`mwlink` без `--serial`) или собрать с `MW_USE_SERIAL 1` |
| MoneroPunkSigner: «HID device not found» | собрано с `MW_USE_HID 0` или `USB Mode` = Hardware CDC | §2a; `USB Mode` = USB-OTG |
| Нет пункта «SD card files» | у платы `HAS_SD 0` или собрано с `MW_USE_SD 0` | §2a |
| Ошибка сборки «No exchange interface» | выключены все интерфейсы | включить хотя бы один (§2a) |
| Нет консоли на UART0 | `USB CDC On Boot` = Disabled — UART0 занят протоколом | включить CDC On Boot; лог всё равно виден в консоли программы на ПК |
| Windows показывает устройство с ошибкой после смены набора интерфейсов | кэш дескрипторов по VID/PID | удалить устройство в Диспетчере устройств и переподключить |
| Порт исчезает после прошивки | USB переключился в MSC | перевести в загрузчик: удерживая BOOT, нажать RESET |
| Нет Serial-вывода | `USB CDC On Boot` = Disabled | включить |
| После перепрошивки пропали кошельки | `Erase All Flash Before Sketch Upload` = Enabled | выключить |
| Цвета инвертированы / переставлены байты | `LV_COLOR_FORMAT_DEFAULT` | переключить между `LV_COLOR_FORMAT_RGB565` и `LV_COLOR_FORMAT_RGB565_SWAPPED` (не `LV_COLOR_16_SWAP` — он устарел) |
| Windows не видит новый файл на MSC | кэш SCSI | `mw_usb_media_changed()` — Unit Attention 0x28/0x00 (ТЗ 3.3) |
| Кириллица — «прямоугольники» | шрифт без диапазона U+0400 | сконвертировать шрифт с кириллицей |
| Дисплей чёрный на GPIO 35–37 | эти пины заняты OPI PSRAM | перенести на другие GPIO |
| `TOUCH_INT` и `CAM_PIN_SIOC` конфликтуют | в таблице ТЗ 2.2 оба = 39 | см. комментарий в `boards/es3c28p.h` |
| Watchdog при подписи | тяжёлый счёт в `loop()` / задаче UI | считать на криптозадаче, `MW_CRYPTO_TASK_CORE` = 1 |
| Переполнение стека криптозадачи | `mw_transaction_t` на стеке | размещать в куче/PSRAM, см. `architecture.md` §3 |
| Wi-Fi/BT внезапно линкуются | включён `MW_ENABLE_WIFI`/`MW_ENABLE_BT` | `app_config.h` выдаёт `#error` — так и задумано (ТЗ 8.4) |

---

## 9. Сборка хостовых тестов

Тесты собираются обычным `gcc` и Arduino IDE для них не нужен:

```
cd tools/test
make run
```

Подробности — `testing.md`.
