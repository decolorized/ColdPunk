# Добавление новой платы

Автоопределение платы не используется (ТЗ 2.1). Конфигурация задаётся
вручную файлом `board_config.h` и фиксируется на этапе компиляции.

---

## 1. Что нужно от платы

Обязательный минимум (ТЗ 1.4):

| Требование | Проверка |
| :--- | :--- |
| Чип ESP32-S3 | S2/C3/классический ESP32 не подходят |
| PSRAM ≥ 8 МБ | нужен непрерывный блок 2 МиБ для `cn_slow_hash` |
| Аппаратный USB OTG | для MSC/MTP; есть у всех S3 |
| eFuse + модуль HMAC | для запечатывания seed |
| TRNG | есть у всех S3 |

Минимальное разрешение экрана — **128×64** (ТЗ 5.6). На таком экране
доступна только прокручиваемая клавиатура с кнопочным управлением.

Камера и кнопки опциональны. Тач опционален — без него обязательны кнопки.

---

## 2. Порядок действий

1. Скопировать `boards/es3c28p.h` в `boards/<имя>.h`.
2. Заменить `BOARD_NAME`.
3. Заполнить пины и флаги (структура — ниже).
4. Подключить файл в сборке (см. `docs/build_arduino.md`, раздел 6).
5. Проверить по чек-листу из раздела 6 этого документа.

Структура файла жёстко задана ТЗ 2.2 — не добавляйте и не переименовывайте
поля произвольно: HAL рассчитывает на эти имена.

---

## 3. Секции `board_config.h`

### Заголовок

```c
#ifndef BOARD_CONFIG_H
#define BOARD_CONFIG_H

#include "../src/config/app_config.h"

#define BOARD_NAME "MYBOARD"
```

`app_config.h` подключается ради `SEED_INPUT_AUTO` / `SEED_INPUT_FULL_KB` /
`SEED_INPUT_SCROLL_KB`.

### Display

```c
#define DISPLAY_DRIVER   DISPLAY_ILI9341
#define DISPLAY_WIDTH    240
#define DISPLAY_HEIGHT   320
#define DISPLAY_ROTATION 0
#define TFT_CS           10
#define TFT_DC            9
#define TFT_RST           8
#define TFT_MOSI         11
#define TFT_MISO         13
#define TFT_SCK          12
#define TFT_BL           14
#define TFT_BL_ACTIVE_HIGH 1
```

Допустимые значения `DISPLAY_DRIVER` (`src/hal/hal.h`):

| Константа | Значение | Разрешения (ТЗ 2.3) |
| :--- | ---: | :--- |
| `DISPLAY_ILI9341` | 1 | 240×320 |
| `DISPLAY_ST7789` | 2 | 240×240, 240×320 |
| `DISPLAY_ST7701S` | 3 | 480×480 |
| `DISPLAY_GC9A01` | 4 | 240×240 (круглый) |
| `DISPLAY_ILI9488` | 5 | 320×480 |
| `DISPLAY_SSD1306` | 6 | 128×64, монохром |
| `DISPLAY_SH1106` | 7 | 128×64, монохром |

`DISPLAY_ROTATION` — 0..3. `DISPLAY_WIDTH`/`DISPLAY_HEIGHT` задают размер
**после** поворота: при нечётном повороте экран альбомный, ширина больше
высоты (иначе `display.cpp` не соберётся, а после `begin()` в лог пишется
ошибка, если Arduino_GFX сообщает другой размер). Пример ES3C28P: портрет —
`240/320/0`, альбом с USB слева — `320/240/1`, с USB справа — `320/240/3`.

Для монохромных панелей (`SSD1306`, `SH1106`) в `mw_hal_caps()` должно
выставляться `monochrome = true`; интерфейс у них I²C, поэтому поля
`TFT_MOSI`/`TFT_SCK` интерпретируются как SDA/SCL — это должен учитывать
драйвер в HAL.

### Touch

```c
#define HAS_TOUCH        1
#define TOUCH_DRIVER     TOUCH_FT6336G
#define TOUCH_SDA        17
#define TOUCH_SCL        18
#define TOUCH_INT        16
#define TOUCH_RST        15
```

| Константа | Значение | Интерфейс (ТЗ 2.4) |
| :--- | ---: | :--- |
| `TOUCH_NONE` | 0 | — |
| `TOUCH_FT6336G` | 1 | I²C |
| `TOUCH_FT6236` | 2 | I²C |
| `TOUCH_CST816S` | 3 | I²C |
| `TOUCH_GT911` | 4 | I²C |
| `TOUCH_XPT2046` | 5 | SPI (резистивный) |

Для `XPT2046` пины `TOUCH_SDA`/`TOUCH_SCL` — это MOSI/SCK его SPI-шины;
`TOUCH_INT` — IRQ, `TOUCH_RST` обычно `-1`. Резистивный тач требует
калибровки: `mw_touch_calibrate(int32_t coeffs[6])`, результат сохраняется в
`mw_settings_t.touch_calib[6]` / `touch_calibrated` вместе с меткой геометрии
(поворот, размер, версия карты) в зарезервированных байтах 37..39 настроек.
Калибровка, снятая при другой геометрии, при загрузке отбрасывается.

Ёмкостные контроллеры (FT6336G, FT6236, CST816S, GT911) не калибруются и
сохранённую матрицу не применяют. Их точки проходят через
`src/hal/touch_map.c`: сначала флаги платы в осях стекла (`TOUCH_SWAP_XY`,
затем `TOUCH_MIRROR_X` / `TOUCH_MIRROR_Y`), затем обратный поворот
`DISPLAY_ROTATION` (таблица MADCTL Arduino_GFX). Размер стекла по умолчанию —
размер панели при повороте 0; другой задаётся `TOUCH_NATIVE_W/H`. Для ES3C28P
поворот 1 и 3 подтверждён конфигурацией ESPHome этой платы
(github.com/jvduuren/esphome-es3c28p-light-panel), подробности —
`boards/README.md`, раздел «Touch orientation».

Проверка на устройстве: Настройки → «Проверка сенсора». Точка должна быть
под пальцем на всех пяти крестиках. В повороте 1: зеркально слева направо —
`TOUCH_MIRROR_Y 1`, сверху вниз — `TOUCH_MIRROR_X 1`, оси перепутаны —
`TOUCH_SWAP_XY 1`. При включённом отладочном логе координаты пишутся в лог
только пока открыта эта страница (нажатие и отпускание).

При `HAS_TOUCH 0` все четыре пина ставятся в `-1`.

### SD

```c
#define HAS_SD           1
#define SD_CS            21
#define SD_MISO          13
#define SD_MOSI          11
#define SD_SCK           12
```

SD может делить SPI-шину с дисплеем — так сделано в `es3c28p.h`
(«shares the display SPI bus»). Тогда `SD_MOSI`/`SD_SCK`/`SD_MISO`
совпадают с `TFT_*`, различается только CS. При общей шине доступ к SD и к
дисплею должен быть сериализован — это задача HAL.

Без SD (`HAS_SD 0`) остаётся обмен через USB и QR; при этом для USB MSC
нужен внутренний FAT-раздел (`docs/build_arduino.md`, раздел 4).

### Camera

```c
#define HAS_CAMERA       1
#define CAM_PIN_PWDN     -1
#define CAM_PIN_RESET    -1
#define CAM_PIN_XCLK     10
#define CAM_PIN_SIOD     40
#define CAM_PIN_SIOC     39
#define CAM_PIN_D7 .. CAM_PIN_D0
#define CAM_PIN_VSYNC    36
#define CAM_PIN_HREF     35
#define CAM_PIN_PCLK     34
```

Камера нужна только для приёма QR (`MW_CHANNEL_QR`, ТЗ 3.7). Без неё
устройство по-прежнему может **показывать** анимированный QR, но не
сканировать.

Параллельный интерфейс DVP занимает 13–16 выводов и легко конфликтует с
дисплеем, SD и шиной PSRAM. Проверяйте конфликты вручную — см. раздел 6.

**В `src/hal/hal.h` нет функций работы с камерой.** Есть только флаг
`mw_hal_caps()->has_camera`. Контракт драйвера камеры на момент написания
документа не зафиксирован; см. `docs/compliance_matrix.md`, раздел 3.7.

### Buttons

```c
#define HAS_BUTTONS      0
#define BUTTON_UP        -1
#define BUTTON_DOWN      -1
#define BUTTON_LEFT      -1
#define BUTTON_RIGHT     -1
#define BUTTON_SELECT    -1
#define BUTTON_BACK      -1
#define BUTTON_ENCODER_A -1
#define BUTTON_ENCODER_B -1
```

Шесть кнопок по ТЗ 2.5: Вверх / Вниз / Влево / Вправо / Выбор / Назад.
Энкодер опционален и заменяет Влево/Вправо (ТЗ 5.6). Соответствующие
значения в HAL — `mw_button_t` (`MW_BTN_UP` … `MW_BTN_BACK`);
`mw_buttons_read()` возвращает битовую маску, где номер бита равен значению
`mw_button_t`, `mw_encoder_read()` — дельту с прошлого вызова (0, если
энкодера нет).

**Правило:** `HAS_TOUCH 0` и `HAS_BUTTONS 0` одновременно — неработоспособная
конфигурация. Хотя бы одно устройство ввода обязано быть.

### Feature flags

```c
#define HAS_PSRAM        1
#define PSRAM_SIZE_MB    8
#define HAS_HMAC         1
#define HAS_USB_OTG      1
```

`HAS_PSRAM 0` или `PSRAM_SIZE_MB < 8` означает, что `cn_slow_hash` не
запустится и ни один файл обмена открыть не удастся. Такая плата не
поддерживается.

### Режим ввода по умолчанию

```c
#define DEFAULT_SEED_INPUT_MODE  SEED_INPUT_AUTO
```

| Значение | Поведение |
| :--- | :--- |
| `SEED_INPUT_AUTO` | правило ТЗ 5.5 (ниже) |
| `SEED_INPUT_FULL_KB` | всегда полная клавиатура |
| `SEED_INPUT_SCROLL_KB` | всегда прокручиваемая |

Правило AUTO (ТЗ 5.5, реализуется `mw_settings_default_keyboard()`):

| Условие | Результат |
| :--- | :--- |
| `HAS_TOUCH 0` | `KEYBOARD_SCROLL` |
| `HAS_TOUCH 1` и разрешение ≥ 240×240 | `KEYBOARD_FULL` |
| `HAS_TOUCH 1` и разрешение < 240×240 | `KEYBOARD_SCROLL` |

Применяется один раз при первом запуске; дальше выбор пользователя из
настроек хранится в NVS и имеет приоритет.

---

## 4. Отражение в `mw_hal_caps()`

HAL обязан заполнить структуру из `src/hal/hal.h` по макросам платы:

| Поле `mw_hal_caps_t` | Источник |
| :--- | :--- |
| `width`, `height` | `DISPLAY_WIDTH`, `DISPLAY_HEIGHT` |
| `rotation` | `DISPLAY_ROTATION` |
| `monochrome` | `DISPLAY_DRIVER` ∈ {`SSD1306`, `SH1106`} |
| `has_touch` | `HAS_TOUCH` |
| `has_buttons` | `HAS_BUTTONS` |
| `has_encoder` | `BUTTON_ENCODER_A >= 0` |
| `has_sd` | `HAS_SD` |
| `has_camera` | `HAS_CAMERA` |
| `has_usb` | `HAS_USB_OTG` |
| `has_psram` | `HAS_PSRAM` |
| `psram_size_mb` | `PSRAM_SIZE_MB` |
| `board_name` | `BOARD_NAME` |

UI обязан читать возможности отсюда, а не из макросов, чтобы экраны не
зависели от конкретной платы.

---

## 5. Специфика ESP32-S3 по выводам

Это источник большинства ошибок в новом `board_config.h`.

| Выводы | Почему нельзя / осторожно |
| :--- | :--- |
| GPIO 26–32 | шина встроенного SPI-флеша, недоступны |
| GPIO 33–37 | заняты при **octal (OPI) PSRAM** — на модулях N8R8/N16R8 |
| GPIO 19, 20 | USB D−/D+; при USB OTG заняты |
| GPIO 0 | strapping (BOOT), подтянут |
| GPIO 45, 46 | strapping (VDD_SPI, boot mode) — не использовать для входов с подтяжкой |
| GPIO 43, 44 | UART0 TX/RX, нужны для прошивки |
| GPIO 39–42 | JTAG, если он используется |

Практический вывод: на модуле с OPI PSRAM (а он нужен для 8 МБ) свободных
пинов заметно меньше, чем кажется по даташиту. Таблица пинов в ТЗ 2.2
составлена для классического ESP32 и на S3 неприменима — об этом прямо
сказано в комментарии `boards/es3c28p.h`:

> section 2.2 lists classic-ESP32 pin numbers (TFT_MOSI 23, TFT_SCK 18,
> TOUCH_SDA 21 ...) while section 1.4 mandates ESP32-S3. Those pins do not
> exist or are strapping pins on the S3, and CAM_PIN_SIOC 39 collides with
> TOUCH_INT 39.

---

## 6. Чек-лист перед первой сборкой

Конфликты:

- [ ] ни один GPIO не назначен дважды разным функциям (кроме намеренно общей
      SPI-шины дисплея и SD, где различается только CS);
- [ ] используемые пины не входят в 26–32;
- [ ] при OPI PSRAM не используются 33–37;
- [ ] при USB OTG не используются 19, 20;
- [ ] `TOUCH_INT` не совпадает с `CAM_PIN_SIOC` (типовая ошибка из ТЗ 2.2);
- [ ] strapping-пины (0, 45, 46) не заняты входами с внешней подтяжкой.

Согласованность:

- [ ] `HAS_TOUCH 1` → все `TOUCH_*` заданы; `0` → все `-1`;
- [ ] `HAS_SD 1` → все `SD_*` заданы;
- [ ] `HAS_CAMERA 1` → все `CAM_PIN_D0..D7`, `VSYNC`, `HREF`, `PCLK`,
      `XCLK`, `SIOD`, `SIOC` заданы;
- [ ] `HAS_BUTTONS 1` → заданы как минимум UP/DOWN/SELECT/BACK;
- [ ] `HAS_TOUCH` или `HAS_BUTTONS` — хотя бы одно = 1;
- [ ] `DISPLAY_WIDTH`/`HEIGHT` соответствуют реальной панели и таблице
      ТЗ 2.3;
- [ ] `PSRAM_SIZE_MB` ≥ 8.

Проверка на живом устройстве:

- [ ] `mw_hal_caps()->board_name` печатает ожидаемое имя;
- [ ] `ESP.getPsramSize()` ≥ 8 МБ;
- [ ] `heap_caps_get_largest_free_block(MALLOC_CAP_SPIRAM)` ≥ 2 МиБ до
      инициализации LVGL;
- [ ] `mw_cn_slow_hash_init()` возвращает 0;
- [ ] `mw_random_init()` возвращает `MW_RNG_OK`;
- [ ] дисплей показывает изображение без сдвига и с правильными цветами
      (иначе `LV_COLOR_16_SWAP`);
- [ ] тач попадает в точку (иначе калибровка);
- [ ] SD монтируется, `mw_sd_present()` = true;
- [ ] устройство определяется по USB в выбранном режиме.

---

## 7. Конфигурации без сенсора

ТЗ 2.5: LVGL работает без `indev`, навигация эмулируется через `lv_group`.

Практически:

- фокус перемещается кнопками Вверх/Вниз (или энкодером);
- Влево/Вправо — перемещение по буквам клавиатуры;
- Выбор — активация, Назад — удаление символа;
- долгое «Назад» очищает префикс, очень долгое — всю фразу (ТЗ 5.6).

Минимальный экран 128×64 монохромный. На нём умещается только
прокручиваемая клавиатура — макеты в ТЗ 5.4.

---

## 8. Внесение платы в репозиторий

Если вы добавляете плату в проект:

1. Файл `boards/<имя>.h` со структурой ТЗ 2.2 и комментарием-шапкой:
   что за плата, какой модуль S3, какая PSRAM (OPI/QSPI), откуда взята
   распиновка.
2. Если пины отличаются от документации производителя — объяснить почему,
   как это сделано в `es3c28p.h`.
3. Отметить, что проверено на живом железе, а что нет. Непроверенная плата
   должна быть помечена как непроверенная.
