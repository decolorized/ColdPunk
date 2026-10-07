# UI layer — screens, keyboards and layout rules

LVGL user interface of the Monero cold wallet (TZ section 4 and 5).
Everything below is implemented in `src/ui/`; no screen contains a
board-specific `#ifdef` and no screen contains a hardcoded user-visible
string.

> **Status: UNCOMPILED.** There is no LVGL, no ESP32 core and no `arduino-cli`
> in the environment this layer was written in. It has been checked by
> inspection and syntax-checked against hand-written LVGL 8 and LVGL 9 API
> stubs (`g++ -std=c++17 -fsyntax-only -Wall -Wextra`, clean), but it has
> never been built against the real library or run on hardware. See
> "Not verified" at the end.

---

## 1. File map

| File | Contents |
| :--- | :--- |
| `lvgl_port.cpp` | `lv_init`, display + touch + keypad drivers, tick source, draw buffer, the cross-task call queue, screen routing, settings cache |
| `theme.h` / `theme.cpp` | dark palette, the resolution-adaptive `mw_metrics_t`, shared styles, LVGL 8/9 compatibility macros |
| `i18n.c` | RU/EN string tables (the frozen `mw_str_id_t` plus the extended `mw_xstr_id_t`) |
| `screen_common.h/.cpp` | page & overlay frame, status bar, list/button helpers, `mw_ui_confirm/message/progress`, chooser, full-text viewer |
| `keyboard.h` | shared keyboard model and layout hooks |
| `keyboard_full.cpp` | the model + type 1 "full keyboard" + `mw_kb_run()` |
| `keyboard_scroll.cpp` | type 2 "scroll keyboard" |
| `screen_main.cpp` | neutral root background, boot screen |
| `screen_menu.cpp` | the generic menu page (main menu, wallet list, wallet menu) with the wake signal |
| `screen_game.cpp` | the Minesweeper start screen (LVGL view) |
| `game_model.c/.h` | Minesweeper rules, input state machine, layout (pure C, host-tested) |
| `screen_seed.cpp` | dice entropy, seed display, seed verification |
| `screen_passphrase.cpp` | the TZ 5.2 passphrase flow (creation) and the single entry when opening a wallet |
| `screen_tx.cpp` | transaction review and confirmation |
| `screen_qr.cpp` | animated QR display, camera viewfinder |
| `screen_settings.cpp` | the settings screen, persisted via `mw_settings_save()` |
| `flows.cpp` | the device shell `mw_shell_run()`: game, password, menus, create/import, files and requests from the PC |

---

## 2. Threading (TZ 4.1)

Two tasks matter:

* **LVGL task**, core 0, loops on `mw_ui_tick()`. It is the *only* task that
  may call `lv_*` or dereference an `lv_obj_t`. Every `*_build` function,
  every `lv_event_cb_t` and every `lv_timer_cb_t` runs here.
* **Crypto task**, core 1, runs `mw_shell_run()` (`flows.cpp`): the game, the
  password, the menus and every operation. It owns the secrets and never
  touches LVGL.

The bridge is four primitives in `lvgl_port.cpp`:

```
mw_ui_async_call(fn, arg)   post a job, return immediately
mw_ui_sync_call(fn, arg)    post a job, return when it has run
mw_ui_modal_call(fn, arg)   post a job, block until an LVGL callback calls
                            mw_ui_modal_done(result)   -> returns that result
mw_ui_modal_done(result)    called ON the LVGL task, releases the waiter
```

`mw_ui_confirm()`, `mw_ui_message()`, `mw_ui_progress()`, `mw_kb_run()` and
every `mw_screen_*_run()` are built on those, which is why they are the only
UI entry points a flow may use. `mw_ui_progress()` is asynchronous so a tight
signing loop is never stalled by a repaint.

The UI task registers itself (`mw_ui_task_register()`) before its first tick
and `setup()` calls `mw_ui_task_expect()` before creating it: until then
another task waits instead of driving LVGL. The old "whoever ticks first is
the UI task" rule let the crypto task adopt itself when its first dialog came
before the UI task had ticked (task 3 item 0).

**Restriction:** a modal helper must not be called from the LVGL task while
that task is running — it would need a nested `lv_timer_handler()`, which LVGL
refuses to re-enter. The single legal nested use is during boot, before the
LVGL task exists (the firmware's `fatal()` path relies on it).

### Screen budget

At most **two** LVGL screens exist at any moment: the root screen loaded by
`mw_ui_show()` plus at most one *page* on top of it. Every
`mw_screen_*_run()` creates its page, waits, and destroys it before
returning, so pages never nest. Dialogs (`confirm`, `message`, `progress`,
chooser, full-address viewer) are **overlays** — full-screen containers on the
active screen — so they nest safely without adding a screen.

Page teardown is asynchronous (`lv_obj_delete_async`) because it is routinely
called from inside an event callback of a widget on that very screen.

Autolock: the UI task calls `mw_ui_autolock_tick()` once a second; after the
configured idle time it sets the lock request and calls `mw_ui_cancel_modal()`,
which closes whatever dialog the crypto task waits on (every modal builder
registers its own cancel with `mw_ui_modal_set_cancel()`; pages fall back to
`mw_ui_page_cancel_active()`). While the request is pending every new modal
returns "cancelled" at once, so the flows unwind to the shell, which locks.

`mw_ui_show()` replaces the root screen only when it is what the display
shows. It used to delete "the active screen" - with a dialog open that was the
dialog itself, and the crypto task waited for it forever (the task 3 item 0
"menu clicks do nothing" bug: setup()'s `mw_ui_show()` ran while the first
password dialog was up).

---

## 3. Resolution adaptivity (TZ 4.1)

All geometry comes from one struct, `mw_metrics_t`, computed once in
`theme.cpp` from `mw_hal_caps()`. Nothing outside `theme.cpp` looks at the raw
resolution.

| | 128x64 mono | 240x240 | 240x320 | 320x480 | 480x480 |
| :--- | ---: | ---: | ---: | ---: | ---: |
| tier | TINY | SMALL | MEDIUM | LARGE | XLARGE |
| pad / gap | 1 / 1 | 4 / 4 | 4 / 4 | 6 / 6 | 8 / 8 |
| list row height | 12 | 44 | 46 | 52 | 56 |
| button height | 12 | 44 | 46 | 52 | 56 |
| status bar | none | 22 | 24 | 28 | 30 |
| title | 10 | 24 | 26 | 30 | 32 |
| fonts (small/body/title/mono) | 8/10/10/8 | 12/14/18/12 | 12/14/18/14 | 14/18/24/14 | 14/18/24/18 |
| key cap (w x h) | 21x8 | 40x28 | 40x34 | 53x48 | 80x43 |
| candidate grid | 1 x 2 | 2 x 1 | 2 x 2 | 2 x 2 | 2 x 2 |
| visible scroll letters | 5 | 4 | 4 | 5 | 5 |
| keyboard footer row | no | no | no | yes | yes |

Rules encoded in `build_metrics()`:

* On colour panels `row_h` and `btn_h` are clamped to **>= 40 px**, the TZ 4.1
  minimum touch target. Menus, lists, dialog buttons and the scroll keyboard's
  caps all use those, so every *primary* target is >= 40x40.
* Key caps are always `panel_width / 6`, so six caps fill the panel exactly:
  40 px on a 240 px screen, 80 px on a 480 px one.
* Key cap height is whatever the header, prefix row, candidate grid and footer
  leave over, divided by five, clamped to `[8, cap_width]`.
* **Deliberate deviation:** on 240x240 and 240x320 the *full keyboard's* caps
  come out 40x28 and 40x34 — 40 px wide but under 40 px tall. Six columns and
  five rows plus a candidate list simply do not fit 240 px of height at 40 px
  per row. The scroll keyboard is the alternative there (its caps are
  `row_h` tall, i.e. >= 40) and both are selectable in Settings.
* The key grid scrolls inside its container when it does not fit (128x64).
  LVGL scrolls a freshly focused object into view, so the button cursor drags
  the grid along; on 320x480 and 480x480 nothing ever scrolls.
* Monochrome panels get a two-ink palette, square corners and 1 px borders
  instead of fills; the layout code is identical.

---

## 4. Fonts and Cyrillic (TZ 4.1)

The built-in Montserrat faces cover Latin-1 only, so Russian renders as boxes
without a generated face. `theme.h` declares the faces `extern` and
`theme.cpp` raises a `#warning` when they are absent and falls back to
`lv_font_montserrat_*`.

Generate them with the LVGL font converter:

```sh
npm i -g lv_font_conv

# One command per size: 12, 14, 18, 24.
lv_font_conv \
  --font NotoSans-Regular.ttf \
      --range 0x20-0x7F \
      --range 0x400-0x45F \
  --font FontAwesome5-Solid+Brands+Regular.woff \
      --range 0xF00B,0xF00C,0xF00D,0xF011,0xF013,0xF019,0xF021,0xF053,0xF054,\
0xF067,0xF06E,0xF074,0xF07B,0xF093,0xF0F3,0xF11C,0xF15B,0xF240,0xF241,0xF242,\
0xF243,0xF244,0xF287,0xF2ED,0xF304,0xF55A,0xF7C2,0xF8A2 \
  --size 14 --bpp 4 --format lvgl --lv-include lvgl.h \
  --no-compress -o mw_font_ru_14.c
```

`lv_font_conv` derives the C symbol from the output file name, so the four
files define `mw_font_ru_12`, `mw_font_ru_14`, `mw_font_ru_18`,
`mw_font_ru_24` — exactly the names `theme.h` declares.

Ranges:

* `0x20-0x7F` — ASCII;
* `0x400-0x45F` — Cyrillic, which covers `Ё` (0x401), `ё` (0x451) and all of
  А–я used by `i18n.c`;
* the Font Awesome code points above are the LVGL symbols this UI actually
  draws:

| Code point | LVGL name | Used by |
| :--- | :--- | :--- |
| F00B | `LV_SYMBOL_LIST` | main menu "Кошельки" |
| F00C | `LV_SYMBOL_OK` | keyboard accept cap |
| F00D | `LV_SYMBOL_CLOSE` | keyboard `[✕]` |
| F011 | `LV_SYMBOL_POWER` | autolock row, "no battery gauge" |
| F013 | `LV_SYMBOL_SETTINGS` | main menu |
| F019 | `LV_SYMBOL_DOWNLOAD` | "Импортировать кошелёк" |
| F021 | `LV_SYMBOL_REFRESH` | Minesweeper "new game" |
| F053 / F054 | `LV_SYMBOL_LEFT` / `RIGHT` | scroll keyboard arrows, candidate paging |
| F067 | `LV_SYMBOL_PLUS` | "Создать кошелёк" |
| F06E | `LV_SYMBOL_EYE_OPEN` | tx recipient row, brightness row |
| F074 | `LV_SYMBOL_SHUFFLE` | network row |
| F07B | `LV_SYMBOL_DIRECTORY` | wallet rows |
| F093 | `LV_SYMBOL_UPLOAD` | (unused since task 3) |
| F0F3 | `LV_SYMBOL_BELL` | language row |
| F11C | `LV_SYMBOL_KEYBOARD` | layer cap, keyboard-type row |
| F15B | `LV_SYMBOL_FILE` | "Об устройстве" |
| F240–F244 | `LV_SYMBOL_BATTERY_*` | status bar |
| F287 | `LV_SYMBOL_USB` | status bar, USB mode row |
| F2ED | `LV_SYMBOL_TRASH` | delete wallet, device reset |
| F304 | `LV_SYMBOL_EDIT` | touch calibration row |
| F55A | `LV_SYMBOL_BACKSPACE` | keyboard `⌫` |
| F7C2 | `LV_SYMBOL_SD_CARD` | status bar, SD rows |
| F8A2 | `LV_SYMBOL_NEW_LINE` | keyboard `↵` |

Drop the four `.c` files into the sketch folder and build with
`-DMW_UI_HAS_CYRILLIC_FONT=1`. Without it the firmware still builds and runs;
set the language to English in Settings.

---

## 5. Screens

### 5.1 Start-up (task 3)

The crypto task runs `mw_shell_run()` (`flows.cpp`); every screen below is a
page run from it. The root screen is only a neutral background
(`screen_main.cpp`), it never names the wallet.

```
 power on / lock / autolock
        │
        ▼
 Minesweeper ──(explode, then tap the exploded mine 3× within 2 s)──► password
        ▲                                                             │ cancel
        └─────────────────────────────────────────────────────────────┘
                                    │ ok (first start: set it, twice)
                                    ▼
                               main menu
```

### 5.2 Minesweeper — `screen_game.cpp` (task 3 item 7)

> v5 (2026-10-01): this section is superseded by section 10 below.

```
┌──────────────────────────────┐
│ Сапёр         Мин: 11  F  ↻  │
│ ┌──┬──┬──┬──┬──┬──┬──┬──┐    │
│ │  │ 1│  │  │  │  │  │  │    │   one lv_buttonmatrix for the board
│ ├──┼──┼──┼──┼──┼──┼──┼──┤    │   (the 48 KiB LVGL heap would not
│ │  │  │ *│ ✕│  │  │  │  │    │   hold 80 buttons with labels)
│ └──┴──┴──┴──┴──┴──┴──┴──┘    │
└──────────────────────────────┘
```

Tap reveals, long press or the F mode flags, ↻ starts over; the first reveal
never hits a mine. After an explosion three taps on the ✕ cell within two
seconds leave the game. On button boards the matrix is in the focus group.

### 5.3 Menus — `screen_menu.cpp`

One generic page (`mw_ui_menu_run`) serves the main menu, the wallet list and
the wallet menu: title, optional dim subtitle and footnote, rows with icons,
optional Back button. The list is made non-scrollable when it fits, and the
touch indev has a 16 px scroll threshold, so a tap with a little jitter stays
a click (the "click does nothing" report of task 3 item 0 had a different
root cause - see `lvgl_port.cpp` - but this removes a second way to lose a
click).

| Menu | Rows |
| :--- | :--- |
| main | Кошельки · Настройки · Заблокировать |
| wallets | one row per wallet (`*` = has a passphrase variant) · Создать · Импортировать · Назад |
| wallet | Адрес · Адрес (QR) · Private view key · Private view key (QR) · Переименовать · Удалить · [Закрыть кошелёк] |

The wallet menu is run with `wake`: a file or request from the PC bumps
`mw_ui_wake()`, the menu returns `MW_MENU_WAKE`, the shell handles the event
(confirmation, progress, result) and shows the menu again.

Opening a wallet with a passphrase variant asks for it once
(`mw_screen_passphrase_open_run`): empty opens the base wallet, a wrong one is
reported.

### 5.4 Create wallet — TZ 4.2, 6.5

`mw_flow_create_wallet()` is the TZ 6.5 script, in order:

1. wallet name (free-text keyboard);
2. seed format — 25-word Monero legacy or 16-word Polyseed;
3. entropy source — TRNG (with `mw_random_selftest()`) or dice;
4. dice screen, if chosen;
5. seed display for writing down;
6. **passphrase (always, TZ 5.2)**;
7. verification by partial re-entry;
8. `mw_wallet_create()` + set active;
9. the derived primary address, so it can be checked against the online
   wallet, optionally as a QR code.

Every buffer — entropy, seed material, polyseed struct, indices, passphrase,
derived keys — is wiped with `mw_memzero()` on every exit path, success and
failure alike, and the session is locked.

#### Dice entropy — TZ 6.4

```
┌──────────────────────────────┐
│                  SD USB  85% │
│ Кубики (d6)                  │
│ Бросьте кубик и нажмите      │
│ выпавшее число               │
│ Бросков: 37 из 100           │
│ ███████░░░░░░░░░░░░░░░       │
│ ~95 бит энтропии             │
│   [1]   [2]   [3]            │
│   [4]   [5]   [6]            │
│ [Отменить] [Готово] [Отмена] │
└──────────────────────────────┘
```

100 throws are required before "Готово" leaves the disabled state; the bit
counter uses log2(6) = 2.585 bits per throw in Q8 fixed point
(`MW_DICE_BITS_PER_ROLL_Q8`). The throws are folded into 32 bytes with
PBKDF2-HMAC-SHA512, 2048 rounds, salt `"Monero dice entropy"` (TZ 6.4). Six
faces are laid out 3x2, or 6x1 on panels at least 320 px wide.

#### Seed display

```
┌──────────────────────────────┐
│ Слова 1-5 из 25              │
│ Запишите seed-фразу на       │
│ бумаге. Никогда не           │
│ фотографируйте её.           │
│ ┌──────────────────────────┐ │
│ │  1. abandon              │ │
│ │  2. ability              │ │
│ │  3. able                 │ │
│ │  4. about                │ │
│ │  5. above                │ │
│ └──────────────────────────┘ │
│ [← Назад]         [Далее →]  │
└──────────────────────────────┘
```

Words per page are derived from the mono font's `line_height` and the space
left between the title and the footer, capped at 12. On the last page "Далее"
becomes "Готово" and a confirmation asks whether the phrase really was written
down. There is **no masking** — TZ 5.3 removed it.

#### Verification

Three distinct word positions are drawn from the TRNG (rejection sampling,
sorted ascending) and typed back on the dictionary keyboard. A mismatch is
reported and the whole check restarts, up to three attempts.

### 5.5 Import wallet — TZ 4.2, 5.7, 5.8

1. seed format;
2. word-by-word entry with `allow_back` from the second word on. A word that
   is not in the dictionary is rejected with "Слово N отсутствует в словаре"
   and asked again; `MW_KB_BACK` steps one word back and `MW_KB_RESTART`
   (very long Back) clears the whole phrase;
3. checksum / Polyseed RS code (TZ 5.8) — failure shows
   "Неверная контрольная сумма seed-фразы";
4. **passphrase (always)**;
5. restore height for legacy seeds (Polyseed derives it from its birthday);
6. wallet name, then `mw_wallet_create()` and the address for checking.

### 5.6 Passphrase — TZ 5.2 / 5.9

```
┌──────────────────────────────┐
│                  SD USB  85% │
│ Passphrase                   │
│ Passphrase запрашивается     │
│ всегда. Он не сохраняется    │
│ на устройстве.               │
│ [   Ввести passphrase    ]   │
│ [   Без passphrase       ]   │  amber border - the exceptional choice
│ [   Отмена               ]   │
└──────────────────────────────┘
```

The rules, implemented literally in `screen_passphrase.cpp`:

1. the screen is shown **always**, after every seed entry and before every key
   derivation — there is no code path that skips it;
2. "Без passphrase" needs **two** confirmations: one explaining the
   consequence (`STR_PASSPHRASE_NONE_CONFIRM`) and one asking again
   (`XSTR_PASSPHRASE_EMPTY_Q`);
3. a non-empty passphrase is typed **twice** and compared with
   `mw_ct_equal()`; a mismatch shows "Passphrase не совпадают" and restarts
   the entry;
4. an empty string typed twice still counts as "no passphrase" and still needs
   the double confirmation;
5. `mw_session_wipe_input()` runs on success, on cancel, on mismatch and on
   error; the second copy lives in a local buffer wiped with `mw_memzero()`;
6. the first entry goes into the session scratch buffer, so `out` must be a
   *different* buffer — flows pass their own.

### 5.7 Transaction review — TZ 4.2, 12.3

> v5 (2026-10-01): this section is superseded by section 10 below.

```
┌──────────────────────────────┐
│                  SD USB  85% │
│ Подписать                    │
│ Всего к отправке 1.500000000 │
│ Комиссия        0.000030800  │
│ Сдача           0.240000000  │
│ Входов          2            │
│ Выходов         2            │
│ ┌──────────────────────────┐ │
│ │ o 1/2  48aBcdef...xyz89  │ │
│ │        1.000000000000    │ │
│ │ o 2/2  4Adefghi...uvw12  │ │
│ │        0.500000000000    │ │
│ └──────────────────────────┘ │
│ [Отмена]         [Подписать] │
└──────────────────────────────┘
```

TZ 12.3 requires every output with its recipient address. The list is
scrollable and holds one row per destination with the shortened address and
the amount; selecting a row opens the **full** address in a scrollable
overlay:

```
┌──────────────────────────────┐
│ Получатель 1 из 2            │
│ Сумма: 1.000000000000        │
│ Полный адрес                 │
│ ┌──────────────────────────┐ │
│ │ 48aBcdefghijklmnopqrstuv │ │
│ │ wxyz0123456789ABCDEFGHIJ │ │
│ │ KLMNOPQRSTUVWXYZabcdefgh │ │
│ │ ...                      │ │
│ └──────────────────────────┘ │
│          [Закрыть]           │
└──────────────────────────────┘
```

`mw_tx_check_balance()` runs **before** the screen is drawn; a mismatch shows
"Баланс не сходится" and the flow aborts without ever offering to sign. The
focus ring starts on "Отмена" — "Подписать" is never pre-selected. Unlock
time is shown when it is non-zero. TZ 12.4: a set with more than one
transaction is refused.

### 5.8 Files from the PC — task 3

There is no "sync key images" / "sign transaction" menu item any more: the
wallet menu reacts to what the PC sends.

| PC sends | Device shows | Result for the PC |
| :--- | :--- | :--- |
| outputs export | "Сгенерировать key images для N выходов? (уже известны: M)" → progress | key image export |
| unsigned tx set | per transaction the review screen of 5.7 (and a warning first when inputs were spent by an earlier signed tx) → progress | signed tx set |
| REQ address | "ПК запрашивает адрес кошелька. Отправить?" | JSON with the address |
| REQ view-only | the view key warning + a typed four-digit code | JSON with the address and the private view key |

A refused file shows "Файл отклонён" with the headline and the technical
reason (also sent to the PC log). Unlike the old batch screen, a key image
export stops at the first output that is not ours: a partial export would make
the online wallet's balance silently wrong.

### 5.9 QR display and scan — TZ 3.7, 4.2

```
Display                          Scan
┌────────────────────────────┐   ┌────────────────────────────┐
│ Транзакция подписана       │   │ Сканирование QR            │
│ ██▀▀██▄▄██▀▀██             │   │ ┌────────────────────────┐ │
│ ██▄▄██▀▀██▄▄██             │   │ │       viewfinder       │ │
│ ██▀▀██▄▄██▀▀██             │   │ └────────────────────────┘ │
│ Часть 3 из 7               │   │ ██████░░░░░░░░  47%        │
│ [Пауза] [Готово] [Отмена]  │   │ Наведите камеру на QR-код  │
└────────────────────────────┘   │         [Отмена]           │
                                 └────────────────────────────┘
```

Frames advance every 80 ms (12.5 FPS, TZ 3.7) from `mw_ur_encoder_next()`.
The code is always drawn black on white inside its own white frame, whatever
the UI theme is. The widget needs `LV_USE_QRCODE`; without it the screen says
so instead of showing a blank square.

The scanner is driven from the **caller's** task, which is the only owner of
`mw_camera_*`: capture -> decode -> `mw_ur_decoder_receive()` -> preview into
the canvas buffer -> ask the LVGL task to invalidate it. Image-to-string
decoding is not part of the HAL; the backend, if one is linked, supplies

```c
int mw_qr_decode_frame(const mw_camera_frame_t*, char* out, size_t cap);
```

which is declared **weak**, so a firmware without a decoder still links and
the screen reports "Модуль QR не собран в прошивке". `mw_screen_qr_scan_run()`
is what `mw_transfer_receive(MW_CHANNEL_QR, ...)` should call to drive the
scanner (declared in `ui/screen_common.h`).

### 5.10 Settings — TZ 4.2

```
┌──────────────────────────────┐
│                  SD USB  85% │
│ Настройки                    │
│ ┌──────────────────────────┐ │
│ │ Режим USB: MSC (флешка)  │ │
│ │ Тип клавиатуры: Полная   │ │
│ │ Яркость: 80%             │ │
│ │ Автоблокировка: 5 мин    │ │
│ │ Калибровка сенсора       │ │
│ │ Форматировать SD         │ │
│ │ Язык: Русский            │ │
│ │ Сеть: Mainnet            │ │
│ │ Об устройстве            │ │
│ │ Сброс устройства         │ │
│ └──────────────────────────┘ │
│          [← Назад]           │
└──────────────────────────────┘
```

The screen is a loop of single modals — pick a row, handle it, rebuild — so
modals never nest. Every change goes through `mw_ui_settings_store()`, i.e.
`mw_settings_save()`, and the user is told it was saved. Brightness gets a
live slider that applies immediately and rolls back on cancel. Touch
calibration and SD format rows only appear when the board has the hardware.
Device reset needs two confirmations before `mw_factory_reset()`.

---

## 6. Keyboards — TZ 5.4

> v5 (2026-10-01): this section is superseded by section 10 below.

Both types are implemented, both drive the **same** model
(`keyboard_full.cpp`), and both work under **both** input methods.

### 6.1 Type 1 — full keyboard

Touch panels >= 240x240:

```
┌──────────────────────────────┐
│  Слово 5 из 25     [✕]       │
├──────────────────────────────┤
│  Префикс:  ab_               │
├──────────────────────────────┤
│  ┌──────────┐ ┌──────────┐   │
│  │ abandon  │ │ ability  │   │
│  └──────────┘ └──────────┘   │
│  ┌──────────┐ ┌──────────┐   │
│  │ able     │ │ about    │   │
│  └──────────┘ └──────────┘   │
├──────────────────────────────┤
│  [A] [B] [C] [D] [E] [F]     │
│  [G] [H] [I] [J] [K] [L]     │
│  [M] [N] [O] [P] [Q] [R]     │
│  [S] [T] [U] [V] [W] [X]     │
│  [Y] [Z] [⌫] [↵] [◄] [►]     │
├──────────────────────────────┤
│  [← Назад]      [Очистить]   │
└──────────────────────────────┘
```

128x64, button control:

```
┌────────────────────────────────┐
│ Слово 5/25  Префикс: ab_       │
├────────────────────────────────┤
│ ▶ abandon                      │
│   ability                      │
├────────────────────────────────┤
│ [A] [B] [C] [D] [E] [F]        │
│ [G] [H] [I] [J] [K] [L]        │
│ [M] [N] [O] [P] [Q] [R]        │
│ [S] [T] [U] [V] [W] [X]        │
│ [Y] [Z] [⌫] [↵] [◄] [►]        │
└────────────────────────────────┘
```

The grid is a fixed 6x5 = 30 cells on every resolution — 26 characters plus
four command caps — so the mock-up holds everywhere and only the cap size
changes. Cells 26..29 are `⌫`, then either `↵`/`⌨`, `◄`, `►`:

| Cell | Dictionary mode | Free-text mode |
| :--- | :--- | :--- |
| 26 | backspace | backspace |
| 27 | `↵` accept the first candidate | `⌨` cycle layer (abc / ABC / 123 / #+=) |
| 28 | `◄` previous candidate page, or previous word when the prefix is empty | space |
| 29 | `►` next candidate page | `↵` finish |

The footer row (`[← Назад] [Очистить] [Готово]`) is only built when the panel
is tall enough (320x480 and up); on shorter panels its functions live on the
caps and on the long-press gestures.

### 6.2 Type 2 — scroll keyboard

Touch panels:

```
┌──────────────────────────────┐
│  Слово 5 из 25     [✕]       │
├──────────────────────────────┤
│  Префикс:  ab_               │
├──────────────────────────────┤
│  ┌──────────┐ ┌──────────┐   │
│  │ abandon  │ │ ability  │   │
│  └──────────┘ └──────────┘   │
│  ┌──────────┐ ┌──────────┐   │
│  │ able     │ │ about    │   │
│  └──────────┘ └──────────┘   │
├──────────────────────────────┤
│   ◄   [ A ][ B ][ C ][ D ]  ►│
│         (свайп влево/вправо) │
├──────────────────────────────┤
│  [⌫] [⌨] [Space] [↵]         │
├──────────────────────────────┤
│  [← Назад]      [Очистить]   │
└──────────────────────────────┘
```

128x64, button control:

```
┌────────────────────────────────┐
│ Слово 5/25  Префикс: ab_       │
├────────────────────────────────┤
│ ▶ abandon                      │
│   ability                      │
├────────────────────────────────┤
│   ◄  A  B  C  D  E  ►          │
├────────────────────────────────┤
│ [⌫] [↵] [◄] [►]                │
└────────────────────────────────┘
```

The letter strip is one horizontally scrollable, centre-snapping LVGL
container. A touch user swipes it (or taps the `◄`/`►` caps); a button user
walks it with Left/Right and `lv_obj_scroll_to_view()` follows. It is the
same object either way — there is no second code path. `metrics.scroll_visible`
(3..5) decides how many caps fit, so the caps stay large.

### 6.3 Input methods

**Touch.** Every cap, every candidate and every footer button is a clickable
`lv_button`. Dead keys have `LV_OBJ_FLAG_CLICKABLE` removed as well as being
greyed out, so a mis-tap cannot enter an impossible letter.

**Six buttons (TZ 5.6).** The keyboards install a raw button hook
(`mw_ui_set_button_hook()`); while it is installed `lvgl_port.cpp` feeds the
keypad indev nothing and the hook sees every edge with its hold time. LVGL's
one-dimensional group navigation is not enough for a 6x5 grid, so the
keyboards move a 2-D cursor themselves and call `lv_group_focus_obj()` to move
the focus ring:

| | full keyboard | scroll keyboard |
| :--- | :--- | :--- |
| Left / Right | move one cell, wrapping to the previous/next row | scroll the strip to the previous/next **live** letter (dead letters are skipped) |
| Up / Down | move one row; Up from the top key row enters the candidate grid, Down from the bottom candidate row returns to the keys | move between the candidate list, the strip and the special row |
| Select | enter the focused letter, or accept the focused candidate | same |
| Back — tap | backspace; with an empty prefix and `allow_back`, step to the previous word | same |
| Back — long (>= 600 ms) | clear the prefix | same |
| Back — very long (>= 2000 ms) | clear the whole phrase (`MW_KB_RESTART`) | same |

Every other screen uses plain `lv_group` navigation instead: Up/Down map to
`LV_KEY_PREV`/`LV_KEY_NEXT`, Select to `LV_KEY_ENTER`, Back to `LV_KEY_ESC`,
with auto-repeat on the arrows. An encoder, when present, feeds the same
focus movement.

### 6.4 Word logic — TZ 5.7

1. The user types 1–3 letters.
2. `mw_wordlist_prefix_matches()` fills the candidate grid; `◄`/`►` page it
   when there are more matches than cells.
3. Tapping or selecting a candidate accepts the word and the flow advances.
4. A fully typed word that is the only candidate is accepted automatically.
5. `mw_wordlist_next_letters()` returns the 26-bit set of letters that can
   still extend the prefix; everything outside it is greyed out and made
   unclickable, and the scroll keyboard skips over it while stepping.

In `MW_KB_MODE_FREE_TEXT` (passphrase, wallet name, restore height) there is
no dictionary at all: four layers — `abcdefghijklmnopqrstuvwxyz`,
`ABCDEFGHIJKLMNOPQRSTUVWXYZ`, `1234567890-_=+[]{};:'",.?/` and
`!@#$%^&*()\`~<>\\|` plus space — cycled by the `⌨` cap, with arbitrary
length up to `MW_KB_TEXT_MAX` (128 bytes).

### 6.5 Buffers — TZ 5.10

The keyboard runs a 1 Hz `lv_timer`; after `MW_INPUT_TIMEOUT_MS` (5 minutes)
without a keypress it calls `mw_session_wipe_input()`, wipes its own prefix
and text buffers and aborts the input. Every exit path — accept, cancel, back,
restart, timeout — wipes both buffers with `mw_memzero()`, and `mw_kb_run()`
wipes them once more after the modal returns in case the page was torn down
by the autolock path.

`mw_kb_run()` carries two extra outcomes in its `mw_err_t` return:
`MW_KB_BACK` (-19) for "previous word" and `MW_KB_RESTART` (-20) for "clear
the whole phrase". Both are their own values in `mw_err_t`
(`src/monero/monero_types.h`), deliberately **not** aliases of existing error
codes: the wordlist layer can legitimately return `MW_ERR_FORMAT`, and reading
that as "the user asked to restart" would silently wipe a phrase the user had
already typed.

---

## 7. TZ 4.2 coverage

| TZ 4.2 screen | `mw_screen_id_t` | Implementation |
| :--- | :--- | :--- |
| Главное меню + индикаторы | `MW_SCREEN_MAIN_MENU` | `screen_main.cpp`, status bar in `screen_common.cpp` |
| Экран выбора кошелька | `MW_SCREEN_WALLET_LIST` | `screen_wallets.cpp` |
| Создание кошелька | `MW_SCREEN_WALLET_CREATE` | `flows.cpp` + `screen_seed.cpp` + `screen_passphrase.cpp` |
| Ввод бросков кубиков | `MW_SCREEN_DICE` | `screen_seed.cpp` |
| Отображение seed | `MW_SCREEN_SEED_DISPLAY` | `screen_seed.cpp` |
| Верификация seed | `MW_SCREEN_SEED_VERIFY` | `screen_seed.cpp` |
| Ввод seed | `MW_SCREEN_SEED_INPUT` | `keyboard_full.cpp` / `keyboard_scroll.cpp` |
| Импорт кошелька | `MW_SCREEN_WALLET_IMPORT` | `flows.cpp` |
| Passphrase | `MW_SCREEN_PASSPHRASE` | `screen_passphrase.cpp` |
| Просмотр транзакции | `MW_SCREEN_TX_REVIEW` | `screen_tx.cpp` |
| Синхронизация key images | `MW_SCREEN_KEYIMAGE_SYNC` | `screen_keyimage.cpp` |
| Экран QR-кода | `MW_SCREEN_QR_DISPLAY` | `screen_qr.cpp` |
| Экран сканирования | `MW_SCREEN_QR_SCAN` | `screen_qr.cpp` |
| Настройки | `MW_SCREEN_SETTINGS` | `screen_settings.cpp` |
| Прогресс / сообщение | `MW_SCREEN_PROGRESS`, `MW_SCREEN_MESSAGE` | overlays in `screen_common.cpp` |
| Загрузка | `MW_SCREEN_BOOT` | `screen_main.cpp` |

---

## 8. Memory

* Draw buffer: 1/10 of the panel, whole rows, RGB565. Taken from PSRAM with
  `heap_caps_malloc(MALLOC_CAP_SPIRAM)` when the board has any; otherwise a
  static array sized from `board_config.h` at compile time (7680 px = 15 KiB
  for 240x320). A panel larger than the configured one simply gets a shorter
  partial buffer and LVGL renders in more, smaller chunks.
* Monochrome panels still render RGB565 and are thresholded inside
  `mw_display_blit()`, so the port stays driver-agnostic; the cost on 128x64
  is 1.6 KiB.
* Transaction, signature and export structures are far too large for a task
  stack, so `flows.cpp` takes them from PSRAM first (`big_alloc()`), wipes
  them with `mw_memzero()` and frees them on every exit path including the
  error ones.
* At most two screens are alive at a time; dialogs are overlays.

---

## 9. Not verified

Written and reviewed, **never compiled against the real LVGL and never run**:

1. No build against the actual LVGL library (8.x or 9.x), the ESP32 Arduino
   core, or `arduino-cli`. The syntax check used hand-written API stubs, so
   **exact LVGL signatures are unverified** — in particular
   `lv_obj_set_flex_grow`, `lv_obj_scroll_to_view`, `lv_canvas_set_buffer`,
   `lv_qrcode_*`, `lv_theme_default_init`, `lv_display_set_buffers` and the
   LVGL 8 `lv_disp_drv_t` / `lv_indev_drv_t` fields.
2. Enum names that LVGL 9.2+ renamed with compatibility defines are used in
   their classic spelling and may need updating on newer LVGL:
   `LV_LABEL_LONG_WRAP`, `LV_LABEL_LONG_DOT`, `LV_SCROLL_SNAP_CENTER`,
   `LV_SCROLLBAR_MODE_OFF`.
3. `lv_qrcode` is assumed to be reachable from `lvgl.h` on both 8.x
   (`extra/libs/qrcode`) and 9.x (`src/libs/qrcode`); no explicit include is
   made.
4. No rendering has been seen. Every layout number in section 3 is arithmetic
   from `theme.cpp`, not a screenshot. The 128x64 layouts in particular are at
   the edge of what fits and will need trimming on real hardware.
5. Touch coordinates are passed through from `mw_touch_read()` unchanged; the
   calibration coefficients stored by the settings screen are applied by the
   HAL, not here. Untested.
6. The FreeRTOS handshake (queue depth, semaphore timeouts, the recursive LVGL
   lock, the modal frame stack) is reasoned about but never exercised under
   concurrency.
7. Cyrillic rendering depends on a font that does not exist in the repository.
8. `mw_qr_decode_frame()` has no implementation anywhere in the project, so
   QR scanning cannot work until a decoder backend is linked.
9. `mw_transfer_receive(MW_CHANNEL_QR, ...)` is expected to call
   `mw_screen_qr_scan_run()`; that wiring lives in the transfer module and is
   not part of this layer.

---

## 10. v5 changes (2026-10-01)

### 10.1 Resolution tiers and landscape
- Tiers come from the SHORT side: TINY (mono or short<=128), SMALL (240x240), MEDIUM (240x320 and 320x240), LARGE (short<=360, e.g. 320x480), XLARGE (480x480).
- Fonts small/body/title/mono: TINY 10/12/12/10, SMALL and MEDIUM 12/14/16/12, LARGE 16/20/24/16, XLARGE 18/24/28/24.
- Rows, buttons, keyboard header buttons and seed candidates are at least 40 px on colour panels (32 on 240x240).
- `mw_metrics()->landscape` is w > h. `mw_theme_button_fixed()` gives the button look at an exact size (key caps, candidates, pad cells).
- ES3C28P now defaults to landscape 320x240 (rotation 1).

### 10.2 Full keyboard
- Header row: [Back] [caption or "Word N of M"] [X clears the input, touch only]. No footer.
- The typed-text line has its own row and always shows the END of the input ("..." plus the last characters).
- Done is the check key (seed words: first candidate) or the enter key (free text).
- Key size is measured from the room left: width = content width / columns, height = room / rows, at most 1.5x the width.
- Grids: QWERTY 10x3; ABC 6x5 in portrait, 8x4 in landscape. ABC gives the largest keys in both orientations (landscape 39x42, portrait 38x49); portrait QWERTY stays 23x34 (10 columns in 232 px).
- The space key is labelled "|_|".
- Scroll keyboard: the strip shows 3-5 whole letters snapped left; caps are 1.5x the row height.

### 10.3 PIN pad, QR, menus
- PIN pad: always 1 2 3 / 4 5 6 / 7 8 9 / bksp 0 OK. Landscape: hint, number and Cancel on the left, pad on the right.
- QR: landscape puts the code on the left at full content height (202 px static, 186 px animated at 320x240); portrait static code >= 200 px at 240x320.
- Menus become scrollable when the rows do not fit beside the subtitle, footnote and footer; every row is reachable.
- Page titles are one line; a long title ends in "...".

### 10.4 Minesweeper
- A tap reveals on release; a long press (~0.4 s) flags without revealing; F switches taps to flag mode.
- Button boards: arrows move the outlined selection, SELECT taps, a long SELECT flags, Back toggles flag mode.
- After a loss: the exploded mine is red with a white X, other mines dark red with '*' (mono: white on black).
- Unlock: 3 taps on the X within 2 s. A hold never counts; a tap elsewhere resets the count. No other way out of the game.
- Cells are at least max(32, btn_h-4) px on touch; landscape puts the controls in a right column (8x5 cells of 37 px at 320x240, 6x7 of 38 px at 240x320).
- The game is a decoy, not a security boundary (docs/security.md).

### 10.5 Transaction review
- One scrolling column above a fixed Cancel / Sign footer: Total sent, Fee, Change (amount or "none"), Inputs / outputs, "N dummy output(s), 0 XMR" for sweeps.
- One row per recipient; this wallet's own addresses get the HOME icon and "this wallet M/m".
- When there is change: a row "Change -> this wallet M/m" with the shortened address (encoded from device-derived keys, always (subaddr_account, 0)) and the amount. In landscape it is one scroll below the first recipient.
- Tapping a row opens the full address; own and change rows add "Belongs to this wallet: account M, index m".
- A fee above 0.01 XMR or above 10% of the amount moved needs a second "High fee" confirmation (focus on Cancel).
- Refusals (hybrid addresses, change not to (acct,0), claimed change not paid, wrong subaddress flags, inputs from several accounts) are explained on screen and in the PC log. See docs/security.md.

### 10.6 Settings and unlock
- Capacitive boards show "Touch test" (crosses, a dot under the reported point, a raw -> xy label) instead of "Touch calibration"; calibration remains only for XPT2046. Touch coordinates are logged only while this page is open with debug log on.
- Change password verifies the old password first, re-asks only the new one on mismatch, and checks for a running delay before anything is typed.
- After unlock: "Failed attempts since last unlock: N" when N > 0, and "The previous run crashed (operation, stage)" after a crash reset.
