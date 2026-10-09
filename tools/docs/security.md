# Security model

Monero Cold Wallet — ESP32-S3, air-gapped signer.
Covers TZ sections 5.2, 7.2, 8.1–8.4.

This document describes what the device protects, what it does not protect,
how the key hierarchy is built, and the exact one-shot procedure that burns the
hardware root key. Read the **Known limitations** section before trusting this
device with a balance you cannot afford to lose.

---

## 1. Threat model

The device is an **air-gapped signer**. It never has a network stack compiled
in (`app_config.h` refuses to build if `MW_ENABLE_WIFI` or `MW_ENABLE_BT` is
defined), so the only inputs are the USB link to the PC (mwlink) and, on
ES3C28P and Touch-LCD-2, Feather files on a microSD card. What leaves
it is key images, signed transactions and, only on a request confirmed on the
device, the address or the private view key (to the PC, or - "View key to SD
card", ES3C28P and Touch-LCD-2 - as a text file on the card).

### 1.1 What an attacker **cannot** do

| Attacker capability | Outcome |
| --- | --- |
| Reads the SPI flash off the board (chip-off, flash dumper) | Sees only NVS pages. With flash encryption + NVS encryption enabled, they are ciphertext. Even without flash encryption they see the **sealed** seed blobs: AES-256-GCM under a key that only exists inside the eFuse. |
| Copies the flash image onto an identical ESP32-S3 | The clone has a different (or unburned) eFuse key block. `esp_hmac_calculate()` produces a different per-label key, the GCM tag check fails, and `mw_unseal()` returns `MW_ERR_DECRYPT`. No seed is recovered. |
| Runs arbitrary firmware on the original chip | Cannot read the eFuse key: it is read-protected and only reachable by the HMAC peripheral. The attacker can still *use* the HMAC peripheral to unseal, so this is only stopped by secure boot — see limitations. |
| Edits the wallet directory in NVS (swaps records, renumbers ids, flips ciphertext bits) | Fails closed. The sealing label is `mw.seed.v1.<wallet id>`, so moving a record to another id changes the key; any bit flip breaks the 128-bit GCM tag. |
| Steals the device while it is locked | The session holds no keys: `mw_session_lock()` zeroes `mw_session_t.keys` and the passphrase buffer. Unsealing again requires nothing from the user — but deriving usable keys requires the **passphrase**, which is never stored (TZ 5.2). |
| Observes the device on a network | There is no network. |
| Recovers a deleted wallet's seed from the directory blob | `mw_wallet_delete()` overwrites the record (random, random, zero — each committed) before dropping the slot. |

### 1.2 What an attacker **can** do

* **Physical access plus your passphrase = your coins.** The passphrase is the
  last line of defence. See §3.
* **Physical access plus an unlocked device = your coins.** Autolock
  (`mw_session_expired()`, TZ 4.2) limits the window; the default is 5 minutes.
* **Glitching / fault injection.** The ESP32-S3 has no countermeasures worth
  the name. A determined, well-equipped attacker with the chip in hand and
  unlimited attempts should be assumed to win.
* **Reading PSRAM.** See limitations — keep secrets out of it.
* **Replacing the firmware** (no secure boot by default), then asking the HMAC
  peripheral to unseal everything. The passphrase still stands between them and
  the spend key, which is exactly why TZ 5.2 makes it mandatory.
* **Shoulder-surfing the seed or the passphrase while it is typed.**
* **Supply-chain attacks** on a device you did not provision yourself.

---

## 2. Key hierarchy

```
  eFuse BLOCK_KEYn  (32 bytes, purpose HMAC_UP, READ-PROTECTED, WRITE-PROTECTED;
                     n = the highest free block at provisioning, see §4)
        |
        |  esp_hmac_calculate(HMAC_KEYn, label)      <- runs inside the HMAC
        |  == HMAC-SHA256(efuse_key, label)             peripheral; the key is
        v                                               never in CPU-visible RAM
  per-label AES-256 key  (32 bytes, lives in one stack frame, wiped on exit)
        |
        |  AES-256-GCM, random 128-bit IV, 128-bit tag, no AAD
        v
  sealed blob  ->  encrypted NVS  ->  (optionally) encrypted flash
```

* **Root key** — an eFuse key block (`BLOCK_KEY5` on a fresh chip). Burned
  once (§4), never readable again.
  It is also the key ESP-IDF uses to protect the NVS encryption keys when
  `CONFIG_NVS_SEC_HMAC_EFUSE_KEY_ID=0`, so one burn covers both jobs.
* **Per-label key** — `HMAC(root, label)`. Labels are namespaced strings:
  `mw.seed.v1.<08x wallet id>` for wallet seeds. Distinct labels give
  cryptographically independent keys, so one compromised blob does not help
  against another, and a record cannot be replayed into a different wallet slot.
* **Sealed seed record** — always exactly 64 bytes of plaintext:

  ```
  legacy / raw keys:  [0..31] material            [32..63] random padding
  polyseed (v2):      [0] record version = 2
                      [1] payload length
                      [2..]  serialized polyseed (header + secret)
                      rest   random padding
  ```

  (Version-1 polyseed records had `[0]` = secret length and no birthday or
  features; `payload_from_plain()` recognises them by that byte and refuses
  them with `MW_ERR_VERSION` instead of misreading them.)

  Constant length means `wallet_entry_t.encrypted_seed[64]` is always full and
  the ciphertext does not leak whether a wallet is a 25-word legacy seed or a
  16-word Polyseed.
* **Account keys** — derived on demand by `mw_seed_to_keys(type, seed, len,
  passphrase)`. They exist only inside `mw_session_t` and only while the device
  is unlocked.

### 2.0.1 Wallet payload types

The sealed plaintext is always exactly 64 bytes. Its layout is **implied by
`wallet_entry_t.wallet_type`** — only polyseed, whose secret genuinely varies in
length, carries a length byte. Everything the payload does not occupy is random
padding, so the ciphertext leaks neither the payload length nor the wallet kind.

| `wallet_type` | `[0..31]` | `[32..63]` | Key derivation on load |
| --- | --- | --- | --- |
| 0 — legacy | 32-byte Monero seed | random padding | `mw_seed_to_keys(LEGACY, …, passphrase)` |
| 1 — polyseed | `[0]` = record version 2, `[1]` = length, then the serialized polyseed | random padding | `mw_seed_to_keys(POLYSEED, …, passphrase)` |
| 2 — raw keys (TZ 4.2 import) | spend **secret** | random padding | spend as stored, view = `Hs(spend)` |
| 3 — raw view-only | view **secret** | **public** spend key | view as stored, `pub.spend` as stored, `view_only = true` |

Types 2 and 3 have no seed, so **no passphrase is folded in** — the imported
scalars are final.

`mw_wallet_create_from_keys()` enforces:

* every secret scalar must be canonical (`mw_sc_check`) and non-zero;
* with a spend secret, a supplied view key must equal `Hs(spend)` and a supplied
  public spend key must equal `spend·G`, else `MW_ERR_KEY_MISMATCH`;
* **view-only requires both the private view key and the public spend key.**
  Either one missing is `MW_ERR_INVALID_ARG`. Without the public spend key the
  account's address cannot be computed at all, so a "view key only" wallet would
  be useless;
* the public spend key must pass `mw_point_check_public()` — on the curve, in
  the prime-order subgroup, and not the identity — else `MW_ERR_SUBGROUP`. It is
  re-validated on every load, even though GCM already authenticated it.

> **Return-convention trap (TZ 8.3).** `mw_point_check_public()`,
> `mw_point_is_valid()` and `mw_point_in_main_subgroup()` return a **boolean**:
> `1` means the point passed. They are *not* `mw_err_t`, where `0` means success.
> Writing `if (mw_point_check_public(p) == MW_OK)` inverts the test and silently
> accepts every malicious point, including small-order ones. The correct form is
> `if (!mw_point_check_public(p)) { reject; }`. The test suite pins this with an
> actual order-8 point.

**A view-only wallet can neither sign nor compute key images** — both need the
private spend key. `mw_wallet_load_keys()` marks this two ways so either check
catches it: `keys.view_only` is set **and** `keys.sec.spend` is left all-zero.
Signing and key-image sync must both refuse early on that basis.

### 2.1 Why a seal on top of encrypted NVS

NVS encryption protects the flash image. It does **not** bind a record to its
wallet id, does not survive a partial page recovery, and is unavailable on some
Arduino-core builds (§6.2). The GCM seal adds authentication, per-record key
separation and a fail-closed path that does not depend on the NVS layer being
configured correctly.

### 2.2 AES-GCM implementation

`src/crypto/aes_gcm.c` is a self-contained AES-256-GCM:

* The S-box is computed as `x^254` in GF(2^8) followed by the FIPS-197 affine
  map — **no lookup tables**, so there is no cache-timing signal.
* GHASH uses the bitwise shift-and-mask algorithm — no tables, no branches on
  secret data.
* The key schedule branches only on the round index, never on key material.
* Tag comparison goes through `mw_ct_equal()` (constant time). On a mismatch
  the output buffer is wiped before returning `MW_ERR_DECRYPT`; the caller
  never sees unauthenticated plaintext.
* Verified against the AES-256 GCM test vectors (McGrew–Viega / NIST SP 800-38D
  test cases 13–18), a GMAC case, a 16-byte-IV case and the FIPS-197 Appendix
  C.3 block vector. See `test/test_wallet_store.c`.
* `MW_AES_GCM_USE_MBEDTLS` switches the device build to mbedTLS (hardware AES).
  The portable path stays the reference and is what the host tests exercise.

---

## 3. Passphrase policy (TZ 5.2) — and why it is mandatory

**The device always asks for a passphrase after a seed is entered**, even if the
answer is "none".

Rules enforced by the UI and the session layer:

1. The passphrase prompt is **unconditional** after seed entry — creation and
   import alike.
2. An empty passphrase requires an **explicit** "No passphrase" button plus a
   confirmation dialog. It cannot be reached by pressing OK on an empty field.
3. The passphrase is entered **twice** and must match (typo protection — a typo
   here silently creates a different wallet).
4. Any character is allowed, any length. `mw_session_input_buffer()` provides a
   256-byte buffer.
5. The passphrase is **never written to NVS**, never sealed, never logged. It
   lives in RAM for the duration of one derivation.
6. `mw_session_wipe_input()` zeroes the buffer immediately after the keys are
   derived, and `mw_session_lock()` calls it again. Input buffers are also
   wiped after `MW_INPUT_TIMEOUT_MS` (5 minutes) without a keypress (TZ 5.10).

### Why mandatory

The eFuse seal protects the seed *at rest on this chip*. It does not protect
against someone who has the chip **and** can run code on it — no secure boot by
default, no glitch countermeasures. The passphrase is the only secret that is
not stored anywhere on the device, so it is the only thing that survives a full
physical compromise. Making it optional-by-default would mean most users never
set one; making the prompt unconditional means every user makes a deliberate
choice and every recovery procedure looks the same.

For legacy seeds the passphrase is folded in with Monero's own **seed offset**
scheme (`src/monero/mnemonic.h`):

```
key32 = the 32 bytes the seed encodes (legacy) / polyseed_keygen() (polyseed)
passphrase != ""   ->  key32 = sc_sub(key32, cn_slow_hash(passphrase))   (ref10 sc_sub)
spend = sc_reduce32(key32)
view  = sc_reduce32(keccak256(spend))
```

This is `cryptonote::decrypt_key()` exactly as monero-wallet-cli, the GUI and
Feather apply a seed offset on restore (`src/monero/seed_keys.c`). The host
tests should carry a "seed + passphrase -> address" vector taken from
monero-wallet-cli so a drift of either side shows up.

The empty case is a genuine no-op — **not** `hash_to_scalar("")` — so a wallet
created without a passphrase reproduces the plain Monero wallet exactly and is
restorable in `monero-wallet-cli` or any other standard client. A wallet created
*with* a passphrase is restorable the same way by supplying the same seed offset
passphrase. Polyseed uses its own upstream scheme (`mw_polyseed_crypt`, feature
bit 16).

Note the consequence: a wrong passphrase does not fail, it silently produces a
**different, perfectly valid** wallet with a different address. There is nothing
on the device to check it against, which is why the double entry of rule 3 is
not optional, and why the creation flow shows the resulting primary address for
verification (TZ 4.2).

---

## 4. eFuse provisioning procedure

> ### ⚠ IRREVERSIBLE
> eFuse bits only ever go 0 → 1. Once the key block is burned and read-protected
> it can **never** be read, changed or erased. Losing it makes every wallet
> sealed on that device unrecoverable *from the device* — your seed phrase on
> paper is the only backup. TZ 8.1: *"the HMAC key is programmed before first
> use; updating it means replacing the chip."*
>
> `mw_secure_key_provision()` deliberately takes **no arguments** so it cannot
> be invoked by a generic settings dispatcher, and the UI must place it behind
> **two** separate confirmation screens.

### 4.0 Which key block

The ESP32-S3 has six key blocks, `BLOCK_KEY0..5`. The chip keeps nothing of
its own there (calibration and MAC live in `BLOCK1/2`); they are taken only by
features someone turns on: flash encryption (1-2 blocks) and secure boot (up to
3 digests), which ESP-IDF puts into the **first** free block. The wallet key
therefore goes into the **highest** free block (`BLOCK_KEY5` on a fresh chip)
and leaves the low ones to them.

The block in use is the one with purpose `HMAC_UP` and read protection; its
number is kept in NVS (`hw_kblk`), so an `HMAC_UP` block burned later by
someone else does not replace it. A chip provisioned by older firmware
(`BLOCK_KEY0`) keeps working. Settings → *eFuse key blocks* shows the state of
all six blocks (read-only).

### 4.1 On-device (the normal path)

1. The device does not work without the key: right after the unlock gesture,
   **before the device password**, a chip without it shows the first-start
   notice and the provisioning screens (naming the block). Declining returns
   to the game. When no key block is free, the device says so, lists the
   blocks and does not continue.
2. Confirm screen 1: *"A random 256-bit HMAC key will be burned into eFuse
   BLOCK_KEYn ..."*
3. Confirm screen 2: the typed code.
4. The firmware calls `mw_secure_key_provision()`, which:
   * picks the highest completely unused key block and refuses when there is
     none;
   * generates 32 bytes by XORing `mw_random_bytes()` (health-tested TRNG path,
     TZ 8.2) with `esp_fill_random()`;
   * refuses to burn an all-zero key;
   * calls `esp_efuse_write_key(EFUSE_BLK_KEYn, ESP_EFUSE_KEY_PURPOSE_HMAC_UP,
     key, 32)`, which write-protects the block and sets the key purpose;
   * explicitly sets read protection if the IDF version did not;
   * re-reads the state and returns `MW_OK` only when purpose ==
     `HMAC_UP` **and** read protection is set.
5. `mw_secure_key_status()` now returns `MW_OK`. Without it nothing is sealed:
   `mw_seal()` and `mw_secure_hw_hmac()` return `MW_ERR_NOT_SUPPORTED` (there is
   no bring-up fallback in the firmware any more).

Records written by older firmware in its bring-up mode (hardware part
`keccak256(label)`, a public value) still OPEN: `mw_unseal()` tries that key
when the eFuse one fails and flags it (`mw_secure_last_unseal_legacy()`). The
first unlock after provisioning upgrades the password record to the eFuse key,
and that upgrade re-seals every wallet and key image cache under it. Nothing
new is ever sealed the old way.

### 4.2 From the host with `espefuse.py`

Use this when you provision at the bench (it is also how you burn the key
*before* the first firmware flash, which is the order TZ 8.1 asks for).

```bash
# 0) Install the tool (ships with ESP-IDF; standalone via pip)
pip install esptool

# 1) Generate a 32-byte key. Do this on a machine you trust, and destroy the
#    file afterwards - it is never needed again.
head -c 32 /dev/urandom > hmac_key0.bin

# 2) Inspect the chip first. Pick the highest empty block (BLOCK_KEY5 on a
#    fresh chip) - the firmware looks for HMAC_UP in any block.
espefuse.py --port /dev/ttyACM0 summary

# 3) Burn it with purpose HMAC_UP. --no-read-protect is NOT passed, so the
#    block is read-protected as part of the same operation.
espefuse.py --port /dev/ttyACM0 burn_key BLOCK_KEY5 hmac_key0.bin HMAC_UP

# 4) Verify: KEY_PURPOSE_5 must read HMAC_UP and BLOCK_KEY5 must show
#    "read protected" and "write protected".
espefuse.py --port /dev/ttyACM0 summary | grep -A2 -E 'KEY_PURPOSE_5|BLOCK_KEY5'

# 5) Destroy the key material on the host.
shred -u hmac_key0.bin
```

`espefuse.py` asks for a typed `BURN` confirmation; pass `--do-not-confirm`
only in a factory script you have already tested on a scrap board.

Optional, strongly recommended for a device that will hold real value:

```bash
# Flash encryption in release mode (irreversible, and it disables plaintext
# flashing - you will need a signed OTA path afterwards).
espefuse.py --port /dev/ttyACM0 burn_efuse SPI_BOOT_CRYPT_CNT 7

# Secure Boot v2 (irreversible). Sign your firmware first.
espsecure.py generate_signing_key --version 2 secure_boot_signing_key.pem
espefuse.py --port /dev/ttyACM0 burn_key BLOCK_KEY1 \
    secure_boot_digest.bin SECURE_BOOT_DIGEST0
espefuse.py --port /dev/ttyACM0 burn_efuse SECURE_BOOT_EN 1
```

### 4.3 sdkconfig requirements

For NVS encryption keyed from the same eFuse block (TZ 8.1), the build needs:

```
CONFIG_NVS_ENCRYPTION=y
CONFIG_NVS_SEC_PROVIDER_HMAC=y
CONFIG_NVS_SEC_HMAC_EFUSE_KEY_ID=5        # the block the firmware burned (Settings -> eFuse key blocks)
CONFIG_ESP32S3_UNIVERSAL_MAC_ADDRESSES=... # unchanged
```

A partition for the NVS key store is needed ONLY for the flash-encryption
based scheme; the project's `partitions.csv` has none because the HMAC
provider below is the chosen path. If you switch to the flash-encryption
scheme, add:

```
nvs_key,  data, nvs_keys, ,        4K, encrypted
```

`CONFIG_NVS_SEC_PROVIDER_HMAC` is the scheme that works **without** flash
encryption — it derives the NVS keys from the HMAC key block, which is
precisely the key §4 burns. Prefer it here.

---

## 5. Wipe policy

| Buffer | Wiped by | When |
| --- | --- | --- |
| Plaintext seed | `mw_wallet_unseal_seed()`, `mw_wallet_load_keys()` | Single `done:` cleanup path — every return, success or failure |
| Derived account keys (local copy) | `mw_session_unlock()` | Immediately after the copy into `mw_session_t` |
| Session keys | `mw_session_lock()` | Autolock, error, end of every operation, factory reset |
| Passphrase buffer | `mw_session_wipe_input()` | After key derivation, on lock, on 5-minute input timeout (TZ 5.10) |
| Per-label AES key | `mw_seal()` / `mw_unseal()` | Before returning, on every path |
| AES round keys, GHASH state | `mw_aes256_gcm_*` | Before returning |
| Imported raw key material | `mw_wallet_create_from_keys()` | Single `done:` cleanup path — the 64-byte payload and the derived comparison scalar |
| Deleted wallet record | `mw_wallet_delete()` | Random / random / zero, each pass committed, then the slot is dropped (TZ 7.2) |
| Everything | `mw_factory_reset()` (HAL) | Erases the NVS partition and reboots |

All wiping goes through `mw_memzero()`, which the compiler is not allowed to
optimise away.

**Honest caveat on "secure erase":** NVS is a wear-levelled, log-structured
store on flash. Writing a record three times does not necessarily overwrite the
same physical page — it usually appends new pages and marks the old ones erased.
The three-pass overwrite raises the cost of recovery and guarantees the *logical*
record is gone, but the real protection for an old ciphertext is that it is
still AES-256-GCM under a key that lives in the eFuse. For a hard guarantee, do
a factory reset (full partition erase) and re-provision on a new chip.

---

## 6. Known limitations

Read this section as a list of reasons **not** to treat this device as a
tamper-resistant secure element. It is an honest hobby-grade signer.

### 6.1 PSRAM

PSRAM is external, on an unencrypted bus, and its contents can survive a warm
reset. Flash encryption does not cover it. Secrets must therefore never be
allocated there:

* `mw_session_t` and the passphrase buffer in `session.c` are static and marked
  `DRAM_ATTR` under `ARDUINO`, forcing them into internal SRAM even if the build
  enables `CONFIG_SPIRAM_ALLOW_BSS_SEG_EXTERNAL_MEMORY`.
* Do **not** use `ps_malloc()` / `heap_caps_malloc(..., MALLOC_CAP_SPIRAM)` for
  seeds, keys, passphrases or transaction scratch space that contains them.
  PSRAM is for LVGL frame buffers and the camera.
* Anything that must go through PSRAM should be sealed first.

### 6.2 NVS encryption under the Arduino IDE — a real problem

**The prebuilt ESP32 Arduino core very likely does not have
`CONFIG_NVS_ENCRYPTION` enabled.** The Arduino core ships as precompiled
ESP-IDF libraries with a fixed `sdkconfig`; you cannot turn a Kconfig option on
by adding a `#define` to your sketch. If you flash this firmware from a stock
Arduino IDE installation, **NVS is stored in plaintext**.

What that costs you: the wallet directory (names, restore heights, wallet ids)
is readable from a flash dump, and so are the sealed seed blobs — but the seeds
themselves stay protected by the eFuse-backed GCM seal, which does not depend on
NVS encryption. In other words, you lose a defence-in-depth layer and all
metadata privacy; you do not lose the seeds.

What to do about it, in increasing order of effort:

1. **Accept it knowingly.** The seal is the load-bearing protection. Use a
   strong passphrase (§3) and treat wallet names as public.
2. **Build with ESP-IDF instead of the Arduino IDE**, using the Arduino core as
   an IDF component (`idf.py menuconfig` → *Component config → NVS* →
   `CONFIG_NVS_ENCRYPTION=y`, then *NVS Security Provider* → HMAC,
   `CONFIG_NVS_SEC_HMAC_EFUSE_KEY_ID=0`). This is the supported path and is what
   the sdkconfig snippet in §4.3 assumes.
3. **Rebuild the Arduino core libraries** with a custom `sdkconfig` via
   `esp32-arduino-lib-builder`, then install the result as a local core. Same
   result as (2), more work, but it keeps the Arduino IDE workflow.

Check at runtime before trusting it: if `nvs_flash_init()` succeeds while
`esp_flash_encryption_enabled()` is false and the HMAC provider was never
registered, assume plaintext NVS.

### 6.3 No secure boot by default

Every wallet record is sealed under a key that needs BOTH the device
password (through the password KDF) and the chip's eFuse HMAC key. The eFuse
key cannot be read out, so a dump of the flash cannot be attacked on a PC.

Nothing stops an attacker with the device and USB access from flashing their
own firmware, though. That firmware can call the HMAC peripheral directly, so
the chip becomes a password-guessing oracle without the firmware's attempt
counter and back-off: every guess costs one run of the password KDF on the
chip (200 000 PBKDF2-HMAC-SHA256 rounds plus 9 eFuse HMAC steps). The firmware
itself already runs the PBKDF2 on the SHA accelerator (after a self-test, see
`mw_pbkdf2_sha256_hw()`), so an attacker gains no speed there.

What follows for the user:

* the password is the barrier against a stolen device: new passwords must have
  at least 8 characters (`MW_DEVICE_PW_MIN_NEW`), and digits-only, one repeated
  character or a plain run (`abcdefgh`) draws a warning;
* whoever knows the device password opens every wallet that has no
  passphrase - the passphrase (§3) is the second factor.

Enable Secure Boot v2 and flash encryption (§4.2) to close the oracle. Both are
irreversible and lock you out of plain reflashing; the firmware does not turn
them on by itself.

### 6.4 No anti-tamper

There is no case-intrusion switch, no mesh, no battery-backed tamper flag, no
active shield, no temperature/voltage/clock glitch detection, no secure element.
The ESP32-S3 is a general-purpose MCU. Published fault-injection and
side-channel attacks against ESP32-family flash encryption and secure boot exist
and are not mitigated here.

### 6.5 Other

* **Passphrase check (task 3).** A wallet created with a passphrase keeps a
  14-byte check of the passphrase wallet's public keys INSIDE the sealed seed
  record, so a typo is caught ("wrong passphrase") while the check is only
  readable after the device password unlocked the store. Records made by an
  older firmware carry no check: there a wrong passphrase still silently
  yields a different wallet, and the device says it cannot verify. The
  directory does reveal whether a wallet has a passphrase variant (it has to:
  the prompt is shown or not before anything is unsealed). Autolock is
  time-based only.
* **RNG trust.** Seed generation relies on the ESP32 TRNG plus the SP 800-90B
  style health tests in `mw_random_selftest()`. Users who do not want to trust
  it should use the dice-entropy path (TZ 6.4).
* **The host test backend (`secure_storage_host.c`) is not secure** and is never
  compiled into firmware: it stores the "eFuse" key in a plain file so the unit
  tests can run the full lifecycle on a PC. It is excluded by the
  `MW_HOST_BUILD` guard.
* **`is_hidden` is not a security feature.** It only keeps a wallet out of the
  default list; the record is still in the directory and a flash dump still
  shows that it exists and what it is named. It is not plausible deniability.
* **Physical seed backup remains the user's job.** Nothing on this device is a
  backup of anything.

## 7. Task 3: Feather files, the shell, the PC link

* **What leaves the device.** Key image exports and signed transaction sets
  (sealed with the wallet's view key, like wallet2 does), the address, and -
  only on a PC request confirmed on the device (Yes / No) - the
  private view key. The private spend key, the seed and the passphrase have no
  code path to the USB link at all; the view key JSON is built in
  `wallet_ops.c` from the view scalar only, and a host test checks the spend
  key never appears in it. The same holds for the SD text file of "View key
  to SD card" (`mw_ops_viewonly_text`, written only after a warning on the
  device; host test `test_viewonly_text`).
* **Nothing without confirmation.** Every key image export and every
  transaction is confirmed on the device screen. The link only stores files
  and requests in RAM; the crypto task processes them in the wallet menu.
  While the device is locked (game, password prompt) or no wallet is open the
  link refuses files and requests and INFO reports no wallet names.
* **Change address substitution and hybrid addresses**
  (`mw_tx_check_destinations`, `tx.c`). The online wallet knows the view key,
  so it can build addresses that are half ours: our view key with its own
  spend key (it can spend the output, our wallet never sees it), (D', a*D')
  which looks like one of our subaddresses, or our spend key with a foreign
  view key (burned funds; such an address shares its first 45 characters with
  ours). The check runs in the review (after the inputs are matched) AND
  inside `mw_sign_transaction`, so signing never depends on the review:
  * every destination key and the change_dts keys must be valid public keys;
  * every input must be in `subaddr_account` and all transactions of a set
    must use one account (wallet2 throws on mixed accounts);
  * a destination is OWN only when spend AND view equal an address the device
    re-derives: (0,0), (acct,0), the inputs' verified subaddresses and the
    subaddresses the key image cache knows. The file's `subaddr_indices`
    hints only help to find the inputs; they never make an address own.
    A view key equal to a*spend with no such match starts a bounded search
    (account primaries up to max(known account, acct)+1, at most 50; minors of
    `acct` and of account 0 down from the highest known minor + 200; at most
    600 derivations). Found: own. Not found: refused - export outputs first so
    the device learns the subaddress;
  * our view key (main or any candidate) with another spend key, or a
    candidate's spend key with another view key: refused as a hybrid;
  * an own address whose `is_subaddress` flag does not match its index
    (main flagged as a subaddress, or the reverse) is refused - the output
    would be invisible to the wallet;
  * change follows wallet2: only to `(subaddr_account, 0)`, with
    `change_is_subaddress == (acct != 0)`, and the claimed change amount may
    not exceed what that address is paid (the excess is shown as an own
    recipient). A 0-amount change_dts that nothing pays is wallet2's dummy
    (sweeps): those 0-amount outputs are counted as dummy outputs, not shown
    as recipients.
  The change output is built from the device-derived keys
  (`tx->change_derived`), and the summary encodes the change address from
  them too; a CHANGE row that is not the verified change is refused. The
  review shows the change with its address and index ("Change -> this
  wallet M/m"), "Change: none" when there is none, the number of dummy
  outputs, and marks own recipients with their index. A fee above 0.01 XMR or
  above 10% of what the transaction moves sets `high_fee` (dropped change
  becomes fee), for a second confirmation.
  **Residual risk.** A foreign view key combined with the spend key of one of
  our subaddresses that the device does not know (not an input, not in the
  key image cache, not (0,0) or (acct,0)) cannot be told from a foreign
  address without a full subaddress table: such an output is burned, not
  stolen, and its address is shown in full as an ordinary recipient. A
  foreign spend key with the view key of such an unknown subaddress is the
  same case. Recipient substitution by a compromised online wallet (an
  entirely foreign address) is out of scope: the user compares the address.
* **Key images not synchronised.** An input whose key image the device never
  exported means the online wallet may be spending an already spent output;
  the device refuses and explains. Inputs already spent by an earlier
  transaction signed on the device are warned about. The key image cache
  (`ki_cache.c`) is sealed (AES-GCM, device key) on the FAT partition and
  erased with its wallet and by the factory reset.
* **The Minesweeper start screen is a decoy, not a security boundary.** It
  hides the wallet from a casual look; the device password is what protects
  the sealed seeds. The USB descriptors still name the device.
* **Autolock** closes whatever dialog is open, wipes the keys, drops the
  password-derived user key (`mw_device_auth_forget`) and clears the link's
  inbox/outbox; unlocking again needs the game gesture and the password.
* **Log rule.** The PC log carries what the device does and why it refused
  something; debug mode adds indices, subaddresses, counts and amounts. Keys,
  seeds, passphrases and key images are never logged; the review logs the
  change and own outputs by index only ("tx 1: change 0.5 XMR -> this wallet
  0/0 (re-derived)"), never full addresses.
* **File key.** Opening the unsigned set derives the exchange-file ChaCha key
  (cn_slow_hash of the view key); the sign session keeps it to seal the
  signed set instead of deriving it again, and wipes it when signing ends.
  The session itself is freed with a wiping free.
