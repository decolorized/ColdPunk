# Animated QR transport (Uniform Resources)

TZ 3.7. This is the air-gapped exchange path: the wallet shows an animated QR
sequence on its display and reads one back through the camera. It is wire
compatible with Feather (2.6.0 and later), ANON/NERO and Cake Wallet, because it
implements the Blockchain Commons Uniform Resources specification exactly.

Monero GUI does **not** support UR. Use SD or USB with it.

---

## 1. What goes over the wire

A UR is a URI. Two forms exist.

**Single part** — the whole message fits in one symbol:

```
ur:bytes/hdeymejtswhhylkepmykhhtsytsnoyoyaxaedsuttydmmhhpktpmsrjtgwdpfnsbox...
```

**Multi part** — a sequence number, the number of "pure" parts, and a fragment:

```
ur:bytes/1-9/lpadascfadaxcywenbpljkhdcahkadaemejtswhhylkepmykhhtsytsnoyoyax...
ur:bytes/2-9/lpaoascfadaxcywenbpljkhdcagwdpfnsboxgwlbaawzuefywkdplrsrjynbvyg...
...
```

The type is `bytes` for the four exchange files of TZ 9 and `crypto-keyimage`
where a counterpart asks for it. Everything after the last `/` is
**bytewords, minimal style**: each byte becomes the first and last letter of its
word in the 256-word Blockchain Commons table, and a 4-byte big-endian CRC-32 of
the payload is appended before encoding. So a *n*-byte payload becomes
2·(*n*+4) lowercase letters.

UR strings are case insensitive on input; we emit lower case and accept upper
case, which is what a QR encoder in alphanumeric mode produces.

### The message

For a single-part UR the bytewords carry the CBOR encoding of the payload. For
`ur:bytes` that is one CBOR byte string:

```
58 32 <50 bytes>          # 0x58 = byte string, 1-byte length
```

For a multi-part UR each fragment carries a five-element CBOR array:

```
[ seqNum, seqLen, messageLen, checksum, data ]
   uint    uint      uint       uint     bstr
```

* `seqNum` — 1-based, increments forever and wraps at 2³².
* `seqLen` — the number of fragments the message was split into.
* `messageLen` — length of the **CBOR message**, not of the payload.
* `checksum` — CRC-32 of that whole CBOR message.
* `data` — one fragment, `ceil(messageLen / seqLen)` bytes, zero-padded.

`seqNum` and `seqLen` are repeated in the URI path so a receiver can reject a
mismatched frame before decoding anything.

### The fountain code

Parts `1 .. seqLen` are the *pure* fragments, in order. From `seqLen + 1` onward
each part is the XOR of a pseudo-random subset of fragments, chosen so that a
receiver that missed a frame can recover it without the sender starting over.
The subset is fully determined by `seqNum`, `seqLen` and `checksum`:

1. seed = SHA-256( `seqNum` big-endian ‖ `checksum` big-endian );
2. that digest, read as four big-endian 64-bit words, is the state of a
   **Xoshiro256\*\*** generator;
3. the degree (how many fragments to mix) is drawn from the distribution
   1, 1/2, 1/3 … 1/seqLen using the **Walker-Vose alias method**, taking two
   doubles from the generator;
4. the fragment indexes are a **Fisher-Yates shuffle** of `0 .. seqLen-1`,
   truncated to that degree.

Every detail matters for interop — the double conversion (`next() / 2⁶⁴`), the
reversed index order in the alias-table construction, the removal-by-shift in
the shuffle. `src/transfer/ur.c` follows the reference implementation
bit for bit, and `test/test_ur.c` pins it with the official BCR-2020-005 and
BCR-2020-012 vectors, including the twenty-frame `ur:bytes` sequence that the
reference suite publishes.

### Defaults

| Parameter | Value | Why |
| --- | --- | --- |
| Fragment size | 50 bytes | TZ 3.7; ~110 characters per frame, QR version 5-7 |
| Frame rate | 12.5 fps (`MW_QR_FRAME_MS` = 80 ms) | TZ 3.7 |
| Error correction | level L | maximum density; the fountain code already gives redundancy |
| Max parts | 512 (`MW_UR_MAX_PARTS`) | bounds every decoder allocation |
| Max fragment | 200 bytes (`MW_UR_MAX_FRAGMENT`) | |
| Max file | 64 KB | TZ 3.2 |

A 2 KB file becomes 42 fragments, about 3.4 seconds per pass.

---

## 2. Sending — the device displays

```c
#include "transfer/qr_encode.h"

mw_err_t mw_qr_send_begin(const uint8_t* buf, size_t len,
                          const char* ur_type, size_t fragment);
mw_err_t mw_qr_send_next(mw_qr_t* out);     // next frame; cycles forever
uint32_t mw_qr_send_seq_len(void);          // 1 == a static QR
void     mw_qr_send_end(void);
```

`mw_qr_send_begin` pins the QR **version** for the whole sequence: frames differ
by a character or two as the sequence number grows, and letting the symbol
change size mid-animation forces the scanner to re-acquire on every frame.

The UI owns the screen. Typical loop:

```c
mw_qr_send_begin(file, file_len, MW_UR_TYPE_BYTES, MW_UR_DEFAULT_FRAGMENT);
mw_qr_t frame;
while (!user_pressed_done()) {
    if (mw_qr_send_next(&frame) != MW_OK) break;
    draw(&frame);                 /* mw_qr_get(&frame, x, y) per module */
    mw_delay_ms(MW_QR_FRAME_MS);
}
mw_qr_send_end();
```

`mw_transfer_send(MW_CHANNEL_QR, ...)` runs exactly this loop for you and calls
the UI hook (below) once per frame.

### Drawing

`mw_qr_t` is a bitmap; `mw_qr_get(q, x, y)` is true where the module is dark and
false everywhere outside the symbol, so a quiet zone comes for free:

```c
for (int y = -4; y < q.size + 4; y++)
    for (int x = -4; x < q.size + 4; x++)
        put_block(x, y, mw_qr_get(&q, x, y) ? BLACK : WHITE);
```

Four modules of quiet zone are required by the standard. On a 240×240 display a
version 7 symbol (45 modules) plus quiet zone is 53 modules — four screen pixels
each fits with room to spare.

---

## 3. Receiving — the device scans

```c
mw_err_t mw_qr_recv_begin(uint8_t* buf, size_t cap);
mw_err_t mw_qr_recv_feed(const char* text);   /* MW_ERR_FORMAT == ignore it */
bool     mw_qr_recv_complete(void);
int      mw_qr_recv_progress_permille(void);
mw_err_t mw_qr_recv_result(const uint8_t** data, size_t* len);
void     mw_qr_recv_end(void);

mw_err_t mw_qr_scan_once(char* out, size_t out_cap);   /* capture + decode */
```

`buf` is the decoded-file destination and doubles as the bound on everything:
a frame announcing a `messageLen` larger than `cap` is rejected before a byte is
allocated.

Progress is the fraction of *distinct* fragments recovered, so it only ever goes
up. Duplicate and out-of-order frames are free; a frame from a different
sequence (different `seqLen`, `messageLen` or `checksum`) is discarded.

`mw_transfer_receive(MW_CHANNEL_QR, ...)` runs the capture loop for you.

### The UI hook

```c
typedef bool (*mw_qr_ui_hook_t)(const mw_qr_t* frame, int permille, void* ctx);
void mw_qr_set_ui_hook(mw_qr_ui_hook_t hook, void* ctx);
```

Called once per frame by both directions: `frame` is the symbol to draw when
sending and `NULL` when receiving. Return `false` to cancel — the transfer then
fails with `MW_ERR_ABORTED`.

---

## 4. The scanner

`src/transfer/camera_scan.cpp` turns an 8-bit grayscale frame from
`mw_camera_capture()` into the string inside the symbol:

1. **Adaptive binarisation.** 8×8 block averages, each pixel thresholded against
   the mean of the surrounding 5×5 block neighbourhood. A global threshold fails
   on a photograph of a screen, where the backlight falls off towards the edges.
2. **Finder patterns.** Every second row is scanned for the 1:1:3:1:1 run
   signature, confirmed by a vertical cross-check through the candidate centre.
   Candidates are then scored in *triples*: two legs of equal length meeting at a
   right angle with consistent module sizes. Scoring whole triples is what
   rejects the accidental 1:1:3:1:1 cross sections that dense data areas throw
   off — picking the three highest-scoring individual candidates does not.
3. **Grid sampling.** The three finder centres fix an affine basis. The symbol's
   dimension is *not* taken from the finder module size (a horizontal cut through
   a tilted square is longer than the square's side, so that estimate is biased
   under rotation and can be off by a whole version); instead every candidate
   dimension is scored by how well the timing pattern alternates, and the best
   one wins.
4. **Decoding.** Format information with BCH error correction, unmasking,
   zig-zag codeword extraction, de-interleaving, Reed-Solomon correction
   (Berlekamp-Massey, Chien search, Forney) and the byte-mode segment parser.

### Limits, stated plainly

* Versions 1-20. Animated UR frames are version 5-10; larger symbols are refused
  with `MW_ERR_NOT_SUPPORTED`.
* Error-correction levels L and M. Q and H are refused.
* Byte mode only.
* The grid is sampled with an **affine** transform. That is exact for a
  fronto-parallel view — the wallet pointed at a phone or a monitor — and
  degrades under strong perspective. Alignment-pattern-based perspective
  correction is not implemented.
* No structured-append (multi-symbol) support.

---

## 5. Hostile input

The decoder parses strings that came off a camera pointed at something an
attacker may control. It is written accordingly:

* every buffer is fixed size and every length is checked against it;
* the only allocations are made once per session, from `seqLen` and
  `fragmentLen` values already clamped against `MW_UR_MAX_PARTS`,
  `MW_UR_MAX_FRAGMENT` and the caller's `cap`;
* the mixed-part pool is capped at 32 entries. Dropping a mixed part can never
  stall decoding, because the sender emits the `seqLen` pure parts first and
  cycles back to them;
* a CRC-32 mismatch, a malformed CBOR header, a bad bytewords pair, a
  sequence-number/CBOR disagreement, an oversize `messageLen` — all return
  `MW_ERR_*` and leave the session untouched.

`test/test_ur.c` includes a mutation fuzzer (character flips, truncation,
extension, deletion, 3 KB bodies) and a random-string fuzzer, both run under
`-fsanitize=address,undefined`.

---

## 6. Interoperability status

| Counterpart | Direction | Status |
| --- | --- | --- |
| Blockchain Commons `bc-ur` reference | both | byte-identical frames verified for single-part and 300-frame multi-part sequences |
| Feather ≥ 2.6.0 | both | same encoding; not yet tested against a live build |
| ANON / NERO | both | same encoding; not yet tested against a live build |
| Monero GUI | — | no UR support; use SD or USB |

---

## 7. Files

| File | Contents |
| --- | --- |
| `src/transfer/ur.h` | frozen API |
| `src/transfer/ur.c` | bytewords, CBOR, Xoshiro256\*\*, alias sampler, fountain encoder/decoder |
| `src/transfer/qr_encode.h` / `.c` | QR generator and the QR session API |
| `src/transfer/camera_scan.cpp` | binarisation, finder detection, grid sampling, symbol decoding |
| `src/transfer/transfer.c` | channel dispatch and the QR session state |
| `test/test_ur.c` | BCR-2020-005 / BCR-2020-012 vectors, round trips, fuzzing |
| `test/test_qr.c` | golden matrices from the ISO/IEC 18004 reference implementation |
