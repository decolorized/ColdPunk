// Unified data-exchange layer (TZ 3 / TZ 2.0 1.3). A screen asks for "the
// next input file" and does not care which wire it arrives on.
//
// Channels (TZ 2.0 1.3, task2 item 2): the physical SD card, animated QR
// (UR), the USB link to the host program (CDC serial + vendor HID, link.h) and
// - reserved, not implemented yet - the audio modem. No USB mass-storage,
// floppy or MTP emulation exists any more; the host program is a plain file
// courier and every conversion happens on the device.
#ifndef MW_TRANSFER_H
#define MW_TRANSFER_H

#include "../monero/monero_types.h"

#ifdef __cplusplus
extern "C" {
#endif

// ---------------- TinyUSB availability -------------------------------------
// The ESP32 core passes -DARDUINO_USB_MODE=0 for "USB-OTG (TinyUSB)" and =1
// for "Hardware CDC and JTAG", where TinyUSB is absent. With TinyUSB the
// vendor HID interface is available next to the CDC port; without it only
// `Serial` (whatever the IDE routed it to) carries the link. The firmware
// builds either way (task2 item 3) - a transport that is not there is simply
// reported as unavailable.
//
// Define MW_USB_NO_TINYUSB to force the HID transport off.
#if !defined(MW_USB_TINYUSB) && !defined(MW_USB_NO_TINYUSB) && !defined(MW_HOST_BUILD)
#  if defined(ARDUINO) && defined(ARDUINO_USB_MODE) && (ARDUINO_USB_MODE == 0)
#    define MW_USB_TINYUSB 1
#  endif
#endif

typedef enum {
    MW_CHANNEL_SD = 0,       // physical microSD, FAT32 files (sd_transfer.c)
    MW_CHANNEL_QR,           // animated UR over the display / camera
    MW_CHANNEL_USB_LINK,     // host program over CDC serial or vendor HID (link.h)
    MW_CHANNEL_AUDIO         // reserved: audio modem (TZ 2.0 stage 2), not built
} mw_channel_t;

typedef enum {
    MW_FILE_KIND_OUTPUTS = 0,
    MW_FILE_KIND_KEYIMAGES,
    MW_FILE_KIND_UNSIGNED_TX,
    MW_FILE_KIND_SIGNED_TX,
    // Wallet data the host asked for (address, or address + private view key
    // for a view-only wallet), JSON text. Produced only after the user
    // confirmed on the device (task 3).
    MW_FILE_KIND_WALLET_EXPORT,
    MW_FILE_KIND_COUNT
} mw_file_kind_id_t;

// Largest exchange file (a key image export of ~2700 outputs, a sweep with
// 32 inputs). The USB link payload has the same cap.
#define MW_TRANSFER_MAX_FILE (256u * 1024u)

// Canonical file names used on the SD volume and by the host program.
extern const char* const MW_FILENAME[MW_FILE_KIND_COUNT];

mw_err_t mw_transfer_init(void);
bool     mw_transfer_available(mw_channel_t ch);

// Reads a file into `buf`. For QR this drives the scanner screen until the UR
// sequence is complete or the user cancels; for the USB link it waits for the
// host program to push the file (cancellable through the link wait hook).
mw_err_t mw_transfer_receive(mw_channel_t ch, mw_file_kind_id_t kind,
                             uint8_t* buf, size_t cap, size_t* len);
mw_err_t mw_transfer_send(mw_channel_t ch, mw_file_kind_id_t kind,
                          const uint8_t* buf, size_t len);

#ifdef __cplusplus
}
#endif
#endif
