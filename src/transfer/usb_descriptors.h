// USB identity of the wallet (task2 item 2: only the CDC serial + vendor HID
// link remains; the MSC / MTP / floppy / composite descriptor sets are gone).
//
// SPDX-License-Identifier: MIT
#ifndef MW_USB_DESCRIPTORS_H
#define MW_USB_DESCRIPTORS_H

// 0x303A is Espressif's vendor ID; 0x4024/0x4025 are inside the range
// Espressif reserves for user applications built on their VID. Two PIDs
// because Windows caches the interface layout of a composite device per
// VID/PID: a CDC-only device and a CDC + HID device must not share one.
#define MW_USB_VID            0x303A
#define MW_USB_PID_LINK       0x4024      // CDC serial + vendor HID
#define MW_USB_PID_CDC_ONLY   0x4025      // CDC serial only (no TinyUSB HID)

#endif
