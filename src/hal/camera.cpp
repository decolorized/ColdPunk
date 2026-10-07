// OV2640 camera for QR / UR scanning (TZ 3.7).
//
// Backend: esp32-camera (bundled with the ESP32 Arduino core as esp_camera.h).
//
// Why grayscale
// -------------
// A QR decoder only ever looks at luminance: the first thing any of them does
// with a colour frame is throw the chroma away.  PIXFORMAT_GRAYSCALE gives the
// decoder exactly what it wants, costs a quarter of the RAM of RGB565
// (QVGA: 76.8 KB instead of 153.6 KB), and skips the sensor's colour
// interpolation, which is the slowest stage of the pipeline.  The viewfinder
// then expands grey to RGB565 on the fly in mw_camera_preview() - a grey
// viewfinder is honest about what the decoder is seeing anyway.
//
// Frame ownership
// ---------------
// hal.h promises that a captured frame stays valid until the *next*
// mw_camera_capture().  That maps onto esp32-camera's borrow model directly:
// the driver's buffer is held between calls and returned at the top of the
// next one.  Nothing is copied, so a capture costs no RAM beyond the two
// driver framebuffers in PSRAM.
//
// mw_camera_preview() deliberately does NOT disturb that: it borrows and
// returns its own frame, so a scan loop can hold a frame for the decoder
// while the UI keeps drawing the viewfinder.  That is what fb_count = 2 is
// for.
#if defined(ARDUINO) && !defined(MW_HOST_BUILD)

#include <Arduino.h>
#include <string.h>
#include "display_drivers.h"

// ===========================================================================
// No camera fitted: every entry point fails cleanly
// ===========================================================================
#if !HAS_CAMERA

mw_err_t mw_camera_init(void)   { return MW_ERR_NOT_SUPPORTED; }
void     mw_camera_deinit(void) { }

mw_err_t mw_camera_capture(mw_camera_frame_t* out)
{
    if (out) { out->data = NULL; out->width = 0; out->height = 0; }
    return MW_ERR_NOT_SUPPORTED;
}

mw_err_t mw_camera_preview(uint16_t* out, uint16_t w, uint16_t h)
{
    (void)out; (void)w; (void)h;
    return MW_ERR_NOT_SUPPORTED;
}

#else   // ================= HAS_CAMERA ======================================

#include <esp_camera.h>

// QVGA grayscale is 76.8 KB and resolves a ~50-byte UR fragment at arm's
// length with room to spare (TZ 3.7).  Raise to FRAMESIZE_VGA in
// board_config.h if the optics are unusually wide-angle; it quadruples both
// the RAM and the per-frame decode time.
#ifndef CAMERA_FRAME_SIZE
#define CAMERA_FRAME_SIZE FRAMESIZE_QVGA
#endif
// 20 MHz is the OV2640's happy point on an S3.  Some long flex cables need
// 16 MHz; below that the sensor drops frames.
#ifndef CAM_XCLK_FREQ_HZ
#define CAM_XCLK_FREQ_HZ 20000000
#endif
// LEDC RESOURCE NOTE: esp32-camera generates XCLK with an LEDC timer/channel,
// and src/hal/display.cpp uses LEDC for the backlight.  The backlight is
// attached first (mw_hal_init() brings the display up long before anything
// touches the camera) and lands on channel 0 / timer 0, so the camera is
// pinned to channel 1 / timer 1 here.  If a board ever needs a second PWM,
// give it channel 2 and up.
#ifndef CAM_LEDC_CHANNEL
#define CAM_LEDC_CHANNEL LEDC_CHANNEL_1
#endif
#ifndef CAM_LEDC_TIMER
#define CAM_LEDC_TIMER   LEDC_TIMER_1
#endif
#ifndef CAM_VFLIP
#define CAM_VFLIP  0
#endif
#ifndef CAM_HMIRROR
#define CAM_HMIRROR 0
#endif

static bool         s_cam_ready = false;
static camera_fb_t* s_held      = nullptr;   // frame lent to the caller

// --------------------------------------------------------------------------
// The SCCB pin fields were renamed from pin_sscb_* to pin_sccb_* partway
// through esp32-camera's history, and both spellings are still in the wild
// depending on which core version is installed.  Rather than make the build
// depend on guessing right, pick whichever member actually exists: the int
// overload is preferred and only survives substitution if pin_sccb_sda is
// there, otherwise the long overload takes over.
// --------------------------------------------------------------------------
template <typename C>
static auto cam_set_sccb(C& c, int sda, int scl, int)
    -> decltype(c.pin_sccb_sda, void())
{
    c.pin_sccb_sda = sda;
    c.pin_sccb_scl = scl;
}

template <typename C>
static auto cam_set_sccb(C& c, int sda, int scl, long)
    -> decltype(c.pin_sscb_sda, void())
{
    c.pin_sscb_sda = sda;
    c.pin_sscb_scl = scl;
}

mw_err_t mw_camera_init(void)
{
    if (s_cam_ready) return MW_OK;

#if !HAS_PSRAM
#error "HAS_CAMERA needs HAS_PSRAM: an OV2640 framebuffer does not fit in DRAM"
#endif
    // The driver is asked for PSRAM explicitly below, so a board that lost its
    // PSRAM at runtime must not get as far as esp_camera_init().
    if (!psramFound()) return MW_ERR_MEMORY;

    camera_config_t cfg;
    memset(&cfg, 0, sizeof(cfg));

    cfg.ledc_channel = CAM_LEDC_CHANNEL;
    cfg.ledc_timer   = CAM_LEDC_TIMER;

    cfg.pin_d0    = CAM_PIN_D0;
    cfg.pin_d1    = CAM_PIN_D1;
    cfg.pin_d2    = CAM_PIN_D2;
    cfg.pin_d3    = CAM_PIN_D3;
    cfg.pin_d4    = CAM_PIN_D4;
    cfg.pin_d5    = CAM_PIN_D5;
    cfg.pin_d6    = CAM_PIN_D6;
    cfg.pin_d7    = CAM_PIN_D7;
    cfg.pin_xclk  = CAM_PIN_XCLK;
    cfg.pin_pclk  = CAM_PIN_PCLK;
    cfg.pin_vsync = CAM_PIN_VSYNC;
    cfg.pin_href  = CAM_PIN_HREF;
    cfg.pin_pwdn  = CAM_PIN_PWDN;
    cfg.pin_reset = CAM_PIN_RESET;
    cam_set_sccb(cfg, CAM_PIN_SIOD, CAM_PIN_SIOC, 0);

    cfg.xclk_freq_hz = CAM_XCLK_FREQ_HZ;
    cfg.pixel_format = PIXFORMAT_GRAYSCALE;
    cfg.frame_size   = CAMERA_FRAME_SIZE;
    cfg.jpeg_quality = 12;              // unused for grayscale, kept sane
    cfg.fb_count     = 2;               // one for the decoder, one for the UI
    cfg.fb_location  = CAMERA_FB_IN_PSRAM;
    // A scanner wants the newest frame, not the oldest: with WHEN_EMPTY the
    // decoder would work through a backlog and the viewfinder would lag
    // behind the user's hand.
    cfg.grab_mode    = CAMERA_GRAB_LATEST;

    if (esp_camera_init(&cfg) != ESP_OK) return MW_ERR_IO;

    sensor_t* s = esp_camera_sensor_get();
    if (s) {
        if (s->set_vflip)    s->set_vflip(s, CAM_VFLIP);
        if (s->set_hmirror)  s->set_hmirror(s, CAM_HMIRROR);
        // A QR symbol is pure black-and-white, so push contrast up one notch
        // and leave brightness alone; over-brightening washes out the quiet
        // zone and costs more decodes than it gains.
        if (s->set_contrast) s->set_contrast(s, 1);
    }

    s_cam_ready = true;
    return MW_OK;
}

void mw_camera_deinit(void)
{
    if (!s_cam_ready) return;
    if (s_held) { esp_camera_fb_return(s_held); s_held = nullptr; }
    esp_camera_deinit();
    s_cam_ready = false;
}

mw_err_t mw_camera_capture(mw_camera_frame_t* out)
{
    if (!out) return MW_ERR_INVALID_ARG;
    out->data = NULL;
    out->width = 0;
    out->height = 0;
    if (!s_cam_ready) return MW_ERR_IO;

    // Hand the previous frame back first - hal.h says it is only valid until
    // this call, and the driver needs the buffer returned before it can fill
    // the next one.
    if (s_held) { esp_camera_fb_return(s_held); s_held = nullptr; }

    camera_fb_t* fb = esp_camera_fb_get();
    if (!fb) return MW_ERR_IO;

    if (fb->format != PIXFORMAT_GRAYSCALE ||
        fb->len < (size_t)fb->width * (size_t)fb->height) {
        esp_camera_fb_return(fb);
        return MW_ERR_FORMAT;
    }

    s_held      = fb;
    out->data   = fb->buf;
    out->width  = (uint16_t)fb->width;
    out->height = (uint16_t)fb->height;
    return MW_OK;
}

mw_err_t mw_camera_preview(uint16_t* out, uint16_t w, uint16_t h)
{
    if (!out || w == 0 || h == 0) return MW_ERR_INVALID_ARG;
    if (!s_cam_ready) return MW_ERR_IO;

    // Own borrow, own return: whatever mw_camera_capture() lent out stays
    // valid across this call.
    camera_fb_t* fb = esp_camera_fb_get();
    if (!fb) return MW_ERR_IO;

    if (fb->format != PIXFORMAT_GRAYSCALE ||
        fb->len < (size_t)fb->width * (size_t)fb->height ||
        fb->width == 0 || fb->height == 0) {
        esp_camera_fb_return(fb);
        return MW_ERR_FORMAT;
    }

    // Nearest-neighbour, Q16 fixed-point stepping.  Box filtering would look
    // nicer, but the viewfinder is an aiming aid - the decoder works on the
    // full-resolution frame - and a 480x480 panel would spend real time on it
    // every frame.
    const uint32_t step_x = ((uint32_t)fb->width  << 16) / w;
    const uint32_t step_y = ((uint32_t)fb->height << 16) / h;

    for (uint16_t y = 0; y < h; ++y) {
        uint32_t src_y = ((uint32_t)y * step_y) >> 16;
        if (src_y >= fb->height) src_y = fb->height - 1u;    // belt and braces
        const uint8_t* row = fb->buf + (size_t)src_y * (size_t)fb->width;

        uint16_t* dst = out + (size_t)y * (size_t)w;
        uint32_t  ax  = 0;
        for (uint16_t x = 0; x < w; ++x) {
            uint32_t src_x = ax >> 16;
            if (src_x >= fb->width) src_x = fb->width - 1u;
            const uint8_t g = row[src_x];
            // Grey -> RGB565 on the diagonal: top 5/6/5 bits of the same byte.
            dst[x] = (uint16_t)(((uint16_t)(g & 0xF8) << 8) |
                                ((uint16_t)(g & 0xFC) << 3) |
                                 (uint16_t)(g >> 3));
            ax += step_x;
        }
    }

    esp_camera_fb_return(fb);
    return MW_OK;
}

#endif  // HAS_CAMERA
#endif  // ARDUINO && !MW_HOST_BUILD
