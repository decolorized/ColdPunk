/*
 * Host (desktop) implementation of the HAL.
 *
 * This is what lets the rest of the wallet be exercised on a PC: the crypto,
 * the Monero serialisation, the file formats and - with an SDL LVGL port - the
 * UI, all without an ESP32 on the desk.  Everything device-specific is
 * replaced by the simplest honest equivalent:
 *
 *   display   an in-memory 240x320 RGB565 framebuffer, dumpable as a PPM
 *   touch     absent (mw_hal_caps()->has_touch == false); host tests can
 *             still inject a single tap through mw_host_inject_touch()
 *   buttons   absent
 *   SD card   a directory tree rooted at ./sdcard/ (override with
 *             mw_host_set_sd_root()), same 64 KB / bounded-path rules as the
 *             device build so tests hit the same limits
 *   camera    absent; every mw_camera_* call returns MW_ERR_NOT_SUPPORTED
 *   clock     CLOCK_MONOTONIC, plus an offset the tests can advance
 *   power     no battery, no USB
 *
 * Builds with:
 *   gcc -std=c11 -Wall -Wextra -c -Isrc -DMW_HOST_BUILD=1 src/hal/hal_host.c
 */
#ifdef MW_HOST_BUILD

/* clock_gettime, strnlen, mkdir(2) and friends under -std=c11 (__STRICT_ANSI__). */
#define _POSIX_C_SOURCE 200809L

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <errno.h>
#include <dirent.h>
#include <unistd.h>
#include <sys/stat.h>
#include <sys/types.h>

/* Windows host (mingw-w64): mkdir() takes no mode argument. */
#if defined(_WIN32)
#  include <direct.h>
#  define MW_HOST_MKDIR(p, m) _mkdir(p)
#else
#  define MW_HOST_MKDIR(p, m) mkdir((p), (m))
#endif

#include "hal.h"
#include "display_drivers.h"

/* ======================================================================== */
/* Display                                                                  */
/* ======================================================================== */

#define HOST_W 240
#define HOST_H 320

static uint16_t s_fb[HOST_W * HOST_H];
static int      s_backlight = 100;
static int      s_display_up = 0;

mw_err_t mw_display_init(void)
{
    memset(s_fb, 0, sizeof(s_fb));      /* dark theme, like the device */
    s_display_up = 1;
    return MW_OK;
}

void mw_display_backlight(uint8_t percent)
{
    s_backlight = (percent > 100) ? 100 : (int)percent;
}

void mw_display_blit(int16_t x, int16_t y, int16_t w, int16_t h,
                     const uint16_t* pixels)
{
    int16_t row, col;

    if (!s_display_up || !pixels || w <= 0 || h <= 0) return;

    for (row = 0; row < h; ++row) {
        int16_t py = (int16_t)(y + row);
        if (py < 0 || py >= HOST_H) continue;
        for (col = 0; col < w; ++col) {
            int16_t px = (int16_t)(x + col);
            if (px < 0 || px >= HOST_W) continue;
            s_fb[(size_t)py * HOST_W + (size_t)px] =
                pixels[(size_t)row * (size_t)w + (size_t)col];
        }
    }
}

void mw_display_fill(uint16_t rgb565)
{
    size_t i;
    for (i = 0; i < (size_t)(HOST_W * HOST_H); ++i) s_fb[i] = rgb565;
}

void mw_display_flush(void)   { /* the framebuffer is the display */ }
void mw_display_wait_dma(void) { /* synchronous */ }
bool mw_display_is_mono(void)  { return false; }

mw_err_t mw_host_dump_ppm(const char* path)
{
    FILE*  f;
    size_t i;

    if (!path) return MW_ERR_INVALID_ARG;
    f = fopen(path, "wb");
    if (!f) return MW_ERR_IO;

    if (fprintf(f, "P6\n%d %d\n255\n", HOST_W, HOST_H) < 0) {
        fclose(f);
        return MW_ERR_IO;
    }
    for (i = 0; i < (size_t)(HOST_W * HOST_H); ++i) {
        uint16_t c = s_fb[i];
        /* RGB565 -> RGB888, replicating the high bits into the low ones so
           white stays 0xFFFFFF instead of 0xF8FCF8. */
        unsigned char rgb[3];
        rgb[0] = (unsigned char)(((c >> 11) & 0x1F) * 255u / 31u);
        rgb[1] = (unsigned char)(((c >> 5)  & 0x3F) * 255u / 63u);
        rgb[2] = (unsigned char)(( c        & 0x1F) * 255u / 31u);
        if (fwrite(rgb, 1, 3, f) != 3) { fclose(f); return MW_ERR_IO; }
    }
    fclose(f);
    return MW_OK;
}

/* ======================================================================== */
/* Input                                                                    */
/* ======================================================================== */

static mw_touch_state_t s_injected;
static int              s_injected_armed = 0;

mw_err_t mw_touch_init(void) { return MW_ERR_NOT_SUPPORTED; }

bool mw_touch_read(mw_touch_state_t* out)
{
    if (!out) return false;
    if (s_injected_armed) {
        *out = s_injected;
        s_injected_armed = 0;           /* one-shot */
        return s_injected.pressed;
    }
    out->pressed = false;
    out->x = 0;
    out->y = 0;
    return false;
}

mw_err_t mw_touch_calibrate(int32_t coeffs[6])
{
    (void)coeffs;
    return MW_ERR_NOT_SUPPORTED;
}

void mw_host_inject_touch(uint16_t x, uint16_t y, bool pressed)
{
    s_injected.x = x;
    s_injected.y = y;
    s_injected.pressed = pressed;
    s_injected_armed = 1;
}

mw_err_t mw_buttons_init(void)                  { return MW_ERR_NOT_SUPPORTED; }
uint32_t mw_buttons_read(void)                  { return 0; }
int32_t  mw_encoder_read(void)                  { return 0; }
void     mw_buttons_poll(void)                  { }
uint32_t mw_buttons_press_ms(mw_button_t btn)   { (void)btn; return 0; }

/* ======================================================================== */
/* "SD card": a directory tree on the host filesystem                       */
/* ======================================================================== */

static char s_sd_root[MW_SD_PATH_MAX] = "./sdcard";
static int  s_sd_up = 0;

void mw_host_set_sd_root(const char* path)
{
    size_t n;
    if (!path) return;
    n = strnlen(path, sizeof(s_sd_root));
    if (n >= sizeof(s_sd_root)) return;         /* refuse, do not truncate */
    memcpy(s_sd_root, path, n);
    s_sd_root[n] = '\0';
}

/*
 * Bounded join of the SD root and a caller-supplied path.
 *
 * Same rules as the device build: the result must fit, "\\" is rejected, and
 * no component may be "..".  Without the traversal check a host test could
 * scribble outside ./sdcard/, which is exactly the class of bug the device
 * version exists to prevent - so the host keeps it too.
 */
static mw_err_t host_path(char out[MW_SD_PATH_MAX * 2], const char* in)
{
    size_t rl, il, need, o;
    const char* p;

    if (!out || !in) return MW_ERR_INVALID_ARG;

    il = strnlen(in, MW_SD_PATH_MAX);
    if (il >= MW_SD_PATH_MAX) return MW_ERR_INVALID_ARG;

    for (p = in; *p; ++p) {
        if (*p == '\\') return MW_ERR_INVALID_ARG;
        if (p[0] == '.' && p[1] == '.' &&
            (p == in || p[-1] == '/') &&
            (p[2] == '/' || p[2] == '\0')) return MW_ERR_INVALID_ARG;
    }

    rl = strnlen(s_sd_root, sizeof(s_sd_root));
    while (rl > 1 && s_sd_root[rl - 1] == '/') --rl;    /* no trailing '/' */

    need = rl + 1u + il + 1u;                            /* root + '/' + in */
    if (need > (size_t)(MW_SD_PATH_MAX * 2)) return MW_ERR_INVALID_ARG;

    memcpy(out, s_sd_root, rl);
    o = rl;
    if (in[0] != '/') out[o++] = '/';
    memcpy(out + o, in, il);
    out[o + il] = '\0';
    return MW_OK;
}

mw_err_t mw_sd_init(void)
{
    struct stat st;

    if (MW_HOST_MKDIR(s_sd_root, 0755) != 0 && errno != EEXIST) return MW_ERR_IO;
    if (stat(s_sd_root, &st) != 0 || !S_ISDIR(st.st_mode)) return MW_ERR_IO;

    s_sd_up = 1;
    return MW_OK;
}

bool mw_sd_present(void)
{
    struct stat st;
    return s_sd_up && stat(s_sd_root, &st) == 0 && S_ISDIR(st.st_mode);
}

mw_err_t mw_sd_read_file(const char* path, uint8_t* buf, size_t cap,
                         size_t* len)
{
    char   full[MW_SD_PATH_MAX * 2];
    FILE*  f;
    long   size;
    size_t got;
    mw_err_t e;

    if (len) *len = 0;
    if (!buf || cap == 0) return MW_ERR_INVALID_ARG;
    if (!s_sd_up) return MW_ERR_IO;

    e = host_path(full, path);
    if (e != MW_OK) return e;

    f = fopen(full, "rb");
    if (!f) return MW_ERR_IO;

    if (fseek(f, 0, SEEK_END) != 0) { fclose(f); return MW_ERR_IO; }
    size = ftell(f);
    if (size < 0) { fclose(f); return MW_ERR_IO; }
    if (fseek(f, 0, SEEK_SET) != 0) { fclose(f); return MW_ERR_IO; }

    if ((size_t)size > (size_t)MW_SD_FILE_MAX) { fclose(f); return MW_ERR_TOO_MANY; }
    if ((size_t)size > cap)                    { fclose(f); return MW_ERR_MEMORY; }

    got = fread(buf, 1, (size_t)size, f);
    fclose(f);
    if (got != (size_t)size) return MW_ERR_IO;

    if (len) *len = got;
    return MW_OK;
}

mw_err_t mw_sd_write_file(const char* path, const uint8_t* buf, size_t len)
{
    char  full[MW_SD_PATH_MAX * 2];
    FILE* f;
    mw_err_t e;

    if (!buf && len) return MW_ERR_INVALID_ARG;
    if (len > (size_t)MW_SD_FILE_MAX) return MW_ERR_TOO_MANY;   /* TZ 3.2 */
    if (!s_sd_up) return MW_ERR_IO;

    e = host_path(full, path);
    if (e != MW_OK) return e;

    f = fopen(full, "wb");
    if (!f) return MW_ERR_IO;

    if (len && fwrite(buf, 1, len, f) != len) {
        fclose(f);
        remove(full);
        return MW_ERR_IO;
    }
    if (fclose(f) != 0) return MW_ERR_IO;
    return MW_OK;
}

mw_err_t mw_sd_list(const char* dir, char (*names)[64], int max, int* count)
{
    char   full[MW_SD_PATH_MAX * 2];
    DIR*   d;
    struct dirent* de;
    int    n = 0;
    mw_err_t e;

    if (count) *count = 0;
    if (!names || max <= 0) return MW_ERR_INVALID_ARG;
    if (!s_sd_up) return MW_ERR_IO;

    e = host_path(full, (dir && dir[0]) ? dir : "/");
    if (e != MW_OK) return e;

    d = opendir(full);
    if (!d) return MW_ERR_IO;

    while (n < max && (de = readdir(d)) != NULL) {
        size_t nl;
        if (strcmp(de->d_name, ".") == 0 || strcmp(de->d_name, "..") == 0)
            continue;

        /* Bounded copy: at most MW_SD_NAME_MAX-1 bytes plus the terminator,
           whatever the filesystem hands back. */
        nl = strnlen(de->d_name, (size_t)MW_SD_NAME_MAX);
        if (nl >= (size_t)MW_SD_NAME_MAX) nl = (size_t)MW_SD_NAME_MAX - 1u;
        memcpy(names[n], de->d_name, nl);
        names[n][nl] = '\0';
        ++n;
    }
    closedir(d);

    if (count) *count = n;
    return MW_OK;
}

/* Quick erase, matching the device semantics: remove everything below the
   root, keep the root itself.  Bounded recursion, bounded path joins. */
static mw_err_t host_rm_tree(const char* path, int depth)
{
    DIR* d;
    struct dirent* de;
    mw_err_t rc = MW_OK;

    if (depth > 8) return MW_ERR_TOO_MANY;

    d = opendir(path);
    if (!d) return MW_ERR_IO;

    while ((de = readdir(d)) != NULL) {
        char   child[MW_SD_PATH_MAX * 2];
        size_t pl, nl;
        struct stat st;

        if (strcmp(de->d_name, ".") == 0 || strcmp(de->d_name, "..") == 0)
            continue;

        pl = strnlen(path, sizeof(child));
        nl = strnlen(de->d_name, sizeof(child));
        if (pl + 1u + nl + 1u > sizeof(child)) { rc = MW_ERR_RANGE; continue; }

        memcpy(child, path, pl);
        child[pl] = '/';
        memcpy(child + pl + 1u, de->d_name, nl);
        child[pl + 1u + nl] = '\0';

        if (stat(child, &st) != 0) { rc = MW_ERR_IO; continue; }

        if (S_ISDIR(st.st_mode)) {
            mw_err_t e = host_rm_tree(child, depth + 1);
            if (e != MW_OK) rc = e;
            if (rmdir(child) != 0) rc = MW_ERR_IO;
        } else if (remove(child) != 0) {
            rc = MW_ERR_IO;
        }
    }
    closedir(d);
    return rc;
}

mw_err_t mw_sd_format(void)
{
    if (!s_sd_up) return MW_ERR_IO;
    return host_rm_tree(s_sd_root, 0);
}

/* ======================================================================== */
/* Camera (TZ 3.7)                                                          */
/* ======================================================================== */
/*
 * There is no camera on a desktop build and no attempt is made to fake one
 * from a webcam: a fake frame source would let a QR/UR test pass without ever
 * exercising the real decoder path, which is worse than no stub at all.  The
 * host reports has_camera == false and every entry point says so, exactly as
 * a board with HAS_CAMERA = 0 does - so the UI's "this device cannot scan"
 * branch is the one the host tests actually run.
 *
 * Host-side UR decoding is tested directly against src/transfer/ur.c, which
 * takes bytes rather than pixels and needs no camera.
 */
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

/* ======================================================================== */
/* Power                                                                    */
/* ======================================================================== */

int  mw_battery_percent(void) { return -1; }   /* no gauge on a desktop */
bool mw_usb_connected(void)   { return false; }

/* ======================================================================== */
/* Clock, reboot, factory reset                                             */
/* ======================================================================== */

static uint64_t  s_t0_ms;
static int       s_clock_ready;
static uint32_t  s_time_offset_ms;

static uint64_t host_now_ms(void)
{
    struct timespec ts;
    if (clock_gettime(CLOCK_MONOTONIC, &ts) != 0) return 0;
    return (uint64_t)ts.tv_sec * 1000u + (uint64_t)(ts.tv_nsec / 1000000L);
}

uint32_t mw_millis(void)
{
    uint64_t now = host_now_ms();
    if (!s_clock_ready) { s_t0_ms = now; s_clock_ready = 1; }
    return (uint32_t)((now - s_t0_ms) + s_time_offset_ms);
}

void mw_host_advance_ms(uint32_t ms) { s_time_offset_ms += ms; }

void mw_delay_ms(uint32_t ms)
{
    struct timespec req, rem;
    req.tv_sec  = (time_t)(ms / 1000u);
    req.tv_nsec = (long)(ms % 1000u) * 1000000L;
    while (nanosleep(&req, &rem) != 0 && errno == EINTR) req = rem;
}

/*
 * A host build has nothing to reboot into.  Rather than exit() - which would
 * take a test suite down with it - the state that a reboot would clear is
 * cleared, and the caller is told.  Host tests that need to observe a reboot
 * check the counter below.
 */
static unsigned s_reboot_count;

void mw_reboot(void)
{
    ++s_reboot_count;
    fprintf(stderr, "[hal_host] mw_reboot() - host build, state reset "
                    "(reboot #%u)\n", s_reboot_count);
    memset(s_fb, 0, sizeof(s_fb));
    s_backlight      = 100;
    s_injected_armed = 0;
    s_time_offset_ms = 0;
    s_clock_ready    = 0;
}

/*
 * FACTORY RESET on the host.
 *
 * On the device this erases the entire NVS partition and destroys every
 * wallet (see hal_esp32.cpp).  There is no NVS here, so this only logs and
 * performs the reboot half - the host wallet store, wherever the test put it,
 * is the test's own business to clean up.
 */
void mw_factory_reset(void)
{
    fprintf(stderr, "[hal_host] mw_factory_reset() - on hardware this would "
                    "erase NVS and destroy every wallet.\n");
    mw_reboot();
}

/* ======================================================================== */
/* Crash diagnostics                                                        */
/* ======================================================================== */

/* The "RTC" crumb survives mw_host_simulate_reset(), like the device's
 * RTC_NOINIT memory survives a panic. */
static struct { uint8_t op, stage; uint32_t stack_free; int valid; } s_crumb, s_last;
static uint8_t s_reset_reason = MW_RESET_POWERON;

uint8_t mw_hal_reset_reason(void) { return s_reset_reason; }

void mw_hal_crumb_set(uint8_t op, uint8_t stage)
{
    s_crumb.op = op;
    s_crumb.stage = stage;
    s_crumb.stack_free = 0;              /* not measurable on the host */
    s_crumb.valid = 1;
}

void mw_hal_crumb_clear(void) { memset(&s_crumb, 0, sizeof s_crumb); }

bool mw_hal_last_crash(uint8_t* op, uint8_t* stage)
{
    if (!s_last.valid) return false;
    if (op) *op = s_last.op;
    if (stage) *stage = s_last.stage;
    return true;
}

uint32_t mw_hal_last_crash_stack_free(void) { return s_last.valid ? s_last.stack_free : 0; }
void     mw_hal_last_crash_forget(void)     { memset(&s_last, 0, sizeof s_last); }
uint32_t mw_stack_free_min(void)            { return UINT32_MAX; }

/* Test hook: behaves like a boot after a reset of the given kind. */
void mw_host_simulate_reset(uint8_t reason)
{
    const int crash = reason == MW_RESET_PANIC || reason == MW_RESET_INT_WDT ||
                      reason == MW_RESET_TASK_WDT || reason == MW_RESET_WDT ||
                      reason == MW_RESET_BROWNOUT;
    s_reset_reason = reason;
    memset(&s_last, 0, sizeof s_last);
    if (crash && s_crumb.valid && s_crumb.op != MW_CRUMB_OP_NONE) s_last = s_crumb;
    memset(&s_crumb, 0, sizeof s_crumb);
}

/* ======================================================================== */
/* Capabilities                                                             */
/* ======================================================================== */

static const mw_hal_caps_t s_caps = {
    HOST_W, HOST_H,
    0,              /* rotation    */
    false,          /* monochrome  */
    false,          /* has_touch   */
    false,          /* has_buttons */
    false,          /* has_encoder */
    true,           /* has_sd (a directory stands in for the card) */
    false,          /* has_camera  */
    false,          /* has_usb     */
    false,          /* has_psram   */
    0,              /* psram_size_mb */
    "host"
};

const mw_hal_caps_t* mw_hal_caps(void) { return &s_caps; }

mw_err_t mw_hal_init(void)
{
    mw_err_t e;

    /* Same order as the device (hal_esp32.cpp), minus the parts that have no
       host equivalent, so anything order-sensitive in the layers above shows
       up here too.  The RNG is deliberately NOT initialised from here: the
       host build gets its entropy from src/crypto/random.c, which the tests
       may have already pointed at a deterministic stream. */
    e = mw_display_init();
    if (e != MW_OK) return e;
    mw_display_backlight(100);

    (void)mw_sd_init();     /* optional, exactly as on the device */

    (void)mw_millis();      /* latch the clock origin */
    return MW_OK;
}

void mw_hal_deinit(void)
{
    s_display_up = 0;
    s_sd_up = 0;
}



mw_err_t mw_sd_unlink(const char* path)
{
    char full[MW_SD_PATH_MAX * 2];
    mw_err_t err;

    if (!mw_sd_present()) return MW_ERR_NOT_SUPPORTED;
    err = host_path(full, path);
    if (err != MW_OK) return err;
    if (remove(full) != 0) return MW_ERR_IO;
    return MW_OK;
}

#endif /* MW_HOST_BUILD */
