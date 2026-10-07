// Touch coordinate pipeline - see touch_map.h.
#include "touch_map.h"

#define MW_Q16 65536

uint16_t mw_touch_logical_w(const mw_touch_geom_t* g)
{
    return (g->rotation & 1) ? g->native_h : g->native_w;
}

uint16_t mw_touch_logical_h(const mw_touch_geom_t* g)
{
    return (g->rotation & 1) ? g->native_w : g->native_h;
}

static uint16_t clamp_u16(int64_t v, uint16_t n)
{
    if (v < 0) return 0;
    if (n == 0) return 0;
    if (v > (int64_t)n - 1) return (uint16_t)(n - 1);
    return (uint16_t)v;
}

void mw_touch_map_point(const mw_touch_geom_t* g, int32_t rx, int32_t ry,
                        uint16_t* x, uint16_t* y)
{
    const int32_t W0 = g->native_w, H0 = g->native_h;
    if (g->swap_xy) { int32_t t = rx; rx = ry; ry = t; }
    if (g->mirror_x) rx = W0 - 1 - rx;
    if (g->mirror_y) ry = H0 - 1 - ry;

    int32_t lx, ly;
    switch (g->rotation & 3) {
    case 1:  lx = ry;          ly = W0 - 1 - rx; break;
    case 2:  lx = W0 - 1 - rx; ly = H0 - 1 - ry; break;
    case 3:  lx = H0 - 1 - ry; ly = rx;          break;
    default: lx = rx;          ly = ry;          break;
    }
    *x = clamp_u16(lx, mw_touch_logical_w(g));
    *y = clamp_u16(ly, mw_touch_logical_h(g));
}

static void cal_eval(const int32_t c[6], int32_t u, int32_t v,
                     int64_t* fx, int64_t* fy)
{
    // Arithmetic shift of a negative value rounds toward -inf on every
    // supported compiler; the clamp below makes that irrelevant.
    *fx = ((int64_t)c[0] * u + (int64_t)c[1] * v + c[2]) >> 16;
    *fy = ((int64_t)c[3] * u + (int64_t)c[4] * v + c[5]) >> 16;
}

void mw_touch_cal_apply(const int32_t c[6], int32_t u, int32_t v,
                        uint16_t w, uint16_t h, uint16_t* x, uint16_t* y)
{
    int64_t fx, fy;
    cal_eval(c, u, v, &fx, &fy);
    *x = clamp_u16(fx, w);
    *y = clamp_u16(fy, h);
}

int32_t mw_touch_cal_error(const int32_t c[6], int32_t u, int32_t v,
                           int32_t tx, int32_t ty)
{
    int64_t fx, fy;
    cal_eval(c, u, v, &fx, &fy);
    int64_t ex = fx - tx, ey = fy - ty;
    if (ex < 0) ex = -ex;
    if (ey < 0) ey = -ey;
    int64_t m = ex > ey ? ex : ey;
    return m > 0x7FFFFFFF ? 0x7FFFFFFF : (int32_t)m;
}

int mw_touch_cal_solve(const int32_t ui[3], const int32_t vi[3],
                       const int32_t txi[3], const int32_t tyi[3], int32_t c[6])
{
    double u[3], v[3], x[3], y[3];
    for (int i = 0; i < 3; ++i) {
        u[i] = ui[i]; v[i] = vi[i]; x[i] = txi[i]; y[i] = tyi[i];
    }
    // Solve [u v 1] * [a b c]^T = x and the same for y (Cramer's rule).
    const double det = u[0] * (v[1] - v[2]) - v[0] * (u[1] - u[2])
                     + (u[1] * v[2] - u[2] * v[1]);
    if (det > -1e-6 && det < 1e-6) return -1;            // collinear taps

    double dv[6];
    const double* t[2] = { x, y };
    for (int k = 0; k < 2; ++k) {
        const double* p = t[k];
        dv[3 * k + 0] = (p[0] * (v[1] - v[2]) - v[0] * (p[1] - p[2])
                         + (p[1] * v[2] - p[2] * v[1])) / det;
        dv[3 * k + 1] = (u[0] * (p[1] - p[2]) - p[0] * (u[1] - u[2])
                         + (u[1] * p[2] - u[2] * p[1])) / det;
        dv[3 * k + 2] = (u[0] * (v[1] * p[2] - v[2] * p[1])
                         - v[0] * (u[1] * p[2] - u[2] * p[1])
                         + p[0] * (u[1] * v[2] - u[2] * v[1])) / det;
    }
    for (int i = 0; i < 6; ++i) {
        double q = dv[i] * (double)MW_Q16;
        if (q > 2147483000.0 || q < -2147483000.0) return -1;
        c[i] = (int32_t)(q + (q < 0 ? -0.5 : 0.5));
    }
    return 0;
}

void mw_touch_cal_tag_make(uint8_t tag[3], uint8_t rotation,
                           uint16_t width, uint16_t height)
{
    tag[0] = (uint8_t)(0x80u | ((rotation & 3u) << 2) | (MW_TOUCH_MAP_VERSION & 3u));
    tag[1] = (uint8_t)(width / 8u);
    tag[2] = (uint8_t)(height / 8u);
}

bool mw_touch_cal_tag_ok(const uint8_t tag[3], uint8_t rotation,
                         uint16_t width, uint16_t height)
{
    if (tag[0] == 0 && tag[1] == 0 && tag[2] == 0) return (rotation & 3) == 0;
    uint8_t want[3];
    mw_touch_cal_tag_make(want, rotation, width, height);
    return tag[0] == want[0] && tag[1] == want[1] && tag[2] == want[2];
}
