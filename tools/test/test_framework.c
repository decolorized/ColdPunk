#include "test_framework.h"

int mw_test_failures = 0;
int mw_test_checks = 0;
const char* mw_test_current = "(none)";

void mw_test_hexdump(const char* label, const uint8_t* data, size_t len) {
    printf("%s ", label);
    for (size_t i = 0; i < len; ++i) {
        printf("%02x", data[i]);
        if (i == 47 && len > 48) { printf("..."); break; }
    }
    printf("\n");
}

static int hexval(char c) {
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
}

size_t mw_test_hex(const char* hex, uint8_t* out, size_t cap) {
    size_t n = 0;
    while (hex[0] && hex[1] && n < cap) {
        int hi = hexval(hex[0]), lo = hexval(hex[1]);
        if (hi < 0 || lo < 0) break;
        out[n++] = (uint8_t)((hi << 4) | lo);
        hex += 2;
    }
    return n;
}

int mw_test_summary(void) {
    printf("\n%d checks, %d failures\n", mw_test_checks, mw_test_failures);
    return mw_test_failures == 0 ? 0 : 1;
}
