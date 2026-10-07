// Minimal host-side test framework. No dependencies beyond libc.
#ifndef MW_TEST_FRAMEWORK_H
#define MW_TEST_FRAMEWORK_H

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

extern int mw_test_failures;
extern int mw_test_checks;
extern const char* mw_test_current;

#define MW_TEST(name) static void name(void)

#define RUN_TEST(fn)                                                          \
    do {                                                                      \
        mw_test_current = #fn;                                                \
        int before = mw_test_failures;                                        \
        fn();                                                                 \
        printf("%s %s\n", (mw_test_failures == before) ? "  ok  " : "  FAIL", #fn); \
    } while (0)

#define CHECK(cond)                                                           \
    do {                                                                      \
        mw_test_checks++;                                                     \
        if (!(cond)) {                                                        \
            mw_test_failures++;                                               \
            printf("    ASSERT %s:%d in %s: %s\n", __FILE__, __LINE__,        \
                   mw_test_current, #cond);                                   \
        }                                                                     \
    } while (0)

#define CHECK_EQ_INT(a, b)                                                    \
    do {                                                                      \
        mw_test_checks++;                                                     \
        long long _a = (long long)(a), _b = (long long)(b);                   \
        if (_a != _b) {                                                       \
            mw_test_failures++;                                               \
            printf("    ASSERT %s:%d in %s: %s (%lld) != %s (%lld)\n",        \
                   __FILE__, __LINE__, mw_test_current, #a, _a, #b, _b);      \
        }                                                                     \
    } while (0)

#define CHECK_EQ_MEM(a, b, n)                                                 \
    do {                                                                      \
        mw_test_checks++;                                                     \
        if (memcmp((a), (b), (n)) != 0) {                                     \
            mw_test_failures++;                                               \
            printf("    ASSERT %s:%d in %s: %s != %s\n", __FILE__, __LINE__,  \
                   mw_test_current, #a, #b);                                  \
            mw_test_hexdump("      got ", (const uint8_t*)(a), (n));          \
            mw_test_hexdump("      want", (const uint8_t*)(b), (n));          \
        }                                                                     \
    } while (0)

#define CHECK_EQ_STR(a, b)                                                    \
    do {                                                                      \
        mw_test_checks++;                                                     \
        if (strcmp((a), (b)) != 0) {                                          \
            mw_test_failures++;                                               \
            printf("    ASSERT %s:%d in %s: \"%s\" != \"%s\"\n", __FILE__,    \
                   __LINE__, mw_test_current, (a), (b));                      \
        }                                                                     \
    } while (0)

void mw_test_hexdump(const char* label, const uint8_t* data, size_t len);
// Parses a hex string into `out`. Returns the number of bytes written.
size_t mw_test_hex(const char* hex, uint8_t* out, size_t cap);
int  mw_test_summary(void);

#ifdef __cplusplus
}
#endif
#endif
