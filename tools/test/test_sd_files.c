// SD card file browser: classification, dates, ordering, result names.
#include "test_framework.h"
#include "transfer/sd_files.h"
#include "monero/file_formats.h"

#include <string.h>

static mw_sd_entry_t ent(const char* name, int64_t mtime)
{
    mw_sd_entry_t e;
    memset(&e, 0, sizeof(e));
    strncpy(e.name, name, sizeof(e.name) - 1);
    e.mtime = mtime;
    return e;
}

MW_TEST(test_kind_by_magic)
{
    uint8_t h[MW_SDF_HEAD_LEN];
    memset(h, 0, sizeof(h));
    memcpy(h, MW_MAGIC_OUTPUTS, MW_MAGIC_OUTPUTS_LEN);
    CHECK_EQ_INT(mw_sdf_kind(h, sizeof(h)), MW_SDF_OUTPUTS);

    memset(h, 0, sizeof(h));
    memcpy(h, MW_MAGIC_UNSIGNED_TX, MW_MAGIC_UNSIGNED_TX_LEN);
    h[MW_MAGIC_UNSIGNED_TX_LEN] = MW_UNSIGNED_TX_VERSION;
    CHECK_EQ_INT(mw_sdf_kind(h, sizeof(h)), MW_SDF_UNSIGNED);

    // Results the device wrote, other versions and junk are not listed.
    memset(h, 0, sizeof(h));
    memcpy(h, MW_MAGIC_KEYIMAGES, MW_MAGIC_KEYIMAGES_LEN);
    CHECK_EQ_INT(mw_sdf_kind(h, sizeof(h)), MW_SDF_NONE);
    memset(h, 0, sizeof(h));
    memcpy(h, MW_MAGIC_SIGNED_TX, MW_MAGIC_SIGNED_TX_LEN);
    h[MW_MAGIC_SIGNED_TX_LEN] = MW_UNSIGNED_TX_VERSION;
    CHECK_EQ_INT(mw_sdf_kind(h, sizeof(h)), MW_SDF_NONE);
    memset(h, 0, sizeof(h));
    memcpy(h, MW_MAGIC_UNSIGNED_TX, MW_MAGIC_UNSIGNED_TX_LEN);
    h[MW_MAGIC_UNSIGNED_TX_LEN] = (uint8_t)(MW_UNSIGNED_TX_VERSION + 1);
    CHECK_EQ_INT(mw_sdf_kind(h, sizeof(h)), MW_SDF_NONE);
    CHECK_EQ_INT(mw_sdf_kind((const uint8_t*)"hello", 5), MW_SDF_NONE);
    CHECK_EQ_INT(mw_sdf_kind(NULL, 0), MW_SDF_NONE);
}

MW_TEST(test_name_time)
{
    int64_t t = 0;
    CHECK(mw_sdf_name_time("1789839233_unsigned_monero_tx", &t));
    CHECK_EQ_INT(t, 1789839233);
    CHECK(mw_sdf_name_time("borya-view2_1789637203_outputs", &t));
    CHECK_EQ_INT(t, 1789637203);
    // The first plausible 10-digit run wins; other lengths are ignored.
    CHECK(mw_sdf_name_time("w2_123_17896372031_1789637210_outputs", &t));
    CHECK_EQ_INT(t, 1789637210);
    CHECK(!mw_sdf_name_time("wallet_outputs", &t));
    CHECK(!mw_sdf_name_time("x_0000000001_outputs", &t));   // 1970: not a date
    CHECK(!mw_sdf_name_time(NULL, &t));

    CHECK(!mw_sdf_time_valid(0));
    CHECK(!mw_sdf_time_valid(315532800));                    // FAT zero, 1980-01-01
    CHECK(mw_sdf_time_valid(1789839233));
}

MW_TEST(test_sort_newest_first)
{
    mw_sd_entry_t e[5];
    e[0] = ent("a_1700000000_outputs", 0);                   // no FAT date: name time
    e[1] = ent("b_outputs", 1790000000);                     // FAT date
    e[2] = ent("c_1800000000_outputs", 1600000000);          // FAT date wins over name
    e[3] = ent("d_outputs", 315532800);                      // FAT zero and no name time
    e[4] = ent("1795000000_unsigned_monero_tx", 0);
    mw_sdf_sort(e, 5);
    CHECK(strcmp(e[0].name, "1795000000_unsigned_monero_tx") == 0);
    CHECK(strcmp(e[1].name, "b_outputs") == 0);
    CHECK(strcmp(e[2].name, "a_1700000000_outputs") == 0);
    CHECK(strcmp(e[3].name, "c_1800000000_outputs") == 0);
    CHECK(strcmp(e[4].name, "d_outputs") == 0);
    CHECK_EQ_INT(mw_sdf_sort_time(&e[3]), 1600000000);
}

MW_TEST(test_result_names)
{
    char out[MW_SD_ENTRY_NAME];
    CHECK_EQ_INT(mw_sdf_result_name(MW_SDF_OUTPUTS, "borya_1789637203_outputs", out, sizeof out), MW_OK);
    CHECK(strcmp(out, "borya_1789637203_keyImages") == 0);
    CHECK_EQ_INT(mw_sdf_result_name(MW_SDF_OUTPUTS, "my export.bin", out, sizeof out), MW_OK);
    CHECK(strcmp(out, "my export.bin_keyImages") == 0);
    CHECK_EQ_INT(mw_sdf_result_name(MW_SDF_UNSIGNED, "1789839233_unsigned_monero_tx", out, sizeof out), MW_OK);
    CHECK(strcmp(out, "1789839233_signed_monero_tx") == 0);
    CHECK_EQ_INT(mw_sdf_result_name(MW_SDF_UNSIGNED, "tx.bin", out, sizeof out), MW_OK);
    CHECK(strcmp(out, "tx.bin_signed_monero_tx") == 0);
    CHECK_EQ_INT(mw_sdf_result_name(MW_SDF_NONE, "x", out, sizeof out), MW_ERR_INVALID_ARG);

    // A long source name is shortened so the result still fits.
    char longname[MW_SD_ENTRY_NAME];
    memset(longname, 'w', sizeof(longname) - 1 - 8);
    strcpy(longname + sizeof(longname) - 1 - 8, "_outputs");
    CHECK_EQ_INT((int)strlen(longname), MW_SD_ENTRY_NAME - 1);
    CHECK_EQ_INT(mw_sdf_result_name(MW_SDF_OUTPUTS, longname, out, sizeof out), MW_OK);
    CHECK_EQ_INT((int)strlen(out), MW_SD_ENTRY_NAME - 1);
    CHECK(strcmp(out + strlen(out) - 10, "_keyImages") == 0);
    char small[8];
    CHECK_EQ_INT(mw_sdf_result_name(MW_SDF_OUTPUTS, "x_outputs", small, sizeof small), MW_ERR_RANGE);
}

MW_TEST(test_readme)
{
    CHECK(strcmp(mw_sdf_readme_name, "ColdPunk_readme.txt") == 0);
    CHECK(strstr(mw_sdf_readme_text, "FAT32") != NULL);
}

static const char* safe(const char* in)
{
    static char out[40];
    if (mw_sdf_safe_name(in, out, sizeof out) != MW_OK) return "<err>";
    return out;
}

MW_TEST(test_safe_names)
{
    CHECK(strcmp(safe("main"), "main") == 0);
    CHECK(strcmp(safe("my wallet 2"), "my wallet 2") == 0);
    CHECK(strcmp(safe("a/b\\c:d*e?f\"g<h>i|j"), "a_b_c_d_e_f_g_h_i_j") == 0);
    CHECK(strcmp(safe("  lead"), "lead") == 0);
    CHECK(strcmp(safe("trail. . "), "trail") == 0);
    CHECK(strcmp(safe("..."), "wallet") == 0);
    CHECK(strcmp(safe(""), "wallet") == 0);
    CHECK(strcmp(safe("\x01\x7f"), "__") == 0);
    CHECK(strcmp(safe("CON"), "_CON") == 0);
    CHECK(strcmp(safe("nul.x"), "_nul.x") == 0);
    CHECK(strcmp(safe("com7"), "_com7") == 0);
    CHECK(strcmp(safe("COM0"), "COM0") == 0);
    CHECK(strcmp(safe("CONSOLE"), "CONSOLE") == 0);
    char small[8];
    CHECK_EQ_INT(mw_sdf_safe_name("abcdefghijk", small, sizeof small), MW_OK);
    CHECK(strcmp(small, "abcdef") == 0);
    CHECK(mw_sdf_safe_name("x", small, 4) != MW_OK);
}

MW_TEST(test_viewonly_names)
{
    char out[MW_SD_ENTRY_NAME];
    CHECK_EQ_INT(mw_sdf_viewonly_name("my/wallet", 1, out, sizeof out), MW_OK);
    CHECK(strcmp(out, "my_wallet_viewonly.txt") == 0);
    CHECK_EQ_INT(mw_sdf_viewonly_name("aux", 3, out, sizeof out), MW_OK);
    CHECK(strcmp(out, "_aux_viewonly_3.txt") == 0);
    CHECK_EQ_INT(mw_sdf_viewonly_name("0123456789012345678901234567890", 99, out, sizeof out), MW_OK);
    CHECK(strcmp(out, "0123456789012345678901234567890_viewonly_99.txt") == 0);
}

int main(void)
{
    RUN_TEST(test_safe_names);
    RUN_TEST(test_viewonly_names);
    RUN_TEST(test_kind_by_magic);
    RUN_TEST(test_name_time);
    RUN_TEST(test_sort_newest_first);
    RUN_TEST(test_result_names);
    RUN_TEST(test_readme);
    return mw_test_summary();
}
