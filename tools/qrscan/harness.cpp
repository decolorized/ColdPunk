#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <vector>
#include <string>
extern "C" {
#include "transfer/qr_encode.h"
#include "hal/hal.h"
mw_err_t mw_camera_capture(mw_camera_frame_t* f) { (void)f; return MW_ERR_IO; }
}
extern "C" mw_err_t mw_qr_scan_frame(const uint8_t*, uint16_t, uint16_t, char*, size_t);
static bool read_pgm(const char* p, std::vector<uint8_t>& px, int& w, int& h) {
    FILE* f = fopen(p, "rb"); if (!f) return false;
    char m[3]={0}; int mx; if (fscanf(f, "%2s %d %d %d", m, &w, &h, &mx) != 4) { fclose(f); return false; }
    fgetc(f); px.resize((size_t)w*h); size_t n=fread(px.data(),1,px.size(),f); fclose(f); return n==px.size();
}
int main(int argc, char** argv) {
    int ok=0, bad=0;
    for (int i = 1; i < argc; i++) {
        std::string pgm = std::string(argv[i]) + ".pgm", txt = std::string(argv[i]) + ".txt";
        std::vector<uint8_t> px; int w, h;
        if (!read_pgm(pgm.c_str(), px, w, h)) continue;
        FILE* f = fopen(txt.c_str(), "r"); char meta[64], want[2048];
        if (!fgets(meta, sizeof meta, f) || !fgets(want, sizeof want, f)) return 2; fclose(f);
        want[strcspn(want, "\n")] = 0; meta[strcspn(meta, "\n")] = 0;
        static char out[2048];
        mw_err_t e = mw_qr_scan_frame(px.data(), (uint16_t)w, (uint16_t)h, out, sizeof out);
        bool good = (e == MW_OK && strcmp(out, want) == 0);
        if (good) ok++; else { bad++; printf("FAIL %s [%s] err=%d\n", argv[i], meta, (int)e); }
    }
    printf("ok %d bad %d\n", ok, bad);
    return bad ? 1 : 0;
}
