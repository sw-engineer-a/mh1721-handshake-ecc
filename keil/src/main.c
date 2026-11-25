#include "ecc.h"

#include <stdio.h>

void handshake_loop(void);

int main(void) {
    int ok = ecc_selftest();
    printf(ok ? "MH1721 ECC handshake\nself-test ok\n" : "MH1721 ECC handshake\nself-test FAIL\n");
    if (!ok) {
#ifdef MH1721_HOST
        return 1;
#else
        while (1) {
        }
#endif
    }
#ifdef MH1721_HOST
    return 0;
#else
    printf("waiting for the phone\n");
    handshake_loop();
    return 0;
#endif
}
