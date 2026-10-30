/* Offline runner: firmware C + existing host field backend, no target access. */
#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <time.h>
#include "../../crypto/x25519.h"
#include "../../crypto/ed25519.h"
#include "../../crypto/sha256.h"
#include "../../crypto/sha512.h"

static uint8_t msg[4096], out[64], k[32], u[32];
static unsigned unhex(const char *s, uint8_t *p) {
    unsigned n = 0, v;
    if (!strcmp(s, "-")) return 0;
    while (*s && sscanf(s, "%2x", &v) == 1) { p[n++] = v; s += 2; }
    return n;
}
static void hex(const uint8_t *p, unsigned n) {
    while (n--) printf("%02x", *p++);
    putchar('\n');
}
int main(void) {
    char op[8], a[8193], b[129];
    ed_init();
    while (scanf("%7s %8192s", op, a) == 2) {
        unsigned n = unhex(a, msg), steps = 0;
        if (op[0] == 'x') {
            if (n != 32 || scanf("%128s", b) != 1 || unhex(b, u) != 32) return 2;
            memcpy(k, msg, 32); memcpy(x25519_k, k, 32); memcpy(x25519_u, u, 32);
            x25519_start();
            while (!x25519_step()) { if (++steps > 1024) return 3; }
            hex(x25519_r, 32);
        } else if (op[0] == 's') {
            if (n != 32) return 2;
            ed_sign_start(msg);
            while (!ed_sign_step()) { if (++steps > 1024) return 3; }
            hex(ed_sig, 64);
        } else if (op[0] == 'h') {
            sha512_init();
            /* Deliberately split updates to exercise buffer transitions. */
            for (unsigned i=0; i<n; i+=7) sha512_update(msg+i, n-i<7?n-i:7);
            sha512_final_begin(out);
            while (!sha512_final_step()) { if (++steps > 128) return 3; }
            hex(out, 64);
        } else if (op[0] == 'g') {
            sha256_init(); sha256_update(msg, n); sha256_final(out); hex(out, 32);
        } else return 2;
    }
    return 0;
}
