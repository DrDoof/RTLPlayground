#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include "../../crypto/sha512.h"
#include "../../crypto/ed25519.h"
#include "../../crypto/x25519.h"

int main(int argc, char **argv)
{
	uint8_t out[64], m[32];
	sha512_init();
	sha512_update((const uint8_t *)"abc", 3);
	sha512_final(out);
	for (int i = 0; i < 64; i++) printf("%02x", out[i]);
	printf("\n");
	uint8_t big[300];
	for (int i = 0; i < 300; i++) big[i] = i;
	sha512_init();
	sha512_update(big, 300);
	sha512_final(out);
	for (int i = 0; i < 64; i++) printf("%02x", out[i]);
	printf("\n");
	for (int i = 0; i < 32; i++) m[i] = argc > 1 ? argv[1][i % strlen(argv[1])] : i;
	ed_init();
	ed_sign_start(m);
	int steps = 1;
	while (!ed_sign_step()) steps++;
	for (int i = 0; i < 64; i++) printf("%02x", ed_sig[i]);
	printf("\nsteps %d\n", steps);
	return 0;
}
