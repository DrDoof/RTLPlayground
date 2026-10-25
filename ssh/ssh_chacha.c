#pragma codeseg BANK4
#pragma constseg BANK4

#include <stdint.h>
#include "../crypto/chacha.h"
#include "ssh.h"

void chacha_20(void);
void chacha_update(void);
void chacha_count(void);

__xdata struct chacha20_t __at(0xbf00) chacha20;

static __code const uint8_t sigma[16] = {
	0x61, 0x70, 0x78, 0x65, 0x33, 0x20, 0x64, 0x6e,
	0x79, 0x62, 0x2d, 0x32, 0x6b, 0x20, 0x65, 0x74
};

void ssh_chacha_xor(__xdata const uint8_t *key, __xdata const uint8_t *seq, uint8_t ctr, __xdata uint8_t *buf, uint16_t len) __reentrant
{
	static __xdata uint8_t i, n;
	static __xdata uint8_t * __xdata b;
	static __xdata uint16_t l;
	__xdata uint8_t *c = (__xdata uint8_t *)&chacha20.cnt;

	for (i = 0; i < 16; i++)
		chacha20.constant[i] = sigma[i];
	for (i = 0; i < 32; i++)
		chacha20.key[i] = key[(i & ~3) | (3 - (i & 3))];
	ctr--;
	c[0] = ctr == 0xff ? 0xff : 0;
	c[1] = c[0];
	c[2] = c[0];
	c[3] = ctr;
	for (i = 0; i < 4; i++)
		chacha20.nonce[i] = 0;
	for (i = 0; i < 8; i++)
		chacha20.nonce[4 + i] = seq[(i & ~3) | (3 - (i & 3))];
	b = buf;
	l = len;
	while (l) {
		chacha_count();
		for (i = 0; i < 64; i++)
			chacha20.wstate[i] = chacha20.wstate[64 + i];
		chacha_20();
		chacha_update();
		n = l > 64 ? 64 : l;
		for (i = 0; i < n; i++)
			*b++ ^= chacha20.wstate[i];
		l -= n;
	}
}

