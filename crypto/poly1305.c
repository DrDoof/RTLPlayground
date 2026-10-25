#pragma codeseg BANK4
#pragma constseg BANK4

#include <stdint.h>
#include "poly1305.h"

__xdata struct poly1305_t poly1305;

__xdata __at(0xbea0) uint8_t pm_h[17];
__xdata __at(0xbeb1) uint8_t pm_r[16];

void poly_block_hi(__xdata const uint8_t *src);
void poly_block_lo(__xdata const uint8_t *src);

void poly1305_init(__xdata const uint8_t *key)
{
	uint8_t i;

	for (i = 0; i < 16; i++) {
		pm_r[i] = key[i];
		poly1305.s[i] = key[i + 16];
		pm_h[i] = 0;
	}
	pm_r[3] &= 15;
	pm_r[7] &= 15;
	pm_r[11] &= 15;
	pm_r[15] &= 15;
	pm_r[4] &= 252;
	pm_r[8] &= 252;
	pm_r[12] &= 252;
	pm_h[16] = 0;
	poly1305.fill = 0;
}

void poly1305_update(__xdata const uint8_t *p, uint16_t n) __reentrant
{
	static __xdata const uint8_t * __xdata sp;
	static __xdata uint16_t sn;

	sp = p;
	sn = n;
	while (sn) {
		if (!poly1305.fill && sn >= 16) {
			poly_block_hi(sp);
			sp += 16;
			sn -= 16;
			continue;
		}
		poly1305.buf[poly1305.fill++] = *sp++;
		sn--;
		if (poly1305.fill == 16) {
			poly_block_hi(poly1305.buf);
			poly1305.fill = 0;
		}
	}
}

void poly1305_final(__xdata uint8_t *tag)
{
	static __xdata uint8_t i, sel;
	static __xdata uint16_t t;
	static __xdata uint8_t g[16];

	if (poly1305.fill) {
		poly1305.buf[poly1305.fill++] = 1;
		while (poly1305.fill < 16)
			poly1305.buf[poly1305.fill++] = 0;
		poly_block_lo(poly1305.buf);
	}

	t = 5;
	for (i = 0; i < 16; i++) {
		t += pm_h[i];
		g[i] = t;
		t >>= 8;
	}
	t += pm_h[16];
	sel = t >= 4;

	t = 0;
	for (i = 0; i < 16; i++) {
		t += (sel ? g[i] : pm_h[i]) + poly1305.s[i];
		tag[i] = t;
		t >>= 8;
	}
}
