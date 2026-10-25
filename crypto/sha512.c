#pragma codeseg BANK4
#pragma constseg BANK4

#include <stdint.h>
#include "sha512.h"

__xdata struct sha512_t sha512;

static __xdata uint32_t w[32];
static __xdata uint32_t v[16];
static __xdata uint32_t t1h, t1l, t2h, t2l, xh, xl;

static __code const uint32_t k[160] = {
	0x428a2f98, 0xd728ae22, 0x71374491, 0x23ef65cd, 0xb5c0fbcf, 0xec4d3b2f, 0xe9b5dba5, 0x8189dbbc,
	0x3956c25b, 0xf348b538, 0x59f111f1, 0xb605d019, 0x923f82a4, 0xaf194f9b, 0xab1c5ed5, 0xda6d8118,
	0xd807aa98, 0xa3030242, 0x12835b01, 0x45706fbe, 0x243185be, 0x4ee4b28c, 0x550c7dc3, 0xd5ffb4e2,
	0x72be5d74, 0xf27b896f, 0x80deb1fe, 0x3b1696b1, 0x9bdc06a7, 0x25c71235, 0xc19bf174, 0xcf692694,
	0xe49b69c1, 0x9ef14ad2, 0xefbe4786, 0x384f25e3, 0x0fc19dc6, 0x8b8cd5b5, 0x240ca1cc, 0x77ac9c65,
	0x2de92c6f, 0x592b0275, 0x4a7484aa, 0x6ea6e483, 0x5cb0a9dc, 0xbd41fbd4, 0x76f988da, 0x831153b5,
	0x983e5152, 0xee66dfab, 0xa831c66d, 0x2db43210, 0xb00327c8, 0x98fb213f, 0xbf597fc7, 0xbeef0ee4,
	0xc6e00bf3, 0x3da88fc2, 0xd5a79147, 0x930aa725, 0x06ca6351, 0xe003826f, 0x14292967, 0x0a0e6e70,
	0x27b70a85, 0x46d22ffc, 0x2e1b2138, 0x5c26c926, 0x4d2c6dfc, 0x5ac42aed, 0x53380d13, 0x9d95b3df,
	0x650a7354, 0x8baf63de, 0x766a0abb, 0x3c77b2a8, 0x81c2c92e, 0x47edaee6, 0x92722c85, 0x1482353b,
	0xa2bfe8a1, 0x4cf10364, 0xa81a664b, 0xbc423001, 0xc24b8b70, 0xd0f89791, 0xc76c51a3, 0x0654be30,
	0xd192e819, 0xd6ef5218, 0xd6990624, 0x5565a910, 0xf40e3585, 0x5771202a, 0x106aa070, 0x32bbd1b8,
	0x19a4c116, 0xb8d2d0c8, 0x1e376c08, 0x5141ab53, 0x2748774c, 0xdf8eeb99, 0x34b0bcb5, 0xe19b48a8,
	0x391c0cb3, 0xc5c95a63, 0x4ed8aa4a, 0xe3418acb, 0x5b9cca4f, 0x7763e373, 0x682e6ff3, 0xd6b2b8a3,
	0x748f82ee, 0x5defb2fc, 0x78a5636f, 0x43172f60, 0x84c87814, 0xa1f0ab72, 0x8cc70208, 0x1a6439ec,
	0x90befffa, 0x23631e28, 0xa4506ceb, 0xde82bde9, 0xbef9a3f7, 0xb2c67915, 0xc67178f2, 0xe372532b,
	0xca273ece, 0xea26619c, 0xd186b8c7, 0x21c0c207, 0xeada7dd6, 0xcde0eb1e, 0xf57d4f7f, 0xee6ed178,
	0x06f067aa, 0x72176fba, 0x0a637dc5, 0xa2c898a6, 0x113f9804, 0xbef90dae, 0x1b710b35, 0x131c471b,
	0x28db77f5, 0x23047d84, 0x32caab7b, 0x40c72493, 0x3c9ebe0a, 0x15c9bebc, 0x431d67c4, 0x9c100d4c,
	0x4cc5d4be, 0xcb3e42b6, 0x597f299c, 0xfc657e2a, 0x5fcb6fab, 0x3ad6faec, 0x6c44198c, 0x4a475817
};

static __code const uint32_t iv[16] = {
	0x6a09e667, 0xf3bcc908, 0xbb67ae85, 0x84caa73b, 0x3c6ef372, 0xfe94f82b, 0xa54ff53a, 0x5f1d36f1,
	0x510e527f, 0xade682d1, 0x9b05688c, 0x2b3e6c1f, 0x1f83d9ab, 0xfb41bd6b, 0x5be0cd19, 0x137e2179
};

static void rotr(uint8_t n) __reentrant
{
	uint32_t h = xh, l = xl;

	if (n >= 32) {
		h = xl;
		l = xh;
		n -= 32;
	}
	if (n) {
		xh = (h >> n) | (l << (32 - n));
		xl = (l >> n) | (h << (32 - n));
	} else {
		xh = h;
		xl = l;
	}
}

static void sigma(uint8_t a, uint8_t b, uint8_t c, uint8_t shift) __reentrant
{
	static __xdata uint32_t rh, rl, sh, sl;

	sh = xh;
	sl = xl;
	rotr(a);
	rh = xh;
	rl = xl;
	xh = sh;
	xl = sl;
	rotr(b);
	rh ^= xh;
	rl ^= xl;
	xh = sh;
	xl = sl;
	if (shift) {
		xl = (sl >> c) | (sh << (32 - c));
		xh = sh >> c;
	} else {
		rotr(c);
	}
	xh ^= rh;
	xl ^= rl;
}

static void add(__xdata uint32_t *dh, __xdata uint32_t *dl, uint32_t ah, uint32_t al) __reentrant
{
	uint32_t l = *dl + al;

	*dh += ah + (l < al);
	*dl = l;
}

static void sha512_block(void) __reentrant
{
	static __xdata uint8_t i, j;
	__xdata uint8_t *p = sha512.buf;

	for (i = 0; i < 32; i++) {
		w[i] = ((uint32_t)p[0] << 24) | ((uint32_t)p[1] << 16) | ((uint16_t)p[2] << 8) | p[3];
		p += 4;
	}
	for (i = 0; i < 16; i++)
		v[i] = sha512.h[i];
	for (i = 0; i < 80; i++) {
		j = (i & 15) << 1;
		if (i >= 16) {
			xh = w[(j + 2) & 31];
			xl = w[(j + 3) & 31];
			sigma(1, 8, 7, 1);
			t1h = xh;
			t1l = xl;
			xh = w[(j + 28) & 31];
			xl = w[(j + 29) & 31];
			sigma(19, 61, 6, 1);
			add(&t1h, &t1l, w[(j + 18) & 31], w[(j + 19) & 31]);
			add(&t1h, &t1l, xh, xl);
			add(&w[j], &w[j + 1], t1h, t1l);
		}
		xh = v[8];
		xl = v[9];
		sigma(14, 18, 41, 0);
		t1h = v[14];
		t1l = v[15];
		add(&t1h, &t1l, xh, xl);
		add(&t1h, &t1l, (v[8] & v[10]) ^ (~v[8] & v[12]), (v[9] & v[11]) ^ (~v[9] & v[13]));
		add(&t1h, &t1l, k[i << 1], k[(i << 1) + 1]);
		add(&t1h, &t1l, w[j], w[j + 1]);
		xh = v[0];
		xl = v[1];
		sigma(28, 34, 39, 0);
		t2h = xh;
		t2l = xl;
		add(&t2h, &t2l, (v[0] & v[2]) ^ (v[0] & v[4]) ^ (v[2] & v[4]), (v[1] & v[3]) ^ (v[1] & v[5]) ^ (v[3] & v[5]));
		for (j = 15; j >= 2; j--)
			v[j] = v[j - 2];
		add(&v[8], &v[9], t1h, t1l);
		v[0] = t1h;
		v[1] = t1l;
		add(&v[0], &v[1], t2h, t2l);
	}
	for (i = 0; i < 16; i += 2)
		add(&sha512.h[i], &sha512.h[i + 1], v[i], v[i + 1]);
}

void sha512_init(void)
{
	uint8_t i;

	for (i = 0; i < 16; i++)
		sha512.h[i] = iv[i];
	sha512.len = 0;
	sha512.fill = 0;
}

void sha512_update(__xdata const uint8_t *p, uint16_t n) __reentrant
{
	sha512.len += n;
	while (n--) {
		sha512.buf[sha512.fill++] = *p++;
		if (sha512.fill == 128) {
			sha512_block();
			sha512.fill = 0;
		}
	}
}

void sha512_final(__xdata uint8_t *out) __reentrant
{
	static __xdata uint8_t i;
	static __xdata uint32_t bits;

	bits = (uint32_t)sha512.len << 3;
	sha512.buf[sha512.fill++] = 0x80;
	if (sha512.fill > 112) {
		while (sha512.fill < 128)
			sha512.buf[sha512.fill++] = 0;
		sha512_block();
		sha512.fill = 0;
	}
	while (sha512.fill < 124)
		sha512.buf[sha512.fill++] = 0;
	sha512.buf[124] = bits >> 24;
	sha512.buf[125] = bits >> 16;
	sha512.buf[126] = bits >> 8;
	sha512.buf[127] = bits;
	sha512_block();
	for (i = 0; i < 64; i++)
		out[i] = sha512.h[i >> 2] >> (24 - ((i & 3) << 3));
}
