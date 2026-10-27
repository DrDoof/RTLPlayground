#pragma codeseg BANK4
#pragma constseg BANK4

#include <stdint.h>
#include "x25519.h"

__xdata uint8_t x25519_k[32];
__xdata uint8_t x25519_u[32];
__xdata uint8_t x25519_r[32];

__xdata __at(0xbe00) uint8_t fm_a[32];
__xdata __at(0xbe20) uint8_t fm_b[32];
__xdata __at(0xbe40) uint8_t fm_p[64];
__xdata __at(0xbe80) uint8_t fm_r[32];

static __xdata uint8_t x1[32], x2[32], z2[32], x3[32], z3[32];
static __xdata uint8_t ta[32], tb[32], tc[32], td[32], te[32], tf[32], tg[32];
static __xdata uint8_t i0[32], i1[32], i2[32];

static void fe_mul121665(void)
{
	static __xdata uint8_t i, v;
	static __xdata uint32_t t;

	t = 0;
	for (i = 0; i < 32; i++) {
		/* Consume each independent column immediately: the carry is at most
		 * 121664, so the sum is < 121665 * 256 and fits in 32 bits.
		 * This preserves the exact byte/carry sequence without a 128-byte
		 * XDATA round trip through col[]. */
		v = te[i];
		t += (uint16_t)v * 0x41 + ((uint32_t)((uint16_t)v * 0xdb) << 8) + ((uint32_t)v << 16);
		ta[i] = t;
		t >>= 8;
	}
	while (t) {
		t = (t << 5) + (t << 2) + (t << 1);
		for (i = 0; i < 32 && t; i++) {
			t += ta[i];
			ta[i] = t;
			t >>= 8;
		}
	}
}

void fe_add(__xdata uint8_t *r, __xdata const uint8_t *a, __xdata const uint8_t *b)
{
	uint8_t i;
	uint16_t t = 0;

	for (i = 0; i < 32; i++) {
		t += a[i] + b[i];
		r[i] = t;
		t >>= 8;
	}
	while (t) {
		t = (t << 5) + (t << 2) + (t << 1);
		for (i = 0; i < 32 && t; i++) {
			t += r[i];
			r[i] = t;
			t >>= 8;
		}
	}
}

void fe_sub(__xdata uint8_t *r, __xdata const uint8_t *a, __xdata const uint8_t *b)
{
	uint8_t i, s = 0;
	uint16_t d;

	for (i = 0; i < 32; i++) {
		d = (uint16_t)a[i] - b[i] - s;
		r[i] = d;
		s = (d >> 8) & 1;
	}
	while (s) {
		s = 38;
		for (i = 0; i < 32 && s; i++) {
			d = (uint16_t)r[i] - s;
			r[i] = d;
			s = (d >> 8) & 1;
		}
	}
}

static void fe_cswap(uint8_t swap, __xdata uint8_t *a, __xdata uint8_t *b)
{
	uint8_t i, x, m = -swap;

	for (i = 0; i < 32; i++) {
		x = m & (a[i] ^ b[i]);
		a[i] ^= x;
		b[i] ^= x;
	}
}

struct inv_op {
	__xdata uint8_t *d;
	__xdata uint8_t *s;
	__xdata uint8_t *m;
	uint8_t n;
};

static __code const struct inv_op inv_ops[12] = {
	{ i0, z2, 0, 1 },
	{ i1, i0, z2, 2 },
	{ i0, i1, i0, 0 },
	{ i1, i0, i1, 1 },
	{ i1, i1, i1, 5 },
	{ i2, i1, i1, 10 },
	{ i2, i2, i2, 20 },
	{ i1, i2, i1, 10 },
	{ i2, i1, i1, 50 },
	{ i2, i2, i2, 100 },
	{ i1, i2, i1, 50 },
	{ ta, i1, i0, 5 }
};

void fe_freeze(__xdata uint8_t *r)
{
	static __xdata uint8_t i, k;
	static __xdata uint16_t t;

	for (k = 0; k < 2; k++) {
		t = (r[31] & 0x80) ? 19 : 0;
		r[31] &= 0x7f;
		for (i = 0; i < 32; i++) {
			t += r[i];
			r[i] = t;
			t >>= 8;
		}
	}
	t = 19;
	for (i = 0; i < 32; i++) {
		t += r[i];
		fm_r[i] = t;
		t >>= 8;
	}
	if (fm_r[31] & 0x80) {
		fm_r[31] &= 0x7f;
		for (i = 0; i < 32; i++)
			r[i] = fm_r[i];
	}
}

static __xdata uint8_t xs_state, xs_op, xs_rem, xs_k, xs_bit, xs_swap, xs_inv;
static __xdata uint8_t * __xdata xs_out;
static __xdata int16_t xs_pos;

void x25519_start(void)
{
	for (xs_k = 0; xs_k < 32; xs_k++) {
		x1[xs_k] = x25519_u[xs_k];
		x3[xs_k] = x25519_u[xs_k];
		x2[xs_k] = 0;
		z2[xs_k] = 0;
		z3[xs_k] = 0;
	}
	x25519_k[0] &= 248;
	x25519_k[31] &= 127;
	x25519_k[31] |= 64;
	x1[31] &= 127;
	x3[31] &= 127;
	x2[0] = 1;
	z3[0] = 1;
	xs_swap = 0;
	xs_pos = 254;
	xs_inv = 0;
	xs_state = 1;
}

void fe_inv_start(__xdata uint8_t *out, __xdata const uint8_t *in)
{
	for (xs_k = 0; xs_k < 32; xs_k++)
		z2[xs_k] = in[xs_k];
	xs_out = out;
	xs_inv = 1;
	xs_op = 0;
	xs_rem = 0xff;
	xs_state = 2;
}

static void x25519_ladder(void)
{
	xs_bit = (x25519_k[xs_pos >> 3] >> (xs_pos & 7)) & 1;
	xs_swap ^= xs_bit;
	fe_cswap(xs_swap, x2, x3);
	fe_cswap(xs_swap, z2, z3);
	xs_swap = xs_bit;

	fe_add(ta, x2, z2);
	fe_sub(tb, x2, z2);
	FE_SQ(tc, ta);
	FE_SQ(td, tb);
	fe_sub(te, tc, td);
	fe_add(tf, x3, z3);
	fe_sub(tg, x3, z3);
	FE_MUL(tg, tg, ta);
	FE_MUL(tf, tf, tb);
	fe_add(ta, tg, tf);
	FE_SQ(x3, ta);
	fe_sub(tb, tg, tf);
	FE_SQ(tb, tb);
	FE_MUL(z3, x1, tb);
	FE_MUL(x2, tc, td);
	fe_mul121665();
	fe_add(ta, tc, ta);
	FE_MUL(z2, te, ta);
}

static void x25519_invert_step(void)
{
	if (xs_rem == 0xff) {
		fe_load_a(inv_ops[xs_op].s);
		xs_rem = inv_ops[xs_op].n;
	}
	xs_k = 10;
	while (xs_rem && xs_k) {
		fe_sq_core();
		fe_reduce_a();
		xs_rem--;
		xs_k--;
	}
	if (xs_rem)
		return;
	if (inv_ops[xs_op].m) {
		fe_load_b(inv_ops[xs_op].m);
		fe_mul_core();
		fe_store(inv_ops[xs_op].d);
	} else {
		fe_store_a(inv_ops[xs_op].d);
	}
	xs_rem = 0xff;
	if (++xs_op == 12)
		xs_state = 3;
}

uint8_t x25519_step(void)
{
	if (xs_state == 1) {
		x25519_ladder();
		if (--xs_pos < 0) {
			fe_cswap(xs_swap, x2, x3);
			fe_cswap(xs_swap, z2, z3);
			xs_op = 0;
			xs_rem = 0xff;
			xs_state = 2;
		}
		return 0;
	}
	if (xs_state == 2) {
		x25519_invert_step();
		return 0;
	}
	if (xs_state == 3) {
		if (xs_inv) {
			for (xs_k = 0; xs_k < 32; xs_k++)
				xs_out[xs_k] = ta[xs_k];
		} else {
			FE_MUL(x25519_r, x2, ta);
			fe_freeze(x25519_r);
		}
		xs_state = 0;
	}
	return 1;
}

void x25519(void)
{
	x25519_start();
	while (!x25519_step())
		;
}
