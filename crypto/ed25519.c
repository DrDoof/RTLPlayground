#pragma codeseg BANK4
#pragma constseg BANK4

#include <stdint.h>
#include "x25519.h"
#include "sha512.h"
#include "ed25519.h"
#include "ed25519_consts.h"

__xdata uint8_t ed_sig[64];
__xdata uint8_t ed_pub[32];

static __xdata uint8_t px[32], py[32], pz[32], pt[32];
static __xdata uint8_t ea[32], eb[32], ec[32], ed[32], ee[32], ef[32], eg[32], eh[32];
static __xdata uint8_t bp[96];
static __xdata uint8_t ez[32];
static __xdata uint8_t h64[64];
static __xdata uint8_t sc_r[32], sc_k[32];
static __xdata uint8_t acc[32], tmp[32];
static __xdata const uint8_t * __xdata msg;
__xdata uint8_t es_state;
static __xdata uint8_t es_i;
static __xdata int16_t es_pos;

static __code const uint8_t sc_l[32] = {
	0xed, 0xd3, 0xf5, 0x5c, 0x1a, 0x63, 0x12, 0x58,
	0xd6, 0x9c, 0xf7, 0xa2, 0xde, 0xf9, 0xde, 0x14,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x10
};

static void sc_cond_sub_l(void)
{
	static __xdata uint8_t i, s;
	static __xdata uint16_t t;

	s = 0;
	for (i = 0; i < 32; i++) {
		t = (uint16_t)acc[i] - sc_l[i] - s;
		tmp[i] = t;
		s = (t >> 8) & 1;
	}
	if (!s)
		for (i = 0; i < 32; i++)
			acc[i] = tmp[i];
}

static void sc_dbl(uint8_t bit)
{
	static __xdata uint8_t i, c, n;

	c = bit;
	for (i = 0; i < 32; i++) {
		n = acc[i] >> 7;
		acc[i] = (acc[i] << 1) | c;
		c = n;
	}
	sc_cond_sub_l();
}

static void sc_add(__xdata const uint8_t *b)
{
	static __xdata uint8_t i;
	static __xdata uint16_t t;

	t = 0;
	for (i = 0; i < 32; i++) {
		t += acc[i] + b[i];
		acc[i] = t;
		t >>= 8;
	}
	sc_cond_sub_l();
}

static __xdata int16_t red_pos;

static void sc_red_begin(void)
{
	for (es_i = 0; es_i < 32; es_i++)
		acc[es_i] = 0;
	red_pos = 511;
}

static uint8_t sc_red_step(__xdata uint8_t *out)
{
	static __xdata uint8_t n;

	for (n = 0; n < 64 && red_pos >= 0; n++, red_pos--)
		sc_dbl((h64[red_pos >> 3] >> (red_pos & 7)) & 1);
	if (red_pos >= 0)
		return 0;
	for (es_i = 0; es_i < 32; es_i++)
		out[es_i] = acc[es_i];
	return 1;
}

static void copyc(__xdata uint8_t *d, __code const uint8_t *s, uint8_t n)
{
	while (n--)
		*d++ = *s++;
}

static void ed_double(void)
{
	FE_SQ(ea, px);
	FE_SQ(eb, py);
	FE_SQ(ec, pz);
	fe_add(ec, ec, ec);
	fe_add(ee, px, py);
	FE_SQ(ee, ee);
	fe_sub(ee, ee, ea);
	fe_sub(ee, ee, eb);
	fe_sub(eg, eb, ea);
	fe_sub(ef, eg, ec);
	fe_add(eh, ea, eb);
	fe_sub(eh, ez, eh);
	FE_MUL(px, ee, ef);
	FE_MUL(py, eg, eh);
	FE_MUL(pt, ee, eh);
	FE_MUL(pz, ef, eg);
}

static void ed_add_base(void)
{
	fe_sub(ea, py, px);
	FE_MUL(ea, ea, bp);
	fe_add(eb, py, px);
	FE_MUL(eb, eb, bp + 32);
	FE_MUL(ec, pt, bp + 64);
	fe_add(ed, pz, pz);
	fe_sub(ee, eb, ea);
	fe_sub(ef, ed, ec);
	fe_add(eg, ed, ec);
	fe_add(eh, eb, ea);
	FE_MUL(px, ee, ef);
	FE_MUL(py, eg, eh);
	FE_MUL(pt, ee, eh);
	FE_MUL(pz, ef, eg);
}

void ed_init(void)
{
	copyc(ed_pub, ed_key_pub, 32);
	copyc(bp, ed_bp_ym, 32);
	copyc(bp + 32, ed_bp_yp, 32);
	copyc(bp + 64, ed_bp_t2d, 32);
	for (es_i = 0; es_i < 32; es_i++)
		ez[es_i] = 0;
}

void ed_sign_start(__xdata const uint8_t *m32)
{
	msg = m32;
	es_state = 10;
}

uint8_t ed_sign_step(void)
{
	static __xdata int16_t i;
	static __xdata uint8_t n;

	switch (es_state) {
	case 10:
		sha512_init();
		copyc(tmp, ed_key_prefix, 32);
		sha512_update(tmp, 32);
		sha512_update(msg, 32);
		sha512_final(h64);
		sc_red_begin();
		es_state = 11;
		return 0;
	case 11:
		if (!sc_red_step(sc_r))
			return 0;
		for (es_i = 0; es_i < 32; es_i++) {
			px[es_i] = 0;
			py[es_i] = 0;
			pz[es_i] = 0;
			pt[es_i] = 0;
		}
		py[0] = 1;
		pz[0] = 1;
		es_pos = 252;
		es_state = 1;
		return 0;
	case 1:
		ed_double();
		if ((sc_r[es_pos >> 3] >> (es_pos & 7)) & 1)
			ed_add_base();
		if (--es_pos < 0) {
			fe_inv_start(ee, pz);
			es_state = 2;
		}
		return 0;
	case 2:
		if (x25519_step())
			es_state = 3;
		return 0;
	case 3:
		FE_MUL(ef, px, ee);
		FE_MUL(ed_sig, py, ee);
		fe_freeze(ef);
		fe_freeze(ed_sig);
		ed_sig[31] |= (ef[0] & 1) << 7;
		es_state = 5;
		return 0;
	case 5:
		sha512_init();
		sha512_update(ed_sig, 32);
		sha512_update(ed_pub, 32);
		sha512_update(msg, 32);
		sha512_final(h64);
		sc_red_begin();
		es_state = 6;
		return 0;
	case 6:
		if (!sc_red_step(sc_k))
			return 0;
		copyc(tmp, ed_key_a, 32);
		for (es_i = 0; es_i < 32; es_i++) {
			h64[es_i] = tmp[es_i];
			acc[es_i] = 0;
		}
		i = 254;
		es_state = 4;
		return 0;
	case 4:
		for (n = 0; n < 32 && i >= 0; n++, i--) {
			sc_dbl(0);
			if ((h64[i >> 3] >> (i & 7)) & 1)
				sc_add(sc_k);
		}
		if (i >= 0)
			return 0;
		sc_add(sc_r);
		for (es_i = 0; es_i < 32; es_i++)
			ed_sig[32 + es_i] = acc[es_i];
		es_state = 0;
	}
	return 1;
}
