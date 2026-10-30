#pragma codeseg BANK4
#pragma constseg BANK4

#include <stdint.h>
#include "sha256.h"

__xdata struct sha256_t sha256;

static __xdata uint32_t w[16];
static __xdata uint32_t a, b, c, d, e, f, g, h, t1, t2;

static __code const uint32_t k[64] = {
	0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
	0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
	0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
	0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
	0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
	0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
	0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
	0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
};

static __code const uint32_t iv[8] = {
	0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19
};

#define ROTR(x, n) (((x) >> (n)) | ((x) << (32 - (n))))

/* The existing SHA-256 context and working words have one foreground owner.
 * These reentrant helpers add no shared workspace; splitting their temporary
 * lifetimes reduces SDCC stack spills. ISR callers remain prohibited, as before.
 */
static void load_words(void) __reentrant {
 uint8_t i; __xdata uint8_t *p=sha256.buf;
	for (i = 0; i < 16; i++) {
		w[i] = ((uint32_t)p[0] << 24) | ((uint32_t)p[1] << 16) | ((uint16_t)p[2] << 8) | p[3];
		p += 4;
	}
}
static void schedule(uint8_t i) __reentrant {
 t1=ROTR(w[(i+1)&15],7);
 t1^=ROTR(w[(i+1)&15],18);
 t1^=w[(i+1)&15]>>3;
 t2=ROTR(w[(i+14)&15],17);
 t2^=ROTR(w[(i+14)&15],19);
 t2^=w[(i+14)&15]>>10;
 t1+=t2; t1+=w[(i+9)&15]; w[i&15]+=t1;
}
static void round_first(uint8_t i) __reentrant {
 t1=ROTR(e,6); t1^=ROTR(e,11); t1^=ROTR(e,25);
 /* Ch(e,f,g) = g ^ (e & (f ^ g)). */
 t1+=g^(e&(f^g)); t1+=h; t1+=k[i]; t1+=w[i&15];
}
static void round_second(void) __reentrant {
 t2=ROTR(a,2); t2^=ROTR(a,13); t2^=ROTR(a,22);
 /* Maj(a,b,c) = (a & b) | (c & (a | b)). */
 t2+=(a&b)|(c&(a|b));
}
static void finish_block(void) __reentrant {
	sha256.h[0] += a; sha256.h[1] += b; sha256.h[2] += c; sha256.h[3] += d;
	sha256.h[4] += e; sha256.h[5] += f; sha256.h[6] += g; sha256.h[7] += h;

}
static void sha256_block(void) __reentrant {
 uint8_t i;
 load_words();
	a = sha256.h[0]; b = sha256.h[1]; c = sha256.h[2]; d = sha256.h[3];
	e = sha256.h[4]; f = sha256.h[5]; g = sha256.h[6]; h = sha256.h[7];
 for(i=0;i<64;i++) {
  if(i>=16) schedule(i);
  round_first(i); round_second();
  h=g;g=f;f=e;e=d+t1;d=c;c=b;b=a;a=t1+t2;
 }
 finish_block();
}

void sha256_init(void)
{
	uint8_t i;

	for (i = 0; i < 8; i++)
		sha256.h[i] = iv[i];
	sha256.len = 0;
	sha256.fill = 0;
}

void sha256_update(__xdata const uint8_t *p, uint16_t n) __reentrant
{
	sha256.len += n;
	while (n--) {
		sha256.buf[sha256.fill++] = *p++;
		if (sha256.fill == 64) {
			sha256_block();
			sha256.fill = 0;
		}
	}
}

void sha256_final(__xdata uint8_t *out)
{
	static __xdata uint8_t i;
	static __xdata uint32_t bits;

	bits = sha256.len << 3;

	sha256.buf[sha256.fill++] = 0x80;
	if (sha256.fill > 56) {
		while (sha256.fill < 64)
			sha256.buf[sha256.fill++] = 0;
		sha256_block();
		sha256.fill = 0;
	}
	while (sha256.fill < 60)
		sha256.buf[sha256.fill++] = 0;
	sha256.buf[60] = bits >> 24;
	sha256.buf[61] = bits >> 16;
	sha256.buf[62] = bits >> 8;
	sha256.buf[63] = bits;
	sha256_block();
	for (i = 0; i < 8; i++) {
		*out++ = sha256.h[i] >> 24;
		*out++ = sha256.h[i] >> 16;
		*out++ = sha256.h[i] >> 8;
		*out++ = sha256.h[i];
	}
}
