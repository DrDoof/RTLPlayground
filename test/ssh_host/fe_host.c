#include <stdint.h>
#include <string.h>

extern uint8_t fm_a[32], fm_b[32], fm_p[64], fm_r[32];

void fe_load_a(const uint8_t *s) { memcpy(fm_a, s, 32); }
void fe_load_b(const uint8_t *s) { memcpy(fm_b, s, 32); }

static void mul(const uint8_t *a, const uint8_t *b)
{
	uint32_t acc[64] = {0};
	for (int i = 0; i < 32; i++)
		for (int j = 0; j < 32; j++)
			acc[i + j] += (uint32_t)a[i] * b[j];
	uint32_t c = 0;
	for (int i = 0; i < 64; i++) {
		c += acc[i];
		fm_p[i] = c;
		c >>= 8;
	}
}

void fe_mul_core(void) { mul(fm_a, fm_b); }
void fe_sq_core(void) { mul(fm_a, fm_a); }

static void reduce(void)
{
	uint32_t c = 0;
	for (int i = 0; i < 32; i++) {
		c += fm_p[i] + (uint32_t)fm_p[i + 32] * 38;
		fm_r[i] = c;
		c >>= 8;
	}
	while (c) {
		c *= 38;
		for (int i = 0; i < 32 && c; i++) {
			c += fm_r[i];
			fm_r[i] = c;
			c >>= 8;
		}
	}
}

void fe_store(uint8_t *d) { reduce(); memcpy(d, fm_r, 32); }
void fe_store_a(uint8_t *d) { memcpy(d, fm_a, 32); }
void fe_reduce_a(void) { reduce(); memcpy(fm_a, fm_r, 32); }
