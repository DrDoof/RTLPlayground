#ifndef _SHA512_H_
#define _SHA512_H_

#include <stdint.h>

struct sha512_t {
	uint32_t h[16];
	uint8_t buf[128];
	uint16_t len;
	uint8_t fill;
};

extern __xdata struct sha512_t sha512;

void sha512_init(void);
void sha512_update(__xdata const uint8_t *p, uint16_t n) __reentrant;
void sha512_final(__xdata uint8_t *out) __reentrant;
void sha512_final_begin(__xdata uint8_t *out) __reentrant;
uint8_t sha512_final_step(void);

#endif
