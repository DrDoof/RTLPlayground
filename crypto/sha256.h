#ifndef _SHA256_H_
#define _SHA256_H_

#include <stdint.h>

struct sha256_t {
	uint32_t h[8];
	uint8_t buf[64];
	uint32_t len;
	uint8_t fill;
};

extern __xdata struct sha256_t sha256;

void sha256_init(void);
void sha256_update(__xdata const uint8_t *p, uint16_t n) __reentrant;
void sha256_final(__xdata uint8_t *out);

#endif
