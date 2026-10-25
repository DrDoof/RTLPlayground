#ifndef _POLY1305_H_
#define _POLY1305_H_

#include <stdint.h>

struct poly1305_t {
	uint8_t s[16];
	uint8_t buf[16];
	uint8_t fill;
};

extern __xdata struct poly1305_t poly1305;

void poly1305_init(__xdata const uint8_t *key);
void poly1305_update(__xdata const uint8_t *p, uint16_t n) __reentrant;
void poly1305_final(__xdata uint8_t *tag);

#endif
