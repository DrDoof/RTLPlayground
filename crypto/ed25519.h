#ifndef _ED25519_H_
#define _ED25519_H_

#include <stdint.h>

extern __xdata uint8_t ed_sig[64];
extern __xdata uint8_t ed_pub[32];

void ed_init(void);
void ed_sign_start(__xdata const uint8_t *m32);
uint8_t ed_sign_step(void);

#endif
