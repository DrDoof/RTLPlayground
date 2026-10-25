#ifndef _X25519_H_
#define _X25519_H_

#include <stdint.h>

extern __xdata uint8_t x25519_k[32];
extern __xdata uint8_t x25519_u[32];
extern __xdata uint8_t x25519_r[32];

void x25519(void);
void x25519_start(void);
uint8_t x25519_step(void);

void fe_load_a(__xdata const uint8_t *s);
void fe_load_b(__xdata const uint8_t *s);
void fe_mul_core(void);
void fe_sq_core(void);
void fe_store(__xdata uint8_t *d);
void fe_store_a(__xdata uint8_t *d);
void fe_reduce_a(void);
void fe_add(__xdata uint8_t *r, __xdata const uint8_t *a, __xdata const uint8_t *b);
void fe_sub(__xdata uint8_t *r, __xdata const uint8_t *a, __xdata const uint8_t *b);
void fe_freeze(__xdata uint8_t *r);
void fe_inv_start(__xdata uint8_t *out, __xdata const uint8_t *in);

#define FE_MUL(r, a, b) do { fe_load_a(a); fe_load_b(b); fe_mul_core(); fe_store(r); } while (0)
#define FE_SQ(r, a) do { fe_load_a(a); fe_sq_core(); fe_store(r); } while (0)

#endif
