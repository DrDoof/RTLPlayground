#ifndef _SSH_H_
#define _SSH_H_

#include <stdint.h>

#define SSH_PORT 22

void ssh_init(void);
void ssh_reset(void);
void ssh_input(__xdata const uint8_t *p, uint16_t n) __reentrant;
void ssh_input_eof(void);
uint16_t ssh_output(__xdata uint8_t *out, uint16_t max, uint8_t rexmit) __reentrant;
void ssh_acked(void);
void ssh_poll(void);
uint8_t ssh_inflight(void);
uint8_t ssh_closing(void);

void ssh_chacha_xor(__xdata const uint8_t *key, __xdata const uint8_t *seq, uint8_t ctr, __xdata uint8_t *buf, uint16_t len) __reentrant;
void ssh_port_random(__xdata uint8_t *p, uint8_t n) __reentrant;
uint8_t ssh_port_auth(__xdata const uint8_t *pw, uint8_t len);
uint16_t ssh_port_exec(__xdata uint8_t *line);
extern __xdata uint8_t * __xdata ssh_port_out;
extern __xdata uint8_t ssh_active;

#endif
