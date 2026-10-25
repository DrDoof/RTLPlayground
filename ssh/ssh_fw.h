#ifndef _SSH_FW_H_
#define _SSH_FW_H_

#include <stdint.h>

extern __xdata uint8_t ssh_active;

void ssh_start(void) __banked;
void ssh_idle(void) __banked;
void ssh_appcall(void) __banked;

#endif
