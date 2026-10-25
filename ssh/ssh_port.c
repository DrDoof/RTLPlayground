#pragma codeseg BANK4
#pragma constseg BANK4

#include <stdint.h>
#include "../rtl837x_common.h"
#include "../uip/uip.h"
#include "ssh.h"
#include "ssh_fw.h"

extern volatile __xdata uint8_t sfr_data[4];
extern __xdata uint8_t cmd_capture;
extern __xdata uint8_t outbuf[TCP_OUTBUF_SIZE];
extern __xdata uint16_t slen;
extern __xdata char passwd[21];
void execute_commands(__xdata uint8_t *p) __banked;

__xdata uint8_t * __xdata ssh_port_out;
static __xdata struct uip_conn * __xdata ssh_conn;

void ssh_port_random(__xdata uint8_t *p, uint8_t n) __reentrant
{
	static __xdata uint8_t i;

	for (i = 0; i < n; i++) {
		if (!(i & 3))
			get_random_32();
		p[i] = sfr_data[i & 3];
	}
}

uint8_t ssh_port_auth(__xdata const uint8_t *pw, uint8_t len)
{
	static __xdata uint8_t i;

	for (i = 0; i < len; i++)
		if (!passwd[i] || passwd[i] != pw[i])
			return 0;
	return !passwd[len];
}

uint16_t ssh_port_exec(__xdata uint8_t *line)
{
	ssh_port_out = outbuf;
	slen = 0;
	cmd_capture = 1;
	execute_commands(line);
	cmd_capture = 0;
	return slen;
}

void ssh_start(void) __banked
{
	ssh_conn = 0;
	ssh_init();
	uip_listen(HTONS(SSH_PORT));
}

void ssh_idle(void) __banked
{
	ssh_poll();
}

void ssh_appcall(void) __banked
{
	static __xdata uint16_t n;

	if (uip_connected()) {
		if (ssh_conn) {
			uip_abort();
			return;
		}
		ssh_conn = uip_conn;
		ssh_reset();
	}
	if (uip_conn != ssh_conn)
		return;
	if (uip_closed() || uip_aborted() || uip_timedout()) {
		ssh_conn = 0;
		return;
	}
	if (uip_acked())
		ssh_acked();
	if (uip_newdata())
		ssh_input((__xdata uint8_t *)uip_appdata, uip_datalen());
	if (uip_rexmit()) {
		n = ssh_output((__xdata uint8_t *)uip_appdata, uip_mss(), 1);
		if (n)
			uip_send(uip_appdata, n);
		return;
	}
	if (!ssh_inflight()) {
		n = ssh_output((__xdata uint8_t *)uip_appdata, uip_mss(), 0);
		if (n) {
			uip_send(uip_appdata, n);
			return;
		}
	}
	if (ssh_closing())
		uip_close();
}
