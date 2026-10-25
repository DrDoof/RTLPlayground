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

extern volatile __xdata uint32_t ticks;
extern __xdata uint8_t ssh_kex_done;
extern __xdata uint8_t ssh_step;
static __xdata uint32_t t_kex0;
static __xdata uint16_t t_max_step, t_max_rx, n_steps;
static __xdata uint8_t c_max_step;

static uint32_t now(void)
{
	static __xdata uint32_t a, b;

	do {
		a = ticks;
		b = ticks;
	} while (a != b);
	return a;
}
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
	static __xdata uint32_t t0;
	static __xdata uint16_t dt;

	t0 = now();
	ssh_poll();
	if (!ssh_active && !ssh_kex_done)
		return;
	dt = now() - t0;
	n_steps++;
	if (dt > t_max_step) {
		t_max_step = dt;
		c_max_step = ssh_step;
	}
	if (ssh_kex_done) {
		ssh_kex_done = 0;
		print_string("ssh: kex ");
		print_long(now() - t_kex0);
		print_string(" ticks, steps ");
		print_short(n_steps);
		print_string(", max step ");
		print_short(t_max_step);
		print_string(" at ");
		print_byte(c_max_step);
		print_string(", max rx ");
		print_short(t_max_rx);
		write_char('\n');
	}
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
		t_kex0 = now();
		t_max_step = t_max_rx = n_steps = 0;
		c_max_step = 0;
	}
	if (uip_conn != ssh_conn)
		return;
	if (uip_closed() || uip_aborted() || uip_timedout()) {
		ssh_conn = 0;
		return;
	}
	if (uip_acked())
		ssh_acked();
	if (uip_newdata()) {
		static __xdata uint32_t t0;
		static __xdata uint16_t dt;

		t0 = now();
		ssh_input((__xdata uint8_t *)uip_appdata, uip_datalen());
		dt = now() - t0;
		if (dt > t_max_rx)
			t_max_rx = dt;
	}
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
