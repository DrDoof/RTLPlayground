/*
 * LLDP (802.1AB) TX+RX and CDP RX for the RTL837x platform
 * This code is in the Public Domain
 */
#ifndef _RTL837X_LLDP_H_
#define _RTL837X_LLDP_H_

#include <stdint.h>

/* Discovered neighbors: a global pool, NOT one slot per port - a trunk
 * port can hear many LLDP/CDP speakers. Entries are keyed on (port,
 * identity); when the pool is full the entry closest to expiry is evicted.
 * Strings are NUL-terminated and sanitized to printable ASCII on ingest
 * (they are remote-controlled data and end up in JSON / the web UI). */
#define LLDP_NB_MAX	16
struct lldp_neighbor {
	uint8_t proto;		/* 0 free, 1 LLDP, 2 CDP */
	uint8_t port;		/* logical ingress port */
	uint8_t chassis[6];	/* MAC-subtype chassis id (zeroed for others) */
	char    portid[13];
	char    sysname[17];
	uint16_t ttl;		/* seconds until the entry expires */
};

extern __xdata uint8_t lldpEnabled;
extern __xdata uint8_t lldp_interval_s;
extern __xdata uint16_t lldp_txmask;	/* per-port TX enable; 0 = RX-only (default) */
extern __xdata uint16_t lldp_tx_cnt[16];
extern __xdata uint16_t lldp_rx_cnt[16];
extern __xdata struct lldp_neighbor lldp_nb[LLDP_NB_MAX];

void lldp_init(void) __banked;
void lldp_on(void) __banked;
void lldp_off(void) __banked;
void lldp_timers(void) __banked;	/* call ~once per main-loop pass */
void lldp_in(void) __banked __reentrant;		/* 01:80:c2:00:00:0e, ethertype 0x88cc */
void cdp_in(void) __banked __reentrant;		/* 01:00:0c:cc:cc:cc, SNAP PID 0x2000 */
void lldp_parse(void) __banked;		/* CLI: "lldp ..." */

#endif
