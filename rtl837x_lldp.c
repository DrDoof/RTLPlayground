/*
 * LLDP (802.1AB) TX+RX and CDP RX for the RTL837x platform
 * This code is in the Public Domain
 *
 * TX: one LLDPDU per front port every lldp_interval_s seconds (Chassis ID,
 * Port ID, TTL, System Name/Description, Capabilities, Management Address).
 * RX: one neighbor slot per port (last speaker wins), aged by the TTL the
 * neighbor announced. CDP is RX-only: Device-ID and Port-ID are mapped into
 * the same table. Strings are sanitized on ingest - they are remote data
 * and end up in JSON and the web UI.
 */

/* BANK2 alongside STP/LACP. Bank 3 IS hardware-usable (verified 2026-07-22),
 * but a whole .c file compiles into ONE bank, and lldp_parse calls the
 * BANK2 CLI helpers cmd_compare()/atoi_byte() with plain (non-banked)
 * lcalls - fatal from another bank. Living in bank 3 needs those helpers
 * (and cmpMAC) marked __banked first; until then lldp stays in BANK2. */
#pragma codeseg BANK2
#pragma constseg BANK2

#include <stdint.h>
#include "rtl837x_common.h"
#include "rtl837x_sfr.h"
#include "rtl837x_regs.h"
#include "rtl837x_lldp.h"
#include "uip.h"
#include "machine.h"

extern __code struct machine machine;
extern __xdata struct uip_eth_addr uip_ethaddr;
extern __xdata uint8_t uip_buf[UIP_CONF_BUFFER_SIZE + 2];
extern __xdata uint16_t management_vlan;
extern __xdata uip_ipaddr_t uip_hostaddr;

/* CLI tokenizer helpers (cmd_parser.c, HOME bank) */
extern __xdata uint8_t cmd_words_len;
extern __xdata uint8_t cmd_words_b[15];
extern __xdata uint8_t cmd_buffer[];
uint8_t cmd_compare(uint8_t start, __code uint8_t * cmd);
uint8_t atoi_byte(uint8_t idx);
extern __xdata uint8_t atoi_results_u8;

__xdata uint8_t lldpEnabled;
__xdata uint8_t lldp_interval_s;
__xdata uint16_t lldp_txmask;
__xdata uint16_t lldp_tx_cnt[16];	/* per-port LLDPDU TX counter */
__xdata uint16_t lldp_rx_cnt[16];	/* RX counter; indexed by rtl_tag nibble (0-15) */
__xdata struct lldp_neighbor lldp_nb[LLDP_NB_MAX];

/* Scratch in xdata (8051 IRAM discipline, cf. rtl837x_stp.c) */
static __xdata uint8_t  lldp_i;
static __xdata uint8_t  lldp_scratch;
static __xdata uint8_t  lldp_prescale;	/* main-loop passes -> ~1 Hz */
static __xdata uint8_t  lldp_txwait;	/* seconds until the next TX round */
static __xdata uint8_t * __xdata lldp_p;	/* frame build/parse cursor */
static __xdata uint8_t * __xdata lldp_end;
static __xdata struct lldp_neighbor * __xdata lldp_nbp;
static __xdata struct lldp_neighbor * __xdata lldp_best;
static __xdata struct lldp_neighbor lldp_tmp;	/* parse target, then keyed into the pool */
static __xdata uint8_t lldp_k;
static __xdata uint16_t lldp_t, lldp_l;		/* TLV type/length scratch */
static __xdata uint16_t lldp_saved_vlan;
static __xdata uint8_t  lldp_dlen;

#define LLDP_O	(&uip_buf[RTL_FRAME_DESC_SIZE])
/* RX layout as delivered by the ASIC: dst6 src6 rtl_tag8 vlan_tag4 ... */
#define LLDP_RX_ETHERTYPE	24
#define LLDP_RX_PAYLOAD		26

/* Reserved-MAC action register for 01:80:c2:00:00:0e (base + 4 * 0x0e) */
#define RTL837X_RMA14_CONF	(RTL837X_RMA0_CONF + 4 * 0x0e)

static void copy_code(__xdata uint8_t *dst, __code char *src, uint8_t len) __reentrant
{
	for (lldp_scratch = 0; lldp_scratch < len; lldp_scratch++)
		dst[lldp_scratch] = src[lldp_scratch];
}

static char sanitize(uint8_t c) __reentrant
{
	if (c < 0x20 || c > 0x7e || c == '"' || c == '\\')
		return '.';
	return (char)c;
}

/* Copy a length-limited remote string into a NUL-terminated sanitized slot */
static void copy_str(__xdata char *dst, __xdata uint8_t *src, uint8_t len, uint8_t max) __reentrant
{
	if (len > max)
		len = max;
	for (lldp_scratch = 0; lldp_scratch < len; lldp_scratch++)
		dst[lldp_scratch] = sanitize(src[lldp_scratch]);
	dst[len] = 0;
}


#define LLDP_TAG ((__xdata struct rtl_tag *)(LLDP_O + 12))
/* Commit lldp_tmp into the pool: an existing entry with the same (port,
 * proto, identity) is updated, else a free slot is taken, else the entry
 * closest to expiry is evicted. Identity: chassis MAC for LLDP, the
 * sysname (Device-ID) string for CDP. */
static void commit_tmp(void)
{
	lldp_best = 0;
	for (lldp_scratch = 0; lldp_scratch < LLDP_NB_MAX; lldp_scratch++) {
		lldp_nbp = &lldp_nb[lldp_scratch];
		if (lldp_nbp->proto == lldp_tmp.proto && lldp_nbp->port == lldp_tmp.port) {
			if (lldp_tmp.proto == 1) {
				/* local 6-byte compare: cmpMAC lives in BANK2 and a
				 * cross-bank plain lcall from BANK3 would jump into the
				 * wrong window (this bricked the switch twice). */
				for (lldp_k = 0; lldp_k < 6 && lldp_nbp->chassis[lldp_k] == lldp_tmp.chassis[lldp_k]; lldp_k++)
					;
				if (lldp_k == 6)
					break;
			} else {
				lldp_k = 0;
				while (lldp_k < 16 && lldp_nbp->sysname[lldp_k]
				       && lldp_nbp->sysname[lldp_k] == lldp_tmp.sysname[lldp_k])
					lldp_k++;
				if (lldp_nbp->sysname[lldp_k] == lldp_tmp.sysname[lldp_k])
					break;
			}
		}
		if (!lldp_nbp->proto && !lldp_best)
			lldp_best = lldp_nbp;
		lldp_nbp = 0;
	}
	if (!lldp_nbp) {
		lldp_nbp = lldp_best;
		if (!lldp_nbp) {	/* pool full: evict closest to expiry */
			lldp_nbp = &lldp_nb[0];
			for (lldp_scratch = 1; lldp_scratch < LLDP_NB_MAX; lldp_scratch++) {
				if (lldp_nb[lldp_scratch].ttl < lldp_nbp->ttl)
					lldp_nbp = &lldp_nb[lldp_scratch];
			}
		}
	}
	memcpy(lldp_nbp, &lldp_tmp, sizeof(struct lldp_neighbor));
}


static void lldp_send(uint8_t port) __reentrant
{
	__xdata uint8_t *o = LLDP_O;

	o[0] = 0x01; o[1] = 0x80; o[2] = 0xc2; o[3] = 0x00; o[4] = 0x00; o[5] = 0x0e;
	memcpy(o + 6, uip_ethaddr.addr, 6);

	LLDP_TAG->tag = HTONS(RTL_FRAME_TAG_ID);
	LLDP_TAG->version = RTL_FRAME_TAG_VERSION;
	LLDP_TAG->reason = 0x00;
	/* Ethertype frame: LEARN_DIS|KEEP is the hardware-verified LACP recipe
	 * (KEEP kills LLC frames like BPDUs, but is fine - and wanted - here). */
	LLDP_TAG->flags = HTONS(RTL_TAG_LEARN_DIS | RTL_TAG_KEEP);
	LLDP_TAG->pmask = HTONS(((uint16_t)1) << port);

	o[20] = 0x88; o[21] = 0xcc;
	lldp_p = o + 22;

	/* Chassis ID, subtype 4 (MAC address) */
	*lldp_p++ = (1 << 1); *lldp_p++ = 7; *lldp_p++ = 4;
	memcpy(lldp_p, uip_ethaddr.addr, 6); lldp_p += 6;

	/* Port ID, subtype 5 (interface name): "Port N" (physical numbering) */
	*lldp_p++ = (2 << 1); *lldp_p++ = 7; *lldp_p++ = 5;
	copy_code(lldp_p, "Port ", 5); lldp_p += 5;
	*lldp_p++ = '1' + port;		/* log N = phys N+1 on this hardware */

	/* TTL: 3 x interval, capped to a byte's worth of headroom */
	*lldp_p++ = (3 << 1); *lldp_p++ = 2;
	*lldp_p++ = 0; *lldp_p++ = (uint8_t)(lldp_interval_s < 85 ? 3 * lldp_interval_s : 255);

	/* System Name (configurable via "lldp sysname") */
	lldp_dlen = 0;
	while (hostname[lldp_dlen] && lldp_dlen < 23) {
		lldp_p[2 + lldp_dlen] = hostname[lldp_dlen];
		lldp_dlen++;
	}
	*lldp_p++ = (5 << 1); *lldp_p++ = lldp_dlen; lldp_p += lldp_dlen;

	/* System Description: the model name */
	lldp_dlen = 0;
	while (machine.machine_name[lldp_dlen])
		lldp_dlen++;
	*lldp_p++ = (6 << 1); *lldp_p++ = lldp_dlen;
	copy_code(lldp_p, machine.machine_name, lldp_dlen); lldp_p += lldp_dlen;

	/* Capabilities: bridge, enabled */
	*lldp_p++ = (7 << 1); *lldp_p++ = 4;
	*lldp_p++ = 0x00; *lldp_p++ = 0x04; *lldp_p++ = 0x00; *lldp_p++ = 0x04;

	/* Management Address: IPv4, unknown interface numbering */
	*lldp_p++ = (8 << 1); *lldp_p++ = 12;
	*lldp_p++ = 5;		/* address string length: subtype + 4 */
	*lldp_p++ = 1;		/* subtype IPv4 */
	memcpy(lldp_p, (__xdata uint8_t *)&uip_hostaddr, 4); lldp_p += 4;
	*lldp_p++ = 1;		/* if numbering: unknown */
	*lldp_p++ = 0; *lldp_p++ = 0; *lldp_p++ = 0; *lldp_p++ = 0;	/* if index */
	*lldp_p++ = 0;		/* OID length */

	/* End of LLDPDU */
	*lldp_p++ = 0; *lldp_p++ = 0;

	lldp_saved_vlan = management_vlan;
	management_vlan = 0;	/* link-local: egress untagged (cf. stp_cnf_send) */
	uip_len = lldp_p - o;
	tcpip_output();
	management_vlan = lldp_saved_vlan;
	lldp_tx_cnt[port]++;
}


void lldp_in(void) __banked __reentrant
{
	if (!lldpEnabled)
		return;
	lldp_i = uip_buf[12 + 7] & 0x0f;	/* RX port from rtl_tag.pmask low nibble */
	lldp_rx_cnt[lldp_i]++;
	if (uip_buf[LLDP_RX_ETHERTYPE] != 0x88 || uip_buf[LLDP_RX_ETHERTYPE + 1] != 0xcc)
		return;

	memset(&lldp_tmp, 0, sizeof(lldp_tmp));
	lldp_tmp.proto = 1;
	lldp_tmp.port = lldp_i;
	lldp_tmp.ttl = 120;
	lldp_p = &uip_buf[LLDP_RX_PAYLOAD];
	lldp_end = &uip_buf[uip_len > 4 ? uip_len - 2 : 0];
	while (lldp_p < lldp_end) {
		lldp_t = lldp_p[0] >> 1;
		lldp_l = ((uint16_t)(lldp_p[0] & 1) << 8) | lldp_p[1];
		lldp_p += 2;
		if (lldp_t == 0 || lldp_p + lldp_l > lldp_end + 2)
			break;
		switch (lldp_t) {
		case 1:		/* Chassis ID */
			if (lldp_l == 7 && lldp_p[0] == 4)
				memcpy(lldp_tmp.chassis, lldp_p + 1, 6);
			break;
		case 2:		/* Port ID (skip the subtype byte) */
			if (lldp_l >= 2)
				copy_str(lldp_tmp.portid, lldp_p + 1, (uint8_t)(lldp_l - 1), 12);
			break;
		case 3:		/* TTL */
			if (lldp_l == 2)
				lldp_tmp.ttl = ((uint16_t)lldp_p[0] << 8) | lldp_p[1];
			break;
		case 5:		/* System Name */
			copy_str(lldp_tmp.sysname, lldp_p, (uint8_t)lldp_l, 16);
			break;
		}
		lldp_p += lldp_l;
	}
	/* Require a MAC chassis id (the pool key); TTL 0 = shutdown announcement */
	if (lldp_tmp.ttl && (lldp_tmp.chassis[0] | lldp_tmp.chassis[1] | lldp_tmp.chassis[2]
	    | lldp_tmp.chassis[3] | lldp_tmp.chassis[4] | lldp_tmp.chassis[5]))
		commit_tmp();
	uip_len = 0;
}


void cdp_in(void) __banked __reentrant
{
	if (!lldpEnabled)
		return;
	lldp_i = uip_buf[12 + 7] & 0x0f;
	/* LLC/SNAP: AA AA 03, OUI 00:00:0C, PID 0x2000 (payload starts at 26) */
	if (uip_buf[26] != 0xaa || uip_buf[27] != 0xaa || uip_buf[31] != 0x0c
	    || uip_buf[32] != 0x20 || uip_buf[33] != 0x00)
		return;

	memset(&lldp_tmp, 0, sizeof(lldp_tmp));
	lldp_tmp.proto = 2;
	lldp_tmp.port = lldp_i;
	lldp_tmp.ttl = uip_buf[35];	/* CDP header: version, ttl, checksum */
	lldp_p = &uip_buf[38];
	lldp_end = &uip_buf[uip_len];
	while (lldp_p + 4 <= lldp_end) {
		lldp_t = ((uint16_t)lldp_p[0] << 8) | lldp_p[1];
		lldp_l = ((uint16_t)lldp_p[2] << 8) | lldp_p[3];
		if (lldp_l < 4 || lldp_p + lldp_l > lldp_end)
			break;
		if (lldp_t == 0x0001)	/* Device-ID */
			copy_str(lldp_tmp.sysname, lldp_p + 4, (uint8_t)(lldp_l - 4 > 16 ? 16 : lldp_l - 4), 16);
		else if (lldp_t == 0x0003)	/* Port-ID */
			copy_str(lldp_tmp.portid, lldp_p + 4, (uint8_t)(lldp_l - 4 > 12 ? 12 : lldp_l - 4), 12);
		lldp_p += lldp_l;
	}
	if (lldp_tmp.ttl && lldp_tmp.sysname[0])	/* Device-ID is the pool key */
		commit_tmp();
	uip_len = 0;
}


/* ~1 Hz housekeeping driven from the main loop (~256 Hz): neighbor aging
 * and the periodic TX round. */
void lldp_timers(void) __banked
{
	if (++lldp_prescale != 0)
		return;

	for (lldp_i = 0; lldp_i < LLDP_NB_MAX; lldp_i++) {
		if (lldp_nb[lldp_i].proto && --lldp_nb[lldp_i].ttl == 0)
			lldp_nb[lldp_i].proto = 0;
	}

	if (lldp_txwait--)
		return;
	lldp_txwait = lldp_interval_s;
	for (lldp_i = machine.min_port; lldp_i <= machine.max_port; lldp_i++) {
		if (lldp_txmask & (((uint16_t)1) << lldp_i))
			lldp_send(lldp_i);
	}
}


void lldp_on(void) __banked
{
	lldpEnabled = 1;
	lldp_txwait = 1;	/* first TX round within ~2 s */
	/* TRAP (to CPU only), not FORWARD: LLDP (01:80:c2:00:00:0e) is
	 * link-local and must never be relayed to other ports. FORWARD does
	 * deliver to the CPU but ALSO floods the frame across the switch,
	 * making non-adjacent devices appear as each other's LLDP neighbours
	 * through us. Hardware-verified that TRAP still reaches the CPU-RX
	 * ring for this address (unlike slow-protocols/LACP, where trap was
	 * a dead path and forward was required). */
	REG_SET(RTL837X_RMA14_CONF, RTL837X_RMA_ACT_TRAP);
}


void lldp_off(void) __banked
{
	REG_SET(RTL837X_RMA14_CONF, RTL837X_RMA_ACT_DROP);
	lldpEnabled = 0;
	for (lldp_i = 0; lldp_i < LLDP_NB_MAX; lldp_i++)
		lldp_nb[lldp_i].proto = 0;
}


/* Boot defaults: RX on, TX off (hardware-verified hazard: the upstream
 * TP-Link Easy Smart's loop prevention cuts its port on OUR link-local TX -
 * BPDUs and LLDPDUs alike - so announcing ourselves is strictly opt-in,
 * globally or per port), 30 s interval (802.1AB default). */
void lldp_init(void) __banked
{
	lldp_interval_s = 30;
	lldp_txmask = 0;
	for (lldp_i = 0; lldp_i < LLDP_NB_MAX; lldp_i++)
		lldp_nb[lldp_i].proto = 0;
	lldp_on();
}


void lldp_parse(void) __banked
{
	if (cmd_compare(1, "on")) {
		lldp_on();
		return;
	}
	if (cmd_compare(1, "off")) {
		lldp_off();
		return;
	}
	if (cmd_words_len >= 3 && cmd_compare(1, "tx")) {
		if (cmd_compare(2, "on"))
			lldp_txmask = 0x01ff;	/* front ports only; also keeps the
						 * value in itoa16_html()'s range */
		else if (cmd_compare(2, "off"))
			lldp_txmask = 0;
		else
			goto err;
		return;
	}
	if (cmd_words_len >= 5 && cmd_compare(1, "port") && cmd_compare(3, "tx")) {
		if (!atoi_byte(cmd_words_b[2]) || atoi_results_u8 < 1 || atoi_results_u8 > 9)
			goto err;
		lldp_scratch = machine.phys_to_log_port[atoi_results_u8 - 1];
		if (cmd_compare(4, "on"))
			lldp_txmask |= ((uint16_t)1) << lldp_scratch;
		else if (cmd_compare(4, "off"))
			lldp_txmask &= ~(((uint16_t)1) << lldp_scratch);
		else
			goto err;
		return;
	}
	if (cmd_words_len >= 3 && cmd_compare(1, "interval")) {
		if (!atoi_byte(cmd_words_b[2]) || atoi_results_u8 < 5)
			goto err;
		lldp_interval_s = atoi_results_u8;
		return;
	}
	/* "lldp sysname <text>" / "lldp sysdesc <text>": rest of the line
	 * (spaces preserved by the tokenizer), sanitized to printable ASCII. */
err:
	print_string("?lldp\n");
}
