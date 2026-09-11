/*
 * Host-side sandbox for the RTL837x STP/RSTP implementation.
 *
 * Compiles the UNMODIFIED rtl837x_stp.c against shim headers (see shim/) and
 * drives it with synthetic BPDUs from neighbouring bridges. The port states it
 * writes into the ASIC's MSTP register are read back and asserted, so the
 * scenarios test the roles that ship in the firmware image - only the platform
 * below them (frame I/O, registers, console) is mocked.
 *
 * Run: make -C test/stp    (exit code 0 = all scenarios pass)
 */
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <stdbool.h>

#include "rtl837x_common.h"
#include "machine.h"
#include "uip.h"
#include "rtl837x_regs.h"
#include "rtl837x_stp.h"

#define NPORTS	9	/* indices 0..8, front-panel 1..9 */

/* ---------- platform mocks ---------- */

uint8_t uip_buf[UIP_CONF_BUFFER_SIZE + 2];
uint16_t uip_len;
struct uip_eth_addr uip_ethaddr = { .addr = {0x1c,0x2a,0xa3,0x1a,0x72,0x4e} };
struct machine machine = { .min_port = 0, .max_port = NPORTS - 1,
			   .log_to_phys_port = {1, 2, 3, 4, 5, 6, 7, 8, 9} };
struct machine_runtime machine_detected = { .isRTL8373 = 1 };
uint8_t sfr_data[4];
bool stp_enabled;
uint16_t management_vlan;
uint8_t cmd_buffer[CMD_BUF_SIZE];
uint8_t cmd_words_len;
uint8_t cmd_words_b[15];
char save_cmd;
uint8_t atoi_results_u8;

static int verbose;
void print_string(char *s) { if (verbose) fputs(s, stdout); }
void print_byte(uint8_t b) { if (verbose) printf("%02x", b); }
void print_short(uint16_t v) { if (verbose) printf("%04x", v); }
void print_long(uint32_t v) { if (verbose) printf("%08x", v); }
void write_char(char c) { if (verbose) putchar(c); }
void itoa(uint8_t v) { if (verbose) printf("%u", v); }
void print_reg(uint16_t reg) { (void)reg; }

uint8_t cmd_compare(uint8_t start, uint8_t *cmd) { (void)start; (void)cmd; return 0; }
uint8_t atoi_byte(uint8_t idx) { (void)idx; return 0; }
uint8_t cmd_parse_port_separator(uint8_t idx) { (void)idx; return 0; }
void execute_config(void) { }
int8_t vlan_get(uint16_t vlan) { (void)vlan; return -1; }
uint16_t port_pvid_get(uint8_t port) { (void)port; return 1; }
void port_l2mc_set(uint8_t mac_last, uint16_t vid, uint16_t pmask) { (void)mac_last; (void)vid; (void)pmask; }
uint8_t port_ingress_filter_get(uint8_t port) { (void)port; return 0; }

static int flush_count[NPORTS];
void port_l2_forget_port(uint8_t port) { if (port < NPORTS) flush_count[port]++; }

/* The two registers the module touches: the per-port MSTP state (2 bits each,
 * written through sfr_data) and the carrier bitmap it polls once a second. */
static uint8_t mstp_reg[4];
static uint16_t sim_links;
static uint8_t sim_speed[NPORTS];	/* nibble as the ASIC reports it: 2 = 1G, 4 = 10G */
static int tx_frames[NPORTS];

void reg_read_m(uint16_t addr)
{
	memset(sfr_data, 0, 4);
	if (addr == RTL837X_MSTP_STATES)
		memcpy(sfr_data, mstp_reg, 4);
	else if (addr == RTL837X_REG_LINKS_STS) {
		sfr_data[1] = (uint8_t)sim_links;
		sfr_data[2] = (uint8_t)(sim_links >> 8);
	} else if (addr == RTL837X_REG_LINKS || addr == RTL837X_REG_LINKS_89) {
		uint8_t base = (addr == RTL837X_REG_LINKS) ? 0 : 8;
		for (uint8_t k = 0; k < 8 && base + k < NPORTS; k++)
			sfr_data[3 - (k >> 1)] |= (k & 1) ? (uint8_t)(sim_speed[base + k] << 4)
							  : sim_speed[base + k];
	}
}

void reg_write_m(uint16_t addr)
{
	if (addr == RTL837X_MSTP_STATES) {
		memcpy(mstp_reg, sfr_data, 4);
		if (verbose > 1)
			printf("    [mstp <- %02x %02x %02x %02x]\n",
			       mstp_reg[0], mstp_reg[1], mstp_reg[2], mstp_reg[3]);
	}
}

void tcpip_output(void)
{
	/* The TX path fills a CPU-tagged frame; the port bitmap says where. */
	uint16_t pmask = HTONS(((struct { uint8_t a[12]; uint16_t tag; uint8_t v; uint8_t r;
				 uint16_t f; uint16_t pmask; } *)uip_buf)->pmask);
	for (uint8_t p = 0; p < NPORTS; p++)
		if (pmask & (1 << p))
			tx_frames[p]++;
	uip_len = 0;
}

/* ---------- helpers ---------- */

static uint8_t port_state(uint8_t port)
{
	return (mstp_reg[3 - (port >> 2)] >> ((port << 1) & 0x7)) & 0x3;
}

static const char *state_name(uint8_t s)
{
	static const char *n[] = { "off", "discarding", "learning", "forwarding" };
	return n[s & 3];
}

static void links_set(uint16_t mask)
{
	sim_links = mask;
}

/* One pass of the 50 Hz STP tick. */
static void tick(unsigned n)
{
	while (n--)
		stp_timers();
}

static void secs(unsigned s)
{
	tick(s * STP_HZ);
}

/* Feed one Config/RST BPDU in on a port, as the NIC would hand it over. */
struct sim_bpdu {
	uint8_t port;		/* ingress port index */
	uint8_t root_prio;	/* high byte of the root priority */
	uint8_t root_mac[6];
	uint32_t root_cost;	/* root path cost as advertised */
	uint8_t br_prio;	/* sender's own bridge priority high byte */
	uint8_t br_mac[6];
	uint8_t port_id;	/* sender's port number, 1-based */
};

/* The module reads the frame through its own struct; mirror it here so the
 * host compiler lays both out identically instead of guessing offsets. */
struct sim_pkt_in {
	uint8_t stp_addr[6];
	uint8_t src_addr[6];
	struct rtl_tag rtl_tag;
	struct vlan_tag vlan_tag;
	uint16_t msg_len;
	uint8_t dsap;
	uint8_t ssap;
	uint8_t ctrl;
	uint16_t proto;
	uint8_t version;
	uint8_t bpdu_type;
	uint8_t flags;
	struct bridge root;
	uint32_t root_path_cost;
	struct bridge bridge;
	uint8_t port_prio;
	uint8_t port_id;
	uint16_t age;
	uint16_t age_max;
	uint16_t hello;
	uint16_t fwd_delay;
	uint8_t version1_length;
};

static uint32_t swap32(uint32_t v)
{
	return (v << 24) | ((v & 0xff00) << 8) | ((v >> 8) & 0xff00) | (v >> 24);
}

static void bpdu_in(const struct sim_bpdu *b)
{
	struct sim_pkt_in *f = (struct sim_pkt_in *)uip_buf;

	memset(uip_buf, 0, sizeof(uip_buf));
	memcpy(f->stp_addr, "\x01\x80\xc2\x00\x00\x00", 6);
	memcpy(f->src_addr, b->br_mac, 6);
	f->rtl_tag.pmask = HTONS(b->port);
	f->msg_len = HTONS(38);
	f->dsap = 0x42;
	f->ssap = 0x42;
	f->ctrl = 0x03;
	f->proto = 0;
	f->version = 0x02;		/* RSTP */
	f->bpdu_type = 0x02;		/* RST BPDU */
	f->flags = 0x3c;		/* designated, learning + forwarding */
	f->root.prio = b->root_prio;
	f->root.ext = 0;
	memcpy(f->root.mac, b->root_mac, 6);
	f->root_path_cost = swap32(b->root_cost);
	f->bridge.prio = b->br_prio;
	f->bridge.ext = 0;
	memcpy(f->bridge.mac, b->br_mac, 6);
	f->port_prio = 0x80;
	f->port_id = b->port_id;
	f->age = 0;
	f->age_max = HTONS(20);
	f->hello = HTONS(2);
	f->fwd_delay = HTONS(15);
	uip_len = sizeof(struct sim_pkt_in);
	stp_in();
}

/* ---------- scenario plumbing ---------- */

static int failures;

static void check(int cond, const char *what)
{
	if (!cond) {
		printf("  FAIL: %s\n", what);
		failures++;
	} else if (verbose)
		printf("  ok: %s\n", what);
}

static void check_state(uint8_t port, uint8_t want, const char *what)
{
	uint8_t got = port_state(port);
	if (got != want) {
		printf("  FAIL: %s: port %u is %s, expected %s\n",
		       what, port + 1, state_name(got), state_name(want));
		failures++;
	} else if (verbose)
		printf("  ok: %s (port %u %s)\n", what, port + 1, state_name(got));
}

static void reset_all(void)
{
	memset(mstp_reg, 0, sizeof(mstp_reg));
	memset(flush_count, 0, sizeof(flush_count));
	memset(tx_frames, 0, sizeof(tx_frames));
	for (uint8_t p = 0; p < NPORTS; p++)
		sim_speed[p] = 2;	/* 1G unless a scenario says otherwise */
	stp_enabled = 1;
	stp_defaults();
	links_set(0);
	stp_setup();
	tick(2 * STP_HZ);	/* let the link poll see the carrier state */
}

/* The neighbours of the live topology this was written for: a root bridge
 * reached directly on port 9, and a second bridge on port 1 that has its own,
 * cheaper path to that same root. */
static const uint8_t ROOT_MAC[6] = {0x1c,0x2a,0xa3,0x1e,0xc2,0x03};
static const uint8_t PEER_MAC[6] = {0x00,0x82,0x44,0x2a,0x74,0x82};

static void scen_edge_ports(void)
{
	printf("1. a port nobody talks STP on becomes an edge port\n");
	reset_all();
	links_set(1 << 3);
	secs(1);		/* link poll notices the carrier */
	check_state(3, 1, "port with fresh carrier starts discarding");
	secs(4);
	check_state(3, 3, "silent port goes forwarding as an edge port");
}

static void scen_root_port(void)
{
	printf("2. the bridge follows the root heard on port 9\n");
	reset_all();
	links_set(1 << 8);
	secs(1);
	struct sim_bpdu root_bpdu = { .port = 8, .root_prio = 0x40, .root_cost = 0,
				      .br_prio = 0x40, .port_id = 2 };
	memcpy(root_bpdu.root_mac, ROOT_MAC, 6);
	memcpy(root_bpdu.br_mac, ROOT_MAC, 6);
	bpdu_in(&root_bpdu);
	check(stp_root_port == 8, "port 9 becomes the root port");
	secs(20);
	bpdu_in(&root_bpdu);
	check_state(8, 3, "root port forwards after the listen period");
}

static void scen_ring(void)
{
	printf("3. a neighbour with a cheaper path to the root must block us\n");
	reset_all();
	links_set((1 << 0) | (1 << 8));
	secs(1);

	struct sim_bpdu from_root = { .port = 8, .root_prio = 0x40, .root_cost = 0,
				      .br_prio = 0x40, .port_id = 2 };
	memcpy(from_root.root_mac, ROOT_MAC, 6);
	memcpy(from_root.br_mac, ROOT_MAC, 6);

	/* Same root, reached by the peer over a 10G link: cost 2000 against the
	 * 20000 this bridge pays on its own uplink. The peer is therefore the
	 * designated bridge on the port 1 segment and port 1 has to stop
	 * forwarding, or the ring through it stays closed. */
	struct sim_bpdu from_peer = { .port = 0, .root_prio = 0x40, .root_cost = 2000,
				      .br_prio = 0x80, .port_id = 1 };
	memcpy(from_peer.root_mac, ROOT_MAC, 6);
	memcpy(from_peer.br_mac, PEER_MAC, 6);

	for (int i = 0; i < 12; i++) {
		bpdu_in(&from_root);
		bpdu_in(&from_peer);
		secs(2);
	}
	check(stp_root_port == 8, "the direct uplink stays the root port");
	check_state(8, 3, "root port forwards");
	check_state(0, 1, "port 1 is discarding (alternate)");
}

static void scen_ring_clears(void)
{
	printf("4. when the better neighbour goes quiet the port comes back\n");
	scen_ring();
	struct sim_bpdu from_root = { .port = 8, .root_prio = 0x40, .root_cost = 0,
				      .br_prio = 0x40, .port_id = 2 };
	memcpy(from_root.root_mac, ROOT_MAC, 6);
	memcpy(from_root.br_mac, ROOT_MAC, 6);
	/* max age has to expire before the stale information is dropped, and the
	 * listen period runs after that. */
	for (int i = 0; i < 12; i++) {
		bpdu_in(&from_root);
		secs(2);
	}
	check_state(0, 1, "port 1 still discards while the peer information is fresh enough");
	for (int i = 0; i < 14; i++) {
		bpdu_in(&from_root);
		secs(2);
	}
	check_state(0, 3, "port 1 forwards again once the peer information aged out");
}

static void scen_cheaper_path(void)
{
	printf("5. the cheaper of two paths to the root becomes the root port\n");
	reset_all();
	stp_pcost[0] = 2000;		/* a 10G link on port 1 */
	links_set((1 << 0) | (1 << 8));
	secs(1);
	struct sim_bpdu from_root_p9 = { .port = 8, .root_prio = 0x40, .root_cost = 0,
					 .br_prio = 0x40, .port_id = 2 };
	memcpy(from_root_p9.root_mac, ROOT_MAC, 6);
	memcpy(from_root_p9.br_mac, ROOT_MAC, 6);
	struct sim_bpdu from_root_p1 = from_root_p9;
	from_root_p1.port = 0;
	from_root_p1.port_id = 7;
	for (int i = 0; i < 12; i++) {
		bpdu_in(&from_root_p9);
		bpdu_in(&from_root_p1);
		secs(2);
	}
	check(stp_root_port == 0, "port 1 wins on cost and becomes the root port");
	check(root_bridge_cost == 2000, "the root path cost follows that port");
	check_state(0, 3, "the root port forwards");
	check_state(8, 1, "the dearer path to the same root is discarding");
	stp_pcost[0] = 0;
}

static void scen_we_are_better(void)
{
	printf("6. a neighbour with a worse path does not block us\n");
	reset_all();
	links_set((1 << 0) | (1 << 8));
	secs(1);
	struct sim_bpdu from_root = { .port = 8, .root_prio = 0x40, .root_cost = 0,
				      .br_prio = 0x40, .port_id = 2 };
	memcpy(from_root.root_mac, ROOT_MAC, 6);
	memcpy(from_root.br_mac, ROOT_MAC, 6);
	/* The peer reaches the same root, but only through a chain that costs
	 * more than our own uplink: we stay the designated bridge there. */
	struct sim_bpdu from_peer = { .port = 0, .root_prio = 0x40, .root_cost = 200000,
				      .br_prio = 0x80, .port_id = 1 };
	memcpy(from_peer.root_mac, ROOT_MAC, 6);
	memcpy(from_peer.br_mac, PEER_MAC, 6);
	for (int i = 0; i < 12; i++) {
		bpdu_in(&from_root);
		bpdu_in(&from_peer);
		secs(2);
	}
	check(stp_root_port == 8, "the uplink stays the root port");
	check_state(0, 3, "port 1 keeps forwarding");
}

static void scen_alt_survives_link_bounce(void)
{
	printf("7. a blocked port stays blocked when the carrier returns\n");
	scen_ring();
	struct sim_bpdu from_root = { .port = 8, .root_prio = 0x40, .root_cost = 0,
				      .br_prio = 0x40, .port_id = 2 };
	memcpy(from_root.root_mac, ROOT_MAC, 6);
	memcpy(from_root.br_mac, ROOT_MAC, 6);
	struct sim_bpdu from_peer = { .port = 0, .root_prio = 0x40, .root_cost = 2000,
				      .br_prio = 0x80, .port_id = 1 };
	memcpy(from_peer.root_mac, ROOT_MAC, 6);
	memcpy(from_peer.br_mac, PEER_MAC, 6);

	/* The peer sends before the once-a-second carrier poll notices the link,
	 * which is what put the port back on the listen timer on real hardware. */
	links_set(1 << 8);
	secs(2);
	links_set((1 << 0) | (1 << 8));
	bpdu_in(&from_peer);
	for (int i = 0; i < 15; i++) {
		bpdu_in(&from_root);
		bpdu_in(&from_peer);
		secs(2);
	}
	check_state(0, 1, "port 1 never reaches forwarding while the peer is better");
	check(stp_root_port == 8, "the uplink is still the root port");
}

static void scen_speed_cost(void)
{
	printf("8. the faster of two links to one root wins on cost\n");
	reset_all();
	sim_speed[8] = 4;		/* 10G uplink on port 9 */
	sim_speed[0] = 2;		/* 1G on port 1 */
	links_set((1 << 0) | (1 << 8));
	secs(1);
	struct sim_bpdu from_root = { .port = 8, .root_prio = 0x40, .root_cost = 0,
				      .br_prio = 0x40, .port_id = 2 };
	memcpy(from_root.root_mac, ROOT_MAC, 6);
	memcpy(from_root.br_mac, ROOT_MAC, 6);
	struct sim_bpdu slow = from_root;
	slow.port = 0;
	slow.port_id = 7;
	for (int i = 0; i < 12; i++) {
		bpdu_in(&from_root);
		bpdu_in(&slow);
		secs(2);
	}
	check(stp_root_port == 8, "the 10G port is the root port");
	check(root_bridge_cost == 2000, "its cost is the 10G value, not a flat default");
}

int main(int argc, char **argv)
{
	verbose = argc > 1 && argv[1][0] == '-' ? (argv[1][1] == 'd' ? 2 : 1) : 0;
	scen_edge_ports();
	scen_root_port();
	scen_ring();
	scen_ring_clears();
	scen_cheaper_path();
	scen_we_are_better();
	scen_alt_survives_link_bounce();
	scen_speed_cost();
	if (failures) {
		printf("\n%d check(s) failed\n", failures);
		return 1;
	}
	printf("\nall scenarios passed\n");
	return 0;
}
