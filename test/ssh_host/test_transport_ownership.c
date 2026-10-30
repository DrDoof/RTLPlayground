/*
 * Host-side bench for the httpd transmit and firmware upload paths.
 *
 * Compiles the UNMODIFIED httpd/httpd.c and uip/uip.c and drives them through a
 * real handshake, GETs with moving receive windows, and multipart POSTs.
 * Everything below the two modules - flash, console, JSON pages - is mocked
 * here, so the bench observes the wire response and the bytes staged to flash.
 *
 * The file served out of the simulated flash carries a position-dependent
 * pattern, so a duplicated or skipped range shows up as a mismatch at a known
 * offset instead of an anonymous "content differs".
 *
 * Run: make -C test    (exit code 0 = all scenarios pass)
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* Some hosts ship these in <sys/_endian.h>, and they assign to their argument;
 * uip.h refuses to be included next to them. The firmware definitions are the
 * ones this bench needs, so the host macros go first. */
#undef HTONS
#undef NTOHS
/* glibc uses different endian constants from this uIP fork. */
#undef LITTLE_ENDIAN
#define LITTLE_ENDIAN 3412

#include "httpd.h"
#include "ssh/ssh.h"
#include "ssh/ssh_fw.h"
#include "uip.h"
#include "rtl837x_common.h"
#include "rtl837x_regs.h"
#include "rtl837x_flash.h"
#include "page_impl.h"
#include "html_data.h"

/* Private to uip.c, and the client needs them to build segments. */
#define TCP_SYN 0x02
#define TCP_PSH 0x08
#define TCP_ACK 0x10

#define TCPH		((struct uip_tcpip_hdr *)&uip_buf[UIP_LLH_LEN])

#define MSS_FULL	1460
#define SMALL_WINDOW	600

/* httpd.c serves this one file without a session, which keeps the bench clear
 * of the login machinery: what is under test is the transmit path. */
#define FILE_START	FDATA_START_login_html
#define FILE_NAME	"/login.html"
#define FILE_LEN	6000
#define PROTECTED_FILE_NAME	"/index.html"
#define PROTECTED_FILE_START	(FILE_START + FILE_LEN + 64)
#define PROTECTED_FILE_LEN	64
#define STREAM_MAX	16384

static int failures;
static int verbose;

#define CHECK(cond, name) do { \
	if (cond) printf("PASS  %s\n", name); \
	else { printf("FAIL  %s\n", name); failures++; } \
} while (0)

static uint8_t pattern(uint32_t addr)
{
	return (uint8_t)((addr * 7u) + (addr >> 8));
}

/* ---- firmware environment below httpd.c --------------------------------- */

volatile uint8_t sfr_data[4];
volatile uint32_t ticks;
uint8_t cmd_capture;
uint8_t err_status;
const uint8_t * const hex = (const uint8_t *)"0123456789abcdef";
uint16_t crc_value;
const uint8_t * const HTTP_RESPONCE_TXT = (const uint8_t *)"HTTP/1.1 200 OK\r\n\r\n";
uint32_t flash_size = 0x80000;
uint8_t flash_buf[FLASH_BUF_SIZE];
uint8_t rx_headers[16];
struct flash_region_t flash_region;

static uint8_t written_config[CONFIG_LEN];
static uint16_t written_config_len;
static uint32_t config_erase_addr, config_write_addr;
static int config_erases, config_writes;
static uint8_t flash_written[1024];
static size_t flash_written_len;
static int flash_write_bad;

const char * const mime_strings[] = { "text/html", "image/svg+xml", "image/x-icon",
			 "image/png", "text/javascript", "text/css", "text/plain" };

const struct f_data f_data[] = {
	{ FILE_NAME, FILE_START, FILE_LEN, mime_HTML, 0 },
	{ PROTECTED_FILE_NAME, PROTECTED_FILE_START, PROTECTED_FILE_LEN, mime_HTML, 0 },
	{ 0, 0, 0, mime_HTML, 0 },
};

void flash_read_bulk(uint8_t *dst)
{
	for (uint16_t i = 0; i < flash_region.len; i++)
		dst[i] = pattern(flash_region.addr + i);
}

void flash_init(uint8_t enable_dio) { (void)enable_dio; }
void flash_sector_erase(void)
{
	config_erases++;
	config_erase_addr = flash_region.addr;
}

void flash_write_bytes(uint8_t *ptr)
{
	if (flash_region.addr < FIRMWARE_UPLOAD_START) {
		config_writes++;
		config_write_addr = flash_region.addr;
		written_config_len = flash_region.len;
		if (written_config_len <= sizeof(written_config))
			memcpy(written_config, ptr, written_config_len);
		return;
	}
	if (flash_region.addr != FIRMWARE_UPLOAD_START + flash_written_len ||
	    flash_region.len > sizeof(flash_written) - flash_written_len) {
		flash_write_bad = 1;
		return;
	}
	memcpy(flash_written + flash_written_len, ptr, flash_region.len);
	flash_written_len += flash_region.len;
}
const char *get_flash_size_str(void) { return "512 kB"; }
void crc16_bank1(uint8_t *v) { (void)v; }
static unsigned reset_calls;
void reset_chip(void) { reset_calls++; }
void delay(uint16_t t) { (void)t; }
void write_char(char c) { (void)c; }
void write_char_no_syslog(char c) { (void)c; }
void itoa_no_syslog(uint8_t v) { (void)v; }
void print_long(uint32_t n) {(void)n;}
void print_short(uint16_t n) {(void)n;}
void print_byte(uint8_t n) {(void)n;}
void print_string(const char *p) { (void)p; }
void print_string_no_syslog(const char *p) { (void)p; }
void print_string_newline_no_syslog(const char *p) { printf("uip: %s\n",p); }
void set_sys_led_state(uint8_t state) { (void)state; }
void cmd_parser(void) { }
void execute_config(void) { }
extern uint8_t ssh_command_buf[]; extern uint16_t ssh_command_len; extern uint8_t outbuf[]; extern uint16_t slen;
void execute_commands(uint8_t *p) { (void)p; for(unsigned i=0;i<2000;i++) { if(cmd_capture==3) ssh_command_buf[ssh_command_len++]=(uint8_t)('A'+i%23); else if(cmd_capture==1) outbuf[slen++]=(uint8_t)('h'+i%7); } }
void clear_command_history(void) { }
void udp_callbacks(void) { }
void tcpip_output(void) { }
void get_random_32(void) { }
static uint32_t fake_now;
void read_reg_timer(uint32_t *tmr) { *tmr = fake_now; }

/* uip-conf.h asks uIP not to define the packet buffer: on the switch it lives
 * at a fixed XDATA address, so the bench provides the storage itself. */
u8_t uip_buf[UIP_CONF_BUFFER_ALLOC_SIZE];

uint16_t strlen_x(const char *s) { return (uint16_t)strlen(s); }

uint16_t strtox(uint8_t *dst, const char *s)
{
	uint16_t n = 0;

	while (s[n]) { dst[n] = (uint8_t)s[n]; n++; }
	return n;
}

void memcpyc(uint8_t *dst, const uint8_t *src, uint16_t len) { memcpy(dst, src, len); }

bool strstart(const uint8_t *a, const uint8_t *b)
{
	while (*b) { if (*a++ != *b++) return false; }
	return true;
}

bool strstart_x(const uint8_t *a, const uint8_t *b) { return strstart(a, b); }

bool send_counters(uint8_t phys_port) { (void)phys_port; return false; }
void send_status(void) { }
void send_vlan(uint16_t vlan) { (void)vlan; }
void send_basic_info(void) { }
void send_bandwidth(void) { }
void send_storm(void) { }
void send_isolation(void) { }
void send_eee(void) { }
void send_l2(uint16_t idx) { (void)idx; }
void l2_delete(uint16_t idx) { (void)idx; }
void send_mirror(void) { }
void send_mtu(void) { }
void send_config(void) { }
void send_cmd_log(void) { }
void send_lacp(void) { }
void send_lag(void) { }
void send_stp(void) { }
void send_stp_counters(void) { }
void send_vlanlist(void) { }
void send_lldp(void) {}

extern uint8_t authenticated;
extern char session_id[];
extern uint32_t last_session_use[];
extern char passwd[21];
extern uint16_t session_timeout;

/* uip.c defines the listen table but no header declares it; the bench reads it
 * to confirm the port httpd_init() asked for is the one uIP is watching. */
extern u16_t uip_listenports[UIP_LISTENPORTS];


extern uint8_t pm_h[17], pm_r[16];

static void poly_block(const uint8_t *m, int hibit)
{
	uint32_t acc[34] = {0}, h[18], t = 0;
	for (int i = 0; i < 17; i++) {
		t += pm_h[i] + (i < 16 ? m[i] : hibit);
		h[i] = t & 0xff;
		t >>= 8;
	}
	h[17] = t;
	for (int i = 0; i < 18; i++)
		for (int j = 0; j < 16; j++)
			acc[i + j] += h[i] * pm_r[j];
	uint8_t pr[36] = {0};
	uint64_t c = 0;
	for (int i = 0; i < 34; i++) {
		c += acc[i];
		pr[i] = c & 0xff;
		c >>= 8;
	}
	for (int round = 0; round < 3; round++) {
		uint8_t hi[20] = {0};
		for (int i = 0; i < 19; i++) {
			int bi = 16 + i;
			uint32_t v = (bi < 36 ? pr[bi] : 0) | ((bi + 1 < 36 ? pr[bi + 1] : 0) << 8);
			hi[i] = (v >> 2) & 0xff;
		}
		pr[16] &= 3;
		for (int i = 17; i < 36; i++) pr[i] = 0;
		uint32_t cc = 0;
		for (int i = 0; i < 36; i++) {
			uint32_t add = i < 20 ? hi[i] * 5 : 0;
			cc += pr[i] + add;
			pr[i] = cc & 0xff;
			cc >>= 8;
		}
	}
	for (int i = 0; i < 17; i++) pm_h[i] = pr[i];
}
void poly_block_hi(const uint8_t *src) { poly_block(src, 1); }
void poly_block_lo(const uint8_t *src) { poly_block(src, 0); }

#define ROTL(a,b) (((a) << (b)) | ((a) >> (32 - (b))))
#define QR(a,b,c,d) (a += b, d ^= a, d = ROTL(d,16), c += d, b ^= c, b = ROTL(b,12), a += b, d ^= a, d = ROTL(d, 8), c += d, b ^= c, b = ROTL(b, 7))
static uint32_t le32(const uint8_t *p) { return p[0] | p[1] << 8 | p[2] << 16 | (uint32_t)p[3] << 24; }

void ssh_chacha_xor(const uint8_t *key, const uint8_t *seq, uint8_t ctr, uint8_t *buf, uint16_t len)
{
	uint32_t in[16], x[16];
	uint8_t ks[64];
	in[0] = 0x61707865; in[1] = 0x3320646e; in[2] = 0x79622d32; in[3] = 0x6b206574;
	for (int i = 0; i < 8; i++) in[4 + i] = le32(key + 4 * i);
	in[12] = ctr; in[13] = 0; in[14] = le32(seq); in[15] = le32(seq + 4);
	while (len) {
		memcpy(x, in, sizeof x);
		for (int i = 0; i < 10; i++) {
			QR(x[0], x[4], x[8], x[12]); QR(x[1], x[5], x[9], x[13]); QR(x[2], x[6], x[10], x[14]); QR(x[3], x[7], x[11], x[15]);
			QR(x[0], x[5], x[10], x[15]); QR(x[1], x[6], x[11], x[12]); QR(x[2], x[7], x[8], x[13]); QR(x[3], x[4], x[9], x[14]);
		}
		for (int i = 0; i < 16; i++) {
			uint32_t v = x[i] + in[i];
			ks[4 * i] = v; ks[4 * i + 1] = v >> 8; ks[4 * i + 2] = v >> 16; ks[4 * i + 3] = v >> 24;
		}
		int n = len < 64 ? len : 64;
		for (int i = 0; i < n; i++) *buf++ ^= ks[i];
		len -= n;
		in[12]++;
	}
}


#define slen ssh_parser_slen
#include "../../ssh/ssh.c"
#undef slen
static uint32_t last_tcp_seq;
static uint16_t cli_port=80, cli_srcport=40000;
static uint32_t cli_seq;	/* next sequence number we send */
static uint32_t cli_rcv_nxt;	/* next sequence number we expect */
static uint16_t cli_window;	/* what we advertise */

static uint8_t stream[STREAM_MAX];	/* bytes accepted from the server */
static int stream_len;

static uint8_t last_tx[MSS_FULL + 64];	/* payload of the last server segment */
static int last_tx_len;

static uint16_t hton16(uint16_t v)
{
	return (uint16_t)((v << 8) | (v >> 8));
}

static void wr32(uint8_t *p, uint32_t v)
{
	p[0] = v >> 24; p[1] = v >> 16; p[2] = v >> 8; p[3] = v;
}

static uint32_t rd32(const uint8_t *p)
{
	return ((uint32_t)p[0] << 24) | ((uint32_t)p[1] << 16) |
	       ((uint32_t)p[2] << 8) | p[3];
}

static void trace(const char *tag)
{
	if (!verbose)
		return;
	printf("      [%-8s] uip_len=%-5u flags=0x%02x seq=%-6u ack=%-6u | conn: state=0x%02x len=%-5u mss=%-5u tstate=%u\n",
	       tag, uip_len,
	       uip_len ? TCPH->flags : 0,
	       uip_len ? rd32(TCPH->seqno) : 0,
	       uip_len ? rd32(TCPH->ackno) : 0,
	       uip_conns[0].tcpstateflags, uip_conns[0].len, uip_conns[0].mss,
	       uip_conns[0].appstate.tstate);
}

/* Takes in one outgoing segment, if uIP produced one. */
static int harvest(void)
{
	uint8_t *payload;
	uint32_t seq;
	int plen, hlen;

	if (uip_len == 0)
		return -1;

	seq = rd32(TCPH->seqno);
	/* The SYNACK carries the MSS option, so the header is not always 20 B. */
	hlen = (TCPH->tcpoffset >> 4) * 4;
	payload = &uip_buf[UIP_LLH_LEN + 20 + hlen];
	plen = (int)uip_len - 20 - hlen;
	if (plen < 0)
		plen = 0;

	if (plen > 0) {
		last_tcp_seq=seq;
		last_tx_len = plen > (int)sizeof(last_tx) ? (int)sizeof(last_tx) : plen;
		memcpy(last_tx, payload, last_tx_len);

		/* A real client keeps what continues the stream and drops the
		 * rest, so bytes sent twice under new sequence numbers land in
		 * the file just as they would in a browser. */
		if (seq == cli_rcv_nxt) {
			if (stream_len + plen <= STREAM_MAX) {
				memcpy(stream + stream_len, payload, plen);
				stream_len += plen;
			}
			cli_rcv_nxt += plen;
		}
		if (verbose)
			printf("      server -> %d B, seq %u\n", plen, seq);
	}
	if (TCPH->flags & TCP_SYN)
		cli_rcv_nxt = seq + 1;

	uip_len = 0;
	return plen;
}

static void client_send(uint8_t flags, const char *payload, int plen)
{
	int hlen = 20;

	/* A SYN carries the MSS option, as every real client does: uIP takes the
	 * connection MSS from it, and without one the server has nothing to send
	 * with. */
	if (flags & TCP_SYN)
		hlen = 24;

	memset(uip_buf, 0, UIP_LLH_LEN + 20 + hlen + (plen > 0 ? plen : 0));
	TCPH->vhl = 0x45;
	TCPH->tos = 0;
	TCPH->len[0] = (uint8_t)((20 + hlen + plen) >> 8);
	TCPH->len[1] = (uint8_t)((20 + hlen + plen) & 0xff);
	TCPH->ttl = 64;
	TCPH->proto = UIP_PROTO_TCP;
	TCPH->ipchksum = 0;
	TCPH->srcipaddr[0] = hton16(0x0a00); TCPH->srcipaddr[1] = hton16(0x0002);
	TCPH->destipaddr[0] = hton16(0x0a00); TCPH->destipaddr[1] = hton16(0x0001);
	TCPH->srcport = hton16(cli_srcport);
	TCPH->destport = hton16(cli_port);
	wr32(TCPH->seqno, cli_seq);
	wr32(TCPH->ackno, cli_rcv_nxt);
	TCPH->tcpoffset = (uint8_t)((hlen / 4) << 4);
	TCPH->flags = flags;
	TCPH->wnd[0] = (uint8_t)(cli_window >> 8);
	TCPH->wnd[1] = (uint8_t)(cli_window & 0xff);
	TCPH->tcpchksum = 0;

	if (hlen == 24) {
		uint8_t *opt = &uip_buf[UIP_LLH_LEN + 40];

		opt[0] = 2; opt[1] = 4;			/* kind = MSS, length 4 */
		opt[2] = MSS_FULL >> 8; opt[3] = MSS_FULL & 0xff;
	}
	if (plen > 0)
		memcpy(&uip_buf[UIP_LLH_LEN + 20 + hlen], payload, plen);

	uip_len = 20 + hlen + plen;

	uip_input();
	trace("input");
	cli_seq += plen;
	if (flags & TCP_SYN)
		cli_seq++;
	harvest();
}

static void client_ack(uint16_t window)
{
	cli_window = window;
	client_send(TCP_ACK, NULL, 0);
}

static void run_periodic(int rounds)
{
	for (int i = 0; i < rounds; i++) {
		uip_periodic(0);
		trace("timer");
		harvest();
	}
}



static void connected(uint16_t port,uint16_t source){cli_port=port;cli_srcport=source;cli_seq=1000;cli_rcv_nxt=0;cli_window=MSS_FULL;stream_len=last_tx_len=0;client_send(TCP_SYN,0,0);client_ack(MSS_FULL);}
static void core_session(void){closing=0;rx_state=ST_ENC;rx_need=4;rx_have=0;enc_on=authed=chan_open=1;kex_state=K_DONE;txq_len=fl_on=flight_len=0;tx_seq=rx_seq=0;remote_window=4096;remote_maxpkt=256;shell=pty=exec_done=0;src_pos=src_len=0;memset(key_c2s,0,64);memset(key_s2c,0,64);phase=3;fragment_pending=stall_pending=0;}
static unsigned ssh_index(void){for(unsigned i=0;i<UIP_CONNS;i++)if(uip_conns[i].lport==HTONS(22))return i;abort();}
static void periodic_ssh(unsigned rounds){for(unsigned i=0;i<rounds;i++){uip_periodic(ssh_index());harvest();}}
static void timeout_cases(void){
 uint32_t start=0xfffffff0U;
 ssh_timeout(start);ssh_reset();txq_len=0;ssh_timeout(start+2999U);CHECK(!closing,"ident deadline before wrap boundary");ssh_timeout(start+3000U);CHECK(closing,"ident deadline at wrapped boundary");
 core_session();phase=2;phase_at=start;clock_tick=start;authed=0;ssh_timeout(start+11999U);CHECK(!closing,"auth deadline before boundary");ssh_timeout(start+12000U);CHECK(closing,"auth deadline absolute");
 core_session();clock_tick=start;uint8_t byte=0;ssh_input(&byte,1);ssh_timeout(start+1999U);CHECK(!closing,"fragment before boundary");ssh_timeout(start+2000U);CHECK(closing,"fragment absolute wrap deadline");
 core_session();src_len=2;ssh_timeout(start);ssh_timeout(start+5999U);CHECK(!closing,"stall before boundary");ssh_timeout(start+6000U);CHECK(closing,"stall at boundary");
 core_session();src_len=64;remote_window=0;ssh_timeout(start);clock_tick=start+5000U;txq_len=0;q_simple(2);uint8_t control[128];ssh_output(control,sizeof control,0);ssh_acked();ssh_timeout(start+6000U);CHECK(closing,"unrelated control ACK does not extend source stall");
 core_session();enc_on=0;phase=1;phase_at=start;ssh_timeout(start+17999U);CHECK(!closing,"KEX before boundary");ssh_timeout(start+18000U);CHECK(closing,"KEX absolute wrap deadline");
}
int main(void){setbuf(stdout,NULL);puts("begin transport");CHECK(UIP_TCP_MSS==1460&&UIP_CONNS==2,"exact target MSS and two TCP slots");
 uip_init();uip_hostaddr[0]=uip_hostaddr[1]=0;httpd_init();ssh_start();printf("listen %x %x sizeofconn %zu\n",uip_listenports[0],uip_listenports[1],sizeof(struct uip_conn));connected(22,40022);client_ack(MSS_FULL);core_session();
 src_len=ssh_port_exec((uint8_t*)"big");src_pos=0;last_tx_len=0;periodic_ssh(1);CHECK(fl_on&&last_tx_len>0,"actual uIP sends SSH ciphertext");
 uint8_t original[1472];unsigned original_len=last_tx_len;uint32_t original_seq=cli_rcv_nxt-original_len;memcpy(original,last_tx,original_len);uint32_t sseq=cli_seq,sack=cli_rcv_nxt;
 connected(80,40080);client_send(TCP_ACK|TCP_PSH,"GET /login.html HTTP/1.1\r\nHost: sw\r\n\r\n",strlen("GET /login.html HTTP/1.1\r\nHost: sw\r\n\r\n"));CHECK(last_tx_len>0,"HTTP response interleaved");unsigned http_len=last_tx_len;uint8_t http_copy[1472];memcpy(http_copy,last_tx,http_len);uint32_t hseq=cli_seq,hack=cli_rcv_nxt;
 /* Neither callback buffer nor source mode may change the retained flight. */
 cli_port=22;cli_srcport=40022;cli_seq=sseq;cli_rcv_nxt=original_seq+original_len/2;cli_window=64;client_send(TCP_ACK,0,0);CHECK(fl_on,"actual partial ACK does not release SSH flight");
 uint32_t sequence_before=tx_seq;pty=1;memset(uip_buf,0xa5,sizeof uip_buf);last_tx_len=0;periodic_ssh(UIP_RTO+3);CHECK(last_tx_len==original_len&&!memcmp(last_tx,original,original_len),"actual uIP retransmit exact ciphertext after HTTP and smaller MSS");CHECK(last_tcp_seq==original_seq,"TCP sequence unchanged on retransmit");CHECK(tx_seq==sequence_before,"retransmit keeps SSH sequence");
 last_tx_len=0;uip_conns[ssh_index()].timer=0;periodic_ssh(1);CHECK(last_tx_len==original_len&&!memcmp(last_tx,original,original_len),"repeated actual retransmit exact bytes");
 cli_rcv_nxt=sack;client_ack(MSS_FULL);CHECK(src_pos>0||!src_len,"full TCP ACK advances source");
 cli_port=80;cli_srcport=40080;cli_seq=hseq;cli_rcv_nxt=hack-http_len;last_tx_len=0;uip_conn=&uip_conns[1-ssh_index()];uip_conn->timer=0;uip_periodic(1-ssh_index());harvest();CHECK(last_tx_len==http_len&&!memcmp(last_tx,http_copy,http_len),"HTTP retransmit unchanged after SSH activity");
 /* Ownership spans FIN_WAIT; stale callbacks cannot write a new owner. */
 struct uip_conn *old=&uip_conns[1-ssh_index()],*other=&uip_conns[ssh_index()];uip_conn=old;old->tcpstateflags=UIP_FIN_WAIT_1;uint16_t oldlen=slen;uip_conn=other;uip_flags=UIP_CONNECTED;httpd_appcall();CHECK((uip_flags&UIP_ABORT)&&slen==oldlen,"closing HTTP owner excludes new claimant");
 uip_conn=old;uip_flags=UIP_ABORT;httpd_appcall();uip_conn=other;uip_flags=UIP_CONNECTED;httpd_appcall();other->tcpstateflags=UIP_ESTABLISHED;uint8_t generation=other->appstate.output_generation;uip_conn=old;uip_flags=UIP_REXMIT;httpd_appcall();CHECK(other->appstate.output_generation==generation&&slen==0,"stale old callback cannot alter new generation");
 timeout_cases();
 /* Actual timeout callback closes TCP, not just the core state. */
 ticks=0;uip_init();httpd_init();ssh_start();connected(22,40022);unsigned timed_index=ssh_index();printf("before deadline phase %u at %u clock %u closing %u state %u len %u timer %u\n",phase,phase_at,clock_tick,closing,uip_conns[timed_index].tcpstateflags,uip_conns[timed_index].len,uip_conns[timed_index].timer);ticks=3000;ssh_idle();uip_periodic(timed_index);printf("after deadline phase %u at %u clock %u closing %u state %u len %u timer %u\n",phase,phase_at,clock_tick,closing,uip_conns[timed_index].tcpstateflags,uip_conns[timed_index].len,uip_conns[timed_index].timer);CHECK((uip_conns[timed_index].tcpstateflags&UIP_TS_MASK)==UIP_CLOSED&&ssh_closing(),"absolute deadline aborts actual TCP owner");
 printf("integrated failures=%d\n",failures);return failures?1:0;
}
