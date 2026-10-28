#pragma codeseg BANK4
#pragma constseg BANK4

#include <stdint.h>
#include "ssh.h"
#include "../crypto/sha256.h"
#include "../crypto/poly1305.h"
#include "../crypto/x25519.h"
#include "../crypto/ed25519.h"

#define RXMAX 512
#define KEXMAX 4096
#define VERSIONMAX 253
#define TXQMAX 512
#define LINEMAX 64
#define LOCAL_WINDOW 4096
#define LOCAL_MAXPKT 256

#define F_PLAIN 1
#define F_RAW 2

#define ST_VERSION 0
#define ST_HEADER 1
#define ST_KEXINIT 2
#define ST_PLAIN 3
#define ST_ENC 4

#define K_WAIT_KEXINIT 0
#define K_WAIT_ECDH 1
#define K_SHARED 2
#define K_SIGN 3
#define K_WAIT_NEWKEYS 4
#define K_DONE 5
#define K_GOT_ECDH 6
#define K_HASH 7
#define K_DC0 8
#define K_DC1 9
#define K_DD0 10
#define K_DD1 11

static __code const char v_s[] = "SSH-2.0-RTLPlayground_0.1";
static __code const char n_kex[] = "curve25519-sha256";
static __code const char n_hostkey[] = "ssh-ed25519";
static __code const char n_cipher[] = "chacha20-poly1305@openssh.com";
static __code const char n_mac[] = "hmac-sha2-256";
static __code const char n_none[] = "none";
static __code const char n_userauth[] = "ssh-userauth";
static __code const char n_password[] = "password";
static __code const char n_session[] = "session";
static __code const char n_ptyreq[] = "pty-req";
static __code const char n_shell[] = "shell";
static __code const char n_exec[] = "exec";
static __code const char n_exitstatus[] = "exit-status";
static __code const char banner[] = "RTLPlayground SSH test\r\n> ";
static __code const char prompt[] = "> ";

static __xdata uint8_t rxbuf[RXMAX];
static __xdata uint16_t rx_have, rx_need, rx_left;
static __xdata uint8_t rx_state;
static __xdata uint32_t rx_seq, tx_seq;

static __xdata uint8_t txq[TXQMAX];
static __xdata uint16_t txq_len;
static __xdata uint16_t fl_q, fl_src, fl_win;
static __xdata uint8_t fl_pkts, fl_on;

static __xdata uint8_t kex_state;
static __xdata uint8_t cookie[16];
static __xdata uint8_t eph[32], q_s[32], q_c[32], kk[32], hh[32], sid[32];
static __xdata uint8_t eph_ready, eph_job;
__xdata uint8_t ssh_active;
static __xdata uint8_t key_c2s[64], key_s2c[64];
static __xdata uint8_t enc_on;

static __xdata uint8_t authed, closing;
static __xdata uint8_t service_ready, skip_guess;
static __xdata uint32_t chan_peer, remote_window, remote_maxpkt;
static __xdata uint16_t local_window;
static __xdata uint8_t chan_open, pty, shell, exec_done, close_sent;
static __xdata uint8_t line[LINEMAX + 1];
static __xdata uint8_t line_len;
static __xdata uint16_t src_pos, src_len;

static __xdata uint8_t emit_hash;
static __xdata uint8_t * __xdata emit_dst;
static __xdata uint8_t tmp4[4];
static __xdata uint8_t seqb[8];
static __xdata uint8_t polykey[32];
static __xdata uint8_t tag[16];

static __xdata const uint8_t * __xdata rp;
static __xdata uint16_t rlen;

/* Sticky, terminal rejection: do not drain or retransmit partially built data. */
static void reject(void)
{
	closing = 1;
	authed = chan_open = 0;
	txq_len = src_len = src_pos = 0;
	fl_on = 0;
	rlen = 0;
}

void ssh_input_eof(void)
{
	reject();
}

static __xdata uint16_t emit_count;

static void put_x(__xdata const uint8_t *p, uint16_t n) __reentrant
{
	if (closing)
		return;
	if (emit_hash == 2) {
		emit_count += n;
		return;
	}
	if (emit_hash) {
		sha256_update(p, n);
		return;
	}
	if (n > (uint16_t)(txq + TXQMAX - emit_dst)) {
		reject();
		return;
	}
	while (n--)
		*emit_dst++ = *p++;
}

static void put_u32(uint32_t v)
{
	tmp4[0] = v >> 24;
	tmp4[1] = v >> 16;
	tmp4[2] = v >> 8;
	tmp4[3] = v;
	put_x(tmp4, 4);
}

static void put_byte(uint8_t b)
{
	tmp4[0] = b;
	put_x(tmp4, 1);
}

static void put_c(__code const char *s)
{
	while (*s)
		put_byte(*s++);
}

static uint8_t clen(__code const char *s)
{
	uint8_t n = 0;

	while (s[n])
		n++;
	return n;
}

static void put_cstr(__code const char *s)
{
	put_u32(clen(s));
	put_c(s);
}

static void put_str(__xdata const uint8_t *p, uint16_t n) __reentrant
{
	put_u32(n);
	put_x(p, n);
}

static void put_mpint(__xdata const uint8_t *p)
{
	static __xdata uint8_t i, lead;

	i = 0;
	while (i < 32 && !p[i])
		i++;
	lead = i < 32 && (p[i] & 0x80);
	put_u32(32 - i + lead);
	if (lead)
		put_byte(0);
	put_x(p + i, 32 - i);
}

static void put_kexinit(void)
{
	put_byte(20);
	put_x(cookie, 16);
	put_cstr(n_kex);
	put_cstr(n_hostkey);
	put_cstr(n_cipher);
	put_cstr(n_cipher);
	put_cstr(n_mac);
	put_cstr(n_mac);
	put_cstr(n_none);
	put_cstr(n_none);
	put_u32(0);
	put_u32(0);
	put_byte(0);
	put_u32(0);
}

static void put_hostkey(void)
{
	put_u32(4 + 11 + 4 + 32);
	put_cstr(n_hostkey);
	put_str(ed_pub, 32);
}

static __xdata uint8_t * __xdata q_hdr;

static void q_begin(uint8_t flags)
{
	if (closing)
		return;
	if (txq_len > TXQMAX - 3) {
		reject();
		return;
	}
	q_hdr = txq + txq_len;
	q_hdr[2] = flags;
	emit_hash = 0;
	emit_dst = q_hdr + 3;
}

static void q_end(void)
{
	static __xdata uint16_t n;

	if (closing)
		return;
	n = emit_dst - q_hdr - 3;
	q_hdr[0] = n >> 8;
	q_hdr[1] = n;
	txq_len += n + 3;
}

static uint8_t q_room(uint16_t n)
{
	return n <= TXQMAX - 3 && txq_len <= TXQMAX - 3 - n;
}

static void seq_bytes(uint32_t s)
{
	seqb[0] = seqb[1] = seqb[2] = seqb[3] = 0;
	seqb[4] = s >> 24;
	seqb[5] = s >> 16;
	seqb[6] = s >> 8;
	seqb[7] = s;
}

static void mac_key(__xdata const uint8_t *key)
{
	uint8_t i;

	for (i = 0; i < 32; i++)
		polykey[i] = 0;
	ssh_chacha_xor(key, seqb, 0, polykey, 32);
	poly1305_init(polykey);
}

static __xdata uint8_t * __xdata wp;
static __xdata uint16_t wleft;

static uint16_t pkt_size(uint16_t plen, uint8_t flags)
{
	static __xdata uint8_t pad;

	if (flags & F_RAW)
		return plen;
	if (flags & F_PLAIN) {
		pad = 8 - ((5 + plen) & 7);
		if (pad < 4)
			pad += 8;
		return 5 + plen + pad;
	}
	pad = 8 - ((1 + plen) & 7);
	if (pad < 4)
		pad += 8;
	return 5 + plen + pad + 16;
}

static __xdata const uint8_t * __xdata pk_src;
static __xdata uint16_t pk_len;
static __xdata uint8_t pk_flags;
static __xdata uint8_t pk_pre[9];
static __xdata uint8_t pk_prelen;

static void write_packet(void) __reentrant
{
	static __xdata uint16_t total, body, i;
	static __xdata uint8_t pad;
	static __xdata uint8_t * __xdata start;

	total = pkt_size(pk_prelen + pk_len, pk_flags);
	start = wp;
	if (pk_flags & F_RAW) {
		for (i = 0; i < pk_len; i++)
			*wp++ = pk_src[i];
		wleft -= total;
		return;
	}
	body = total - 4 - ((pk_flags & F_PLAIN) ? 0 : 16);
	pad = body - 1 - pk_prelen - pk_len;
	wp[0] = 0;
	wp[1] = 0;
	wp[2] = body >> 8;
	wp[3] = body;
	wp[4] = pad;
	wp += 5;
	for (i = 0; i < pk_prelen; i++)
		*wp++ = pk_pre[i];
	for (i = 0; i < pk_len; i++)
		*wp++ = pk_src[i];
	for (i = 0; i < pad; i++)
		*wp++ = 0;
	if (!(pk_flags & F_PLAIN)) {
		if (tx_seq >= 0xffffffffUL - fl_pkts) {
			reject();
			return;
		}
		seq_bytes(tx_seq + fl_pkts);
		ssh_chacha_xor(key_s2c + 32, seqb, 0, start, 4);
		ssh_chacha_xor(key_s2c, seqb, 1, start + 4, body);
		mac_key(key_s2c);
		poly1305_update(start, 4 + body);
		poly1305_final(wp);
		wp += 16;
	}
	fl_pkts++;
	wleft -= total;
}

static __xdata uint8_t cbuf[LOCAL_MAXPKT];

uint16_t ssh_output(__xdata uint8_t *out, uint16_t max, uint8_t rexmit) __reentrant
{
	static __xdata uint16_t qpos, n, lim_q, lim_src, take, room, i, j;

	if (closing && !txq_len)
		return 0;
	if (fl_on && !rexmit)
		return 0;
	lim_q = rexmit ? fl_q : 0xffff;
	lim_src = rexmit ? fl_src : 0xffff;
	wp = out;
	wleft = max;
	fl_pkts = 0;
	qpos = 0;
	while (qpos < txq_len && qpos < lim_q) {
		n = ((uint16_t)txq[qpos] << 8) | txq[qpos + 1];
		pk_flags = txq[qpos + 2];
		if (pkt_size(n, pk_flags) > wleft)
			break;
		pk_src = txq + qpos + 3;
		pk_len = n;
		pk_prelen = 0;
		write_packet();
		if (closing && !txq_len)
			return 0;
		qpos += n + 3;
	}
	take = 0;
	if (qpos == txq_len && chan_open && src_pos < src_len) {
		room = wleft > 64 ? wleft - 64 : 0;
		if (room > sizeof(cbuf))
			room = sizeof(cbuf);
		if (room > remote_window)
			room = remote_window;
		if (room > remote_maxpkt)
			room = remote_maxpkt;
		j = 0;
		while (take < src_len - src_pos && take < lim_src) {
			if (pty && ssh_port_out[src_pos + take] == '\n') {
				if (j + 2 > room)
					break;
				cbuf[j++] = '\r';
			} else if (j + 1 > room) {
				break;
			}
			cbuf[j++] = ssh_port_out[src_pos + take];
			take++;
		}
		if (j) {
			pk_pre[0] = 94;
			pk_pre[1] = chan_peer >> 24;
			pk_pre[2] = chan_peer >> 16;
			pk_pre[3] = chan_peer >> 8;
			pk_pre[4] = chan_peer;
			pk_pre[5] = 0;
			pk_pre[6] = 0;
			pk_pre[7] = j >> 8;
			pk_pre[8] = j;
			pk_prelen = 9;
			pk_src = cbuf;
			pk_len = j;
			pk_flags = 0;
			write_packet();
			if (closing && !txq_len)
				return 0;
		}
		i = j;
	} else {
		i = 0;
	}
	if (!rexmit) {
		fl_q = qpos;
		fl_src = take;
		fl_win = i;
		fl_on = wp != out;
	}
	return wp - out;
}

uint8_t ssh_inflight(void)
{
	return fl_on;
}

uint8_t ssh_closing(void)
{
	return closing && !fl_on && !txq_len;
}

static void q_chan_data_c(__code const char *s)
{
	if (clen(s) > remote_window || !q_room(20 + clen(s)))
		return;
	q_begin(0);
	put_byte(94);
	put_u32(chan_peer);
	put_cstr(s);
	q_end();
	remote_window -= clen(s);
}

static void q_chan_data_x(__xdata const uint8_t *p, uint8_t n) __reentrant
{
	if (n > remote_window || !q_room(20 + n))
		return;
	q_begin(0);
	put_byte(94);
	put_u32(chan_peer);
	put_str(p, n);
	q_end();
	remote_window -= n;
}

static void q_chan_close(void)
{
	if (!q_room(40))
		return;
	q_begin(0);
	put_byte(98);
	put_u32(chan_peer);
	put_cstr(n_exitstatus);
	put_byte(0);
	put_u32(0);
	q_end();
	q_begin(0);
	put_byte(96);
	put_u32(chan_peer);
	q_end();
	q_begin(0);
	put_byte(97);
	put_u32(chan_peer);
	q_end();
	chan_open = 0;
	close_sent = 1;
}

void ssh_acked(void)
{
	static __xdata uint16_t i;

	if (!fl_on)
		return;
	for (i = fl_q; i < txq_len; i++)
		txq[i - fl_q] = txq[i];
	txq_len -= fl_q;
	src_pos += fl_src;
	remote_window -= fl_win;
	tx_seq += fl_pkts;
	fl_on = 0;
	if (chan_open && src_len && src_pos >= src_len) {
		src_pos = src_len = 0;
		if (shell)
			q_chan_data_c(prompt);
		else if (exec_done)
			q_chan_close();
	}
}

void ssh_reset(void)
{
	rx_have = 0;
	rx_state = ST_VERSION;
	rx_seq = tx_seq = 0;
	txq_len = 0;
	fl_on = 0;
	kex_state = K_WAIT_KEXINIT;
	enc_on = 0;
	authed = closing = 0;
	service_ready = skip_guess = 0;
	chan_open = pty = shell = exec_done = close_sent = 0;
	line_len = 0;
	src_pos = src_len = 0;
	ssh_port_random(cookie, 16);
	q_begin(F_RAW);
	put_c(v_s);
	put_byte('\r');
	put_byte('\n');
	q_end();
	q_begin(F_PLAIN);
	put_kexinit();
	q_end();
}

static void derive(__xdata uint8_t *out, uint8_t letter) __reentrant
{
	emit_hash = 1;
	sha256_init();
	put_mpint(kk);
	put_x(hh, 32);
	if (letter) {
		put_byte(letter);
		put_x(sid, 32);
	} else {
		put_x(out - 32, 32);
	}
	sha256_final(out);
}

__xdata uint8_t ssh_kex_done;
__xdata uint8_t ssh_step;

void ssh_init(void)
{
	eph_ready = 0;
	eph_job = 0;
	ssh_active = 0;
	ssh_kex_done = 0;
	kex_state = K_DONE;
	closing = 1;
	ed_init();
}

void ssh_poll(void)
{
	ssh_active = eph_job || (kex_state >= K_SHARED && kex_state <= K_SIGN) || kex_state >= K_GOT_ECDH;
	ssh_step = eph_job ? 0xe0 : (kex_state << 4) | (kex_state == K_SIGN ? es_state : 0);
	if (eph_job) {
		if (x25519_step()) {
			uint8_t i;
			for (i = 0; i < 32; i++)
				q_s[i] = x25519_r[i];
			eph_job = 0;
			eph_ready = 1;
		}
		return;
	}
	if (!eph_ready && !(kex_state >= K_SHARED && kex_state <= K_SIGN) && kex_state < K_GOT_ECDH) {
		uint8_t i;
		ssh_port_random(eph, 32);
		for (i = 0; i < 32; i++) {
			x25519_k[i] = eph[i];
			x25519_u[i] = 0;
		}
		x25519_u[0] = 9;
		x25519_start();
		eph_job = 1;
		return;
	}
	if (kex_state == K_GOT_ECDH && eph_ready) {
		uint8_t i;
		emit_hash = 1;
		put_str(q_c, 32);
		put_str(q_s, 32);
		for (i = 0; i < 32; i++) {
			x25519_k[i] = eph[i];
			x25519_u[i] = q_c[i];
		}
		x25519_start();
		kex_state = K_SHARED;
		return;
	}
	if (kex_state == K_SHARED) {
		if (x25519_step()) {
			uint8_t i;
			for (i = 0; i < 32; i++) {
				kk[i] = x25519_r[i];
				eph[i] = 0;
			}
			eph_ready = 0;
			kex_state = K_HASH;
		}
		return;
	}
	if (kex_state == K_HASH) {
		uint8_t i;
		emit_hash = 1;
		put_mpint(kk);
		sha256_final(hh);
		if (!enc_on)
			for (i = 0; i < 32; i++)
				sid[i] = hh[i];
		kex_state = K_DC0;
		return;
	}
	if (kex_state == K_DC0) {
		derive(key_c2s, 'C');
		kex_state = K_DC1;
		return;
	}
	if (kex_state == K_DC1) {
		derive(key_c2s + 32, 0);
		kex_state = K_DD0;
		return;
	}
	if (kex_state == K_DD0) {
		derive(key_s2c, 'D');
		kex_state = K_DD1;
		return;
	}
	if (kex_state == K_DD1) {
		uint8_t i;
		derive(key_s2c + 32, 0);
		for (i = 0; i < 32; i++)
			kk[i] = 0;
		ed_sign_start(hh);
		kex_state = K_SIGN;
		return;
	}
	if (kex_state == K_SIGN) {
		if (ed_sign_step()) {
			q_begin(F_PLAIN);
			put_byte(31);
			put_hostkey();
			put_str(q_s, 32);
			put_u32(4 + 11 + 4 + 64);
			put_cstr(n_hostkey);
			put_str(ed_sig, 64);
			q_end();
			q_begin(F_PLAIN);
			put_byte(21);
			q_end();
			kex_state = K_WAIT_NEWKEYS;
			ssh_kex_done = 1;
		}
	}
}

/* All cursor failures are terminal. Check the full wire width before narrowing. */
static uint32_t read_u32(void)
{
 uint32_t v;
 v = rp[0];
 v = (v << 8) | rp[1];
 v = (v << 8) | rp[2];
 v = (v << 8) | rp[3];
 rp += 4; rlen -= 4; return v;
}
static uint32_t get_u32(void)
{
 if (closing || rlen < 4) { reject(); return 0; }
 return read_u32();
}
static uint8_t get_byte(void)
{
 if (closing || !rlen) { reject(); return 0; }
 rlen--; return *rp++;
}
static __xdata const uint8_t * __xdata sp;
static __xdata uint16_t slen;
static uint8_t get_str(void)
{
 static __xdata uint32_t wire_length;
 sp = rxbuf; slen = 0;
 wire_length = get_u32();
 if (closing || wire_length > rlen) { reject(); return 0; }
 slen = (uint16_t)wire_length; sp = rp; rp += slen; rlen -= slen; return 1;
}
static uint8_t parsed(void)
{
 if (closing || rlen) { reject(); return 0; }
 return 1;
}
static uint8_t get_bool(void)
{
 static __xdata uint8_t b;
 b = get_byte();
 if (b > 1) reject();
 return b;
}

static uint8_t str_is(__code const char *s)
{
	uint16_t i;

	for (i = 0; i < slen; i++)
		if (!s[i] || s[i] != sp[i])
			return 0;
	return !s[slen];
}

static void q_simple(uint8_t msg)
{
	q_begin(0);
	put_byte(msg);
	q_end();
}

static void q_chan_simple(uint8_t msg)
{
	q_begin(0);
	put_byte(msg);
	put_u32(chan_peer);
	q_end();
}

static void run_line(void)
{
	line[line_len] = 0;
	src_len = line_len ? ssh_port_exec(line) : 0;
	src_pos = 0;
	line_len = 0;
}

static void shell_input(void)
{
	static __xdata uint8_t c;

	while (slen--) {
		c = *sp++;
		if (src_len)
			continue;
		if (c == '\r' || c == '\n') {
			q_chan_data_c("\r\n");
			run_line();
			if (!src_len)
				q_chan_data_c(prompt);
		} else if (c == 0x7f || c == 8) {
			if (line_len) {
				line_len--;
				q_chan_data_c("\b \b");
			}
		} else if (c == 4 && !line_len) {
			q_chan_close();
			return;
		} else if (c == 3) {
			line_len = 0;
			q_chan_data_c("^C\r\n> ");
		} else if (c >= 0x20 && line_len < LINEMAX) {
			line[line_len++] = c;
			q_chan_data_x(&line[line_len - 1], 1);
		}
	}
}

static void handle_enc(uint8_t msg) __reentrant
{
 static __xdata uint8_t want, kind;
 static __xdata uint16_t i;
 static __xdata uint32_t n, window, maximum;
 if (!enc_on || kex_state != K_DONE) { reject(); return; }
 if (msg == 1) {
  get_u32(); get_str(); get_str(); parsed(); reject(); return;
 }
 if (msg == 2 || msg == 3 || msg == 4) {
  if (msg == 3) get_u32();
  else { if (msg == 4) get_bool(); get_str(); if (msg == 4) get_str(); }
  parsed(); return;
 }
 if (msg == 5) {
  get_str();
  if (!parsed() || !str_is(n_userauth) || service_ready) { reject(); return; }
  q_begin(0); put_byte(6); put_cstr(n_userauth); q_end();
  if (!closing) service_ready = 1;
  return;
 }
 if (msg == 50) {
  if (!service_ready || authed) { reject(); return; }
  get_str(); /* Account policy is unchanged; the username remains syntactically bounded. */
  get_str();
  if (closing || !str_is("ssh-connection")) { reject(); return; }
  get_str();
  if (closing) return;
  if (str_is(n_password)) {
   want = get_bool(); get_str();
   if (want) { get_str(); if (!parsed()) return; }
   else {
    if (!parsed()) return;
    if (slen < 64 && ssh_port_auth(sp, slen)) { authed = 1; q_simple(52); return; }
   }
  } else if (str_is(n_none)) { if (!parsed()) return; }
  /* Unsupported methods have method-specific opaque, already bounded tails. */
  q_begin(0); put_byte(51); put_cstr(n_password); put_byte(0); q_end(); return;
 }
 if (!authed) { reject(); return; }
 if (msg == 80) {
  get_str(); want = get_bool(); if (closing) return;
  if (want) q_simple(82); return;
 }
 if (msg == 90) {
  get_str(); kind = str_is(n_session);
  n = get_u32(); window = get_u32(); maximum = get_u32();
  if (closing || (kind && !parsed()) || !maximum) { reject(); return; }
  if (!kind || chan_open) {
   q_begin(0); put_byte(92); put_u32(n); put_u32(4); put_u32(0); put_u32(0); q_end(); return;
  }
  chan_peer = n; remote_window = window; remote_maxpkt = maximum;
  chan_open = 1; local_window = LOCAL_WINDOW;
  q_begin(0); put_byte(91); put_u32(chan_peer); put_u32(0);
  put_u32(LOCAL_WINDOW); put_u32(LOCAL_MAXPKT); q_end(); return;
 }
 if (msg == 93 || msg == 94 || msg == 96 || msg == 97 || msg == 98) {
  n = get_u32();
  if (closing || !chan_open || n != 0) { reject(); return; }
 }
 if (msg == 93) {
  n = get_u32();
  if (!parsed()) return;
  if (n > 0xffffffffUL - remote_window) { reject(); return; }
  remote_window += n; return;
 }
 if (msg == 94) {
  get_str(); if (!parsed()) return;
  if (slen > local_window || slen > LOCAL_MAXPKT) { reject(); return; }
  local_window -= slen;
  if (shell) shell_input();
  if (!closing && local_window < LOCAL_WINDOW / 2) {
   q_begin(0); put_byte(93); put_u32(chan_peer); put_u32(LOCAL_WINDOW-local_window); q_end();
   local_window = LOCAL_WINDOW;
  }
  return;
 }
 if (msg == 96) { parsed(); return; }
 if (msg == 97) {
  if (!parsed()) return;
  if (!close_sent) q_chan_close(); closing = 1; return;
 }
 if (msg == 98) {
  get_str(); want = get_bool(); if (closing) return;
  if (str_is(n_ptyreq)) {
   get_str(); get_u32(); get_u32(); get_u32(); get_u32(); get_str();
   if (!parsed()) return; pty = 1;
  } else if (str_is(n_shell)) {
   if (!parsed()) return; shell = 1;
  } else if (str_is(n_exec)) {
   get_str(); if (!parsed()) return;
   if (slen > LINEMAX) { reject(); return; }
   for (i=0; i<slen; i++) if (!sp[i]) { reject(); return; }
   for (line_len=0; line_len<slen; line_len++) line[line_len]=sp[line_len];
   run_line(); exec_done=1;
  } else { if (want) q_chan_simple(100); return; }
  if (want) q_chan_simple(99);
  if (shell) q_chan_data_c(banner);
  else if (exec_done && !src_len) q_chan_close();
  return;
 }
 q_begin(0); put_byte(3); put_u32(rx_seq-1); q_end();
}

static void handle_plain(void)
{
	static __xdata uint8_t i;

	if (rlen < 1) { reject(); return; }
	if (skip_guess) { skip_guess = 0; return; }
	if (rxbuf[5] == 30 && kex_state == K_WAIT_ECDH) {
		rp = rxbuf + 6;
		rlen--;
		if (!get_str() || slen != 32 || !parsed()) {
			closing = 1;
			return;
		}
		for (i = 0; i < 32; i++)
			q_c[i] = sp[i];
		kex_state = K_GOT_ECDH;
		return;
	}
	if (rxbuf[5] == 21 && rlen == 1 && kex_state == K_WAIT_NEWKEYS) {
		enc_on = 1;
		kex_state = K_DONE;
		return;
	}
	closing = 1;
}

static uint8_t open_enc(void)
{
	static __xdata uint16_t len;
	static __xdata uint8_t i, d;

	seq_bytes(rx_seq);
	len = rx_need - 20;
	mac_key(key_c2s);
	poly1305_update(rxbuf, 4 + len);
	poly1305_final(tag);
	d = 0;
	for (i = 0; i < 16; i++)
		d |= tag[i] ^ rxbuf[4 + len + i];
	if (d)
		return 0;
	ssh_chacha_xor(key_c2s, seqb, 1, rxbuf + 4, len);
	if (rxbuf[4] < 4 || (uint16_t)rxbuf[4] + 2 > len)
		return 0;
	rp = rxbuf + 6;
	rlen = len - rxbuf[4] - 2;
	return 1;
}

/* Validate KEXINIT incrementally without allocating another packet buffer.
 * The transcript still hashes the exact accepted wire payload, including names
 * that are not selected. Four-byte lengths are bounded before narrowing. */
static __xdata uint8_t ks_state, ks_field, ks_n, ks_match, ks_found, ks_first, ks_guess;
static __xdata uint16_t ks_left, ks_pos, ks_remaining;
static __xdata uint32_t ks_length;
static __code const char * __xdata ks_expected;
static void kex_start(uint16_t size)
{
 ks_state=0; ks_field=0; ks_n=0; ks_remaining=size; ks_guess=1;
}
static void kex_next(void)
{
 ks_field++; ks_n=0; ks_length=0;
 ks_state = ks_field == 10 ? 4 : 2;
}
static void kex_name_end(void)
{
 if (!ks_pos) { reject(); return; }
 if (ks_match && ks_expected && !ks_expected[ks_pos]) ks_found=1;
 else if (ks_first && ks_field < 2) ks_guess=0;
 ks_first=0; ks_pos=0; ks_match=1;
}
/* Leaf helper: private existing KEX state; never invoked from interrupts. */
static uint8_t kex_length_byte(uint8_t b)
{
 ks_length=(ks_length<<8)|b;
 return ks_length <= ks_remaining;
}
static void kex_byte(uint8_t b)
{
 if (!ks_remaining || ks_state == 6) { reject(); return; }
 ks_remaining--;
 if (ks_state == 0) {
  if (b != 20) { reject(); return; }
  ks_state=1; ks_n=16;
 } else if (ks_state == 1) {
  if (!--ks_n) { ks_state=2; ks_length=0; }
 } else if (ks_state == 2) {
  if (++ks_n != 4) { kex_length_byte(b); return; }
  if (!kex_length_byte(b)) { reject(); return; }
  if (ks_field == 0) ks_expected = n_kex;
  else if (ks_field == 1) ks_expected = n_hostkey;
  else if (ks_field < 4) ks_expected = n_cipher;
  else if (ks_field == 6 || ks_field == 7) ks_expected = n_none;
  else ks_expected = 0;
  ks_left=(uint16_t)ks_length; ks_pos=0; ks_match=1; ks_found=0; ks_first=1;
  if (!ks_left) {
   if (ks_expected) { reject(); return; }
   kex_next();
  } else ks_state=3;
 } else if (ks_state == 3) {
  if (b == ',') kex_name_end();
  else {
   if (b < 33 || b > 126) { reject(); return; }
   if (ks_expected && ks_match && ks_expected[ks_pos] != b) ks_match=0;
   ks_pos++;
  }
  if (closing) return;
  if (!--ks_left) {
   kex_name_end(); if (closing) return;
   if (ks_expected && !ks_found) { reject(); return; }
   kex_next();
  }
 } else if (ks_state == 4) {
  if (b > 1) { reject(); return; }
  skip_guess=b && !ks_guess; ks_n=4; ks_state=5;
 } else {
  if (b) { reject(); return; }
  if (!--ks_n) ks_state=6;
 }
}

void ssh_input(__xdata const uint8_t *p, uint16_t n) __reentrant
{
	static __xdata uint16_t k, plen, j;
	static __xdata uint32_t wire_length;
	static __xdata uint8_t c;

	while (n && !closing) {
		if (rx_state == ST_VERSION) {
			c = *p++;
			n--;
			if (c == '\n') {
				if (rx_have && rxbuf[rx_have - 1] == '\r')
					rx_have--;
                if (rx_have < 9 || rxbuf[0]!='S' || rxbuf[1]!='S' || rxbuf[2]!='H' || rxbuf[3]!='-' ||
                    !((rxbuf[4]=='2' && rxbuf[5]=='.' && rxbuf[6]=='0' && rxbuf[7]=='-') ||
                      (rx_have>=10 && rxbuf[4]=='1' && rxbuf[5]=='.' && rxbuf[6]=='9' && rxbuf[7]=='9' && rxbuf[8]=='-'))) {
                    reject(); return;
                }
                for (j=0; j<rx_have; j++) if (rxbuf[j]<32 || rxbuf[j]>126) { reject(); return; }
                emit_hash = 1;
                sha256_init();
				put_str(rxbuf, rx_have);
				put_u32(clen(v_s));
				put_c(v_s);
				rx_have = 0;
				rx_need = 5;
				rx_state = ST_HEADER;
			} else {
                if (rx_have >= VERSIONMAX+1 || (rx_have == VERSIONMAX && c != '\r')) { reject(); return; }
                rxbuf[rx_have++] = c;
            }
			continue;
		}
		if (rx_state == ST_ENC) {
            if (rx_need > RXMAX || rx_have >= rx_need) { reject(); return; }
			k = rx_need - rx_have;
			if (k > n)
				k = n;
			for (plen = 0; plen < k; plen++)
				rxbuf[rx_have++] = p[plen];
			p += k;
			n -= k;
			if (rx_have == 4 && rx_need == 4) {
				seq_bytes(rx_seq);
				for (c = 0; c < 4; c++)
					tmp4[c] = rxbuf[c];
				ssh_chacha_xor(key_c2s + 32, seqb, 0, tmp4, 4);
                wire_length=((uint32_t)tmp4[0]<<24)|((uint32_t)tmp4[1]<<16)|((uint16_t)tmp4[2]<<8)|tmp4[3];
                if (wire_length < 8 || wire_length > RXMAX-20 || (wire_length & 7)) { reject(); return; }
                rx_need=(uint16_t)wire_length + 20;
			} else if (rx_have == rx_need && rx_need > 4) {
				if (!open_enc() || rx_seq == 0xffffffffUL) {
					reject();
					return;
				}
				rx_seq++;
				handle_enc(rxbuf[5]);
				rx_have = 0;
				rx_need = 4;
			}
			continue;
		}
		if (rx_state == ST_HEADER) {
			rxbuf[rx_have++] = *p++;
			n--;
			if (rx_have < 5)
				continue;
            wire_length=((uint32_t)rxbuf[0]<<24)|((uint32_t)rxbuf[1]<<16)|((uint16_t)rxbuf[2]<<8)|rxbuf[3];
            if (wire_length < 12 || wire_length > (kex_state == K_WAIT_KEXINIT ? KEXMAX-4 : RXMAX-4) ||
                ((wire_length+4) & 7) || rxbuf[4] < 4 || wire_length < (uint16_t)rxbuf[4]+2) {
                reject(); return;
            }
            plen=(uint16_t)wire_length;
			rx_left = plen - 1;
			if (kex_state == K_WAIT_KEXINIT) {
				if (rx_left <= rxbuf[4]) {
					closing = 1;
					return;
				}
				emit_hash = 1;
				put_u32(rx_left - rxbuf[4]);
				rx_need = rx_left - rxbuf[4];
                kex_start(rx_need);
				rx_state = ST_KEXINIT;
			} else {
				if (plen > RXMAX - 4) {
					closing = 1;
					return;
				}
				rx_need = plen + 4;
				rx_state = ST_PLAIN;
			}
			continue;
		}
		if (rx_state == ST_KEXINIT) {
			k = rx_left;
			if (k > n)
				k = n;
			if (rx_need) {
				plen = k < rx_need ? k : rx_need;
				for (j=0; j<plen; j++) { kex_byte(p[j]); if (closing) return; }
                sha256_update(p, plen);
				rx_need -= plen;
			}
			p += k;
			n -= k;
			rx_left -= k;
			if (!rx_left) {
                if (ks_state != 6 || ks_remaining || rx_seq == 0xffffffffUL) { reject(); return; }
				emit_hash = 2;
				emit_count = 0;
				put_kexinit();
				emit_hash = 1;
				put_u32(emit_count);
				put_kexinit();
				put_hostkey();
				rx_seq++;
				kex_state = K_WAIT_ECDH;
				rx_have = 0;
				rx_state = ST_HEADER;
			}
			continue;
		}
		if (rx_state == ST_PLAIN) {
            if (rx_need > RXMAX || rx_have >= rx_need) { reject(); return; }
			rxbuf[rx_have++] = *p++;
			n--;
			if (rx_have < rx_need)
				continue;
			if (rx_seq == 0xffffffffUL) { reject(); return; }
			rx_seq++;
			rlen = rx_need - 5 - rxbuf[4];
			handle_plain();
			rx_have = 0;
			rx_state = enc_on ? ST_ENC : ST_HEADER;
			rx_need = enc_on ? 4 : 5;
		}
	}
}
