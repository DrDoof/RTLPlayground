#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/socket.h>
#include <sys/select.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include "../../ssh/ssh.h"
#include "../../crypto/ed25519.h"

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

void ssh_port_random(uint8_t *p, uint8_t n)
{
	int fd = open("/dev/urandom", O_RDONLY);
	if (read(fd, p, n) != n) exit(1);
	close(fd);
}

uint8_t ssh_port_auth(const uint8_t *pw, uint8_t len)
{
	return len == 4 && !memcmp(pw, "test", 4);
}

static uint8_t outbuf[2500];
uint8_t *ssh_port_out = outbuf;

uint16_t ssh_port_exec(uint8_t *line)
{
	if (!strcmp((char *)line, "big")) {
		int n = 0;
		for (int i = 0; n < 2400; i++)
			n += sprintf((char *)outbuf + n, "line %04d of a long output\n", i);
		return 2400;
	}
	if (!strcmp((char *)line, "quiet"))
		return 0;
	return sprintf((char *)outbuf, "ran: %s\nsecond line\n", line);
}

int main(int argc, char **argv)
{
	int port = argc > 1 ? atoi(argv[1]) : 2222;
	int mss = argc > 2 ? atoi(argv[2]) : 1460;
	int rxchunk = argc > 3 ? atoi(argv[3]) : mss;
	int ls = socket(AF_INET, SOCK_STREAM, 0), one = 1;
	setsockopt(ls, SOL_SOCKET, SO_REUSEADDR, &one, sizeof one);
	struct sockaddr_in a = { .sin_family = AF_INET, .sin_port = htons(port), .sin_addr.s_addr = htonl(INADDR_LOOPBACK) };
	if (bind(ls, (void *)&a, sizeof a) || listen(ls, 1)) { perror("bind"); return 1; }
	ssh_init();
	for (int i = 0; i < 400; i++) ssh_poll();
	fprintf(stderr, "listening on %d, mss %d\n", port, mss);
	for (;;) {
		int s = accept(ls, NULL, NULL);
		ssh_reset();
		long steps = 0, pkts = 0;
		for (;;) {
			uint8_t in[2048], o1[2048], o2[2048];
			fd_set rf; FD_ZERO(&rf); FD_SET(s, &rf);
			struct timeval tv = { 0, 1000 };
			if (select(s + 1, &rf, NULL, NULL, &tv) > 0) {
				ssize_t r = read(s, in, sizeof in);
				if (r <= 0) break;
				for (ssize_t off = 0; off < r; off += rxchunk) {
					uint16_t k = r - off < rxchunk ? r - off : rxchunk;
					ssh_input(in + off, k);
				}
			}
			ssh_poll();
			steps++;
			uint16_t n = ssh_output(o1, mss, 0);
			if (n) {
				uint16_t m = ssh_output(o2, mss, 1);
				if (m != n || memcmp(o1, o2, n)) { fprintf(stderr, "REXMIT MISMATCH %u %u\n", n, m); return 2; }
				if (write(s, o1, n) != n) break;
				ssh_acked();
				pkts++;
			}
			if (ssh_closing()) break;
		}
		fprintf(stderr, "session end: poll steps %ld, segments %ld\n", steps, pkts);
		close(s);
	}
}
