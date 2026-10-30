/* Offline fixtures use synthetic session keys and credentials only. */
#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#ifndef SSH_SOURCE
#define SSH_SOURCE "../../ssh/ssh.c"
#endif
#include SSH_SOURCE
#define main fixture_server_main
#define ssh_port_auth fixture_auth
#define ssh_port_exec fixture_exec
#include "ssh_host.c"
#undef main
#undef ssh_port_auth
#undef ssh_port_exec
static unsigned auth_calls, exec_calls;
uint8_t ssh_port_auth(const uint8_t *p, uint8_t n) { auth_calls++; return fixture_auth(p,n); }
uint16_t ssh_port_exec(uint8_t *p) { exec_calls++; return fixture_exec(p); }
static unsigned checks;
#define CHECK(x) do { checks++; if (!(x)) { fprintf(stderr,"FAIL line %d: %s\n",__LINE__,#x); abort(); } } while(0)
static void fresh(int state) {
 closing=authed=chan_open=shell=pty=exec_done=close_sent=0;
 rx_have=txq_len=src_len=src_pos=fl_on=fl_pkts=0; rx_seq=tx_seq=0;
 emit_hash=0; rx_state=state; rx_need=state==ST_ENC?4:5;
 enc_on=state==ST_ENC; kex_state=enc_on?K_DONE:K_WAIT_ECDH;
 remote_window=4096; local_window=4096; remote_maxpkt=256;
 memset(key_c2s,0,64); memset(key_s2c,0,64); auth_calls=exec_calls=0;
#ifndef BASELINE
 service_ready=skip_guess=0;
#endif
}
static uint8_t payload[4096], wire[8192];
static size_t used;
static void byte(uint8_t b) { payload[used++]=b; }
static void u32(uint32_t n) { byte(n>>24); byte(n>>16); byte(n>>8); byte(n); }
static void str(const char *s) { size_t n=strlen(s); u32(n); memcpy(payload+used,s,n); used+=n; }
static size_t frame(int encrypted) {
 size_t pad=8-((used+1+(encrypted?0:4))&7); if(pad<4)pad+=8;
 size_t body=used+1+pad; wire[0]=body>>24;wire[1]=body>>16;wire[2]=body>>8;wire[3]=body;
 wire[4]=pad; memcpy(wire+5,payload,used); memset(wire+5+used,0,pad);
 if(encrypted) {
  seq_bytes(rx_seq); ssh_chacha_xor(key_c2s+32,seqb,0,wire,4);
  ssh_chacha_xor(key_c2s,seqb,1,wire+4,body); mac_key(key_c2s);
  poly1305_update(wire,body+4); poly1305_final(wire+body+4);
 }
 return body+4+(encrypted?16:0);
}
static void feed(size_t n,size_t chunk) {
 for(size_t i=0;i<n;i+=chunk) ssh_input(wire+i,n-i<chunk?n-i:chunk);
}
static void send_payload(void) { size_t n=frame(1); feed(n,3); }
static void service(void) { used=0; byte(5);str("ssh-userauth");send_payload(); }
static void login_payload(void) {
 used=0;byte(50);str("test");str("ssh-connection");str("password");byte(0);str("test");
}
static void kex_payload(void) {
 used=0;byte(20);for(int i=0;i<16;i++)byte(i);
 str("curve25519-sha256");str("ssh-ed25519");
 str("chacha20-poly1305@openssh.com");str("chacha20-poly1305@openssh.com");
 str("hmac-sha2-256");str("hmac-sha2-256");str("none");str("none");str("");str("");byte(0);u32(0);
}
static void ecdh_payload(void) { used=0;byte(30);u32(32);for(int i=0;i<32;i++)byte(i+1); }
static void baseline_reproduce(const char *which) {
 fresh(ST_ENC);
 if(!strcmp(which,"string")) {
  uint8_t b[]={0,1,0,1,42}; rp=b;rlen=sizeof b;
  CHECK(get_str()==1 && slen==1 && !closing);puts("REPRODUCED: 32-bit string length narrowed to 1");
 } else if(!strcmp(which,"boolean")) {
  login_payload(); used-=5; rp=payload+1;rlen=used-1;handle_enc(50);
  CHECK(!closing);puts("REPRODUCED: missing password boolean accepted without terminal rejection");
 } else if(!strcmp(which,"padding")) {
  fresh(ST_HEADER);ecdh_payload();size_t n=frame(0);wire[4]=0;feed(n,1);
  CHECK(kex_state==K_GOT_ECDH && !closing);puts("REPRODUCED: zero padding and trailing payload accepted");
 } else if(!strcmp(which,"queue")) {
  for(int i=0;i<100;i++){used=0;byte(5);str("ssh-userauth");rp=payload+1;rlen=used-1;handle_enc(5);}
  puts("queue reproduction did not trip sanitizer");exit(2);
 }
}
#ifndef BASELINE
static void regression(void) {
 /* All full-width framing boundaries, in both pre-auth framing states. */
 uint32_t lengths[]={0,1,7,8,11,12,507,508,509,512,65531,65532,65533,65534,65535,65536,0xffffffff};
 for(unsigned i=0;i<sizeof lengths/sizeof *lengths;i++) {
  fresh(ST_HEADER);uint32_t x=lengths[i];uint8_t h[]={x>>24,x>>16,x>>8,x,4};ssh_input(h,5);
  CHECK(closing == !(x>=12 && x<=508 && !((x+4)&7)));
 }
 for(int pad=0;pad<256;pad++) {
  fresh(ST_HEADER);uint8_t h[]={0,0,0,12,pad};ssh_input(h,5);
  CHECK(closing == !(pad>=4 && pad<=10));
 }
 for(unsigned n=0;n<4;n++){fresh(ST_ENC);rp=payload;rlen=n;get_u32();CHECK(closing);}
 for(unsigned i=0;i<sizeof lengths/sizeof *lengths;i++) {
  fresh(ST_ENC);used=0;u32(lengths[i]);byte(42);rp=payload;rlen=used;
  int ok=get_str();CHECK(ok==(lengths[i]<=1));CHECK(closing==(lengths[i]>1));
 }
 kex_payload();size_t n=frame(0);uint8_t saved[8192];memcpy(saved,wire,n);
 for(size_t split=1;split<n;split++) {
  fresh(ST_HEADER);kex_state=K_WAIT_KEXINIT;sha256_init();memcpy(wire,saved,n);
  ssh_input(wire,split);ssh_input(wire+split,n-split);
  CHECK(!closing && kex_state==K_WAIT_ECDH && rx_seq==1);
 }
 /* Corrupt every KEX byte; deterministic structure mutations must stay bounded. */
 for(size_t i=5;i<n;i++) {
  fresh(ST_HEADER);kex_state=K_WAIT_KEXINIT;sha256_init();memcpy(wire,saved,n);wire[i]^=255;feed(n,1);
  CHECK(rx_have<=RXMAX && txq_len<=TXQMAX);
 }
 fresh(ST_HEADER);kex_state=K_WAIT_KEXINIT;kex_payload();payload[0]=21;n=frame(0);feed(n,1);CHECK(closing);
 fresh(ST_HEADER);ecdh_payload();n=frame(0);feed(n,1);CHECK(!closing&&kex_state==K_GOT_ECDH);
 fresh(ST_HEADER);ecdh_payload();byte(0);n=frame(0);feed(n,n);CHECK(closing);
 fresh(ST_HEADER);kex_state=K_WAIT_NEWKEYS;used=0;byte(21);n=frame(0);feed(n,1);CHECK(enc_on&&!closing);
 fresh(ST_VERSION);const uint8_t ident[]="SSH-2.0-fixture\r\n";ssh_input(ident,sizeof ident-1);CHECK(!closing&&rx_state==ST_HEADER);
 fresh(ST_VERSION);const uint8_t bad[]="HTTP/1.0 test\r\n";ssh_input(bad,sizeof bad-1);CHECK(closing);
 fresh(ST_VERSION);memset(wire,'A',300);feed(300,1);CHECK(closing);
 /* A real encrypted packet: every split, bad tag, and truncation/EOF. */
 used=0;byte(5);str("ssh-userauth");fresh(ST_ENC);n=frame(1);memcpy(saved,wire,n);
 for(size_t split=1;split<n;split++) {
  fresh(ST_ENC);memcpy(wire,saved,n);ssh_input(wire,split);ssh_input(wire+split,n-split);
  CHECK(!closing&&service_ready&&rx_seq==1);
 }
 for(size_t i=0;i<n;i++) {
  fresh(ST_ENC);memcpy(wire,saved,n);wire[i]^=1;feed(n,1);ssh_input_eof();CHECK(closing&&!authed&&!auth_calls);
 }
 for(size_t i=0;i<n;i++){fresh(ST_ENC);memcpy(wire,saved,n);ssh_input(wire,i);ssh_input_eof();CHECK(closing&&!auth_calls);}
 /* Encrypted minimum/maximum lengths, before authenticated dispatch. */
 for(unsigned i=0;i<sizeof lengths/sizeof *lengths;i++) {
  fresh(ST_ENC);uint32_t x=lengths[i];wire[0]=x>>24;wire[1]=x>>16;wire[2]=x>>8;wire[3]=x;
  seq_bytes(0);ssh_chacha_xor(key_c2s+32,seqb,0,wire,4);ssh_input(wire,4);
  CHECK(closing==!(x>=8&&x<=492&&!(x&7)));
 }
 /* Complete authentication must be validated before invoking the password adapter. */
 fresh(ST_ENC);service();CHECK(!closing);login_payload();send_payload();CHECK(authed&&auth_calls==1);
 for(size_t cut=0;cut<50;cut++) {
  fresh(ST_ENC);service();login_payload();if(cut>=used)break;used=cut;
  if(!used){byte(50);}send_payload();CHECK(closing&&!auth_calls&&!authed);
 }
 fresh(ST_ENC);service();login_payload();byte(0);send_payload();CHECK(closing&&!auth_calls);
 fresh(ST_ENC);login_payload();send_payload();CHECK(closing&&!auth_calls);
 fresh(ST_ENC);service();service();CHECK(closing&&txq_len==0);
 fresh(ST_ENC);for(int i=0;i<1000;i++)q_simple(3);CHECK(closing&&txq_len==0);
 /* Multiple packets in one TCP delivery with sequence-dependent MACs. */
 fresh(ST_ENC);used=0;byte(2);str("one");n=frame(1);memcpy(saved,wire,n);
 rx_seq=1;used=0;byte(2);str("two");size_t m=frame(1);memcpy(saved+n,wire,m);rx_seq=0;
 ssh_input(saved,n+m);CHECK(!closing&&rx_seq==2);
 fresh(ST_ENC);authed=chan_open=1;remote_window=0xffffffffUL;used=0;byte(93);u32(0);u32(1);send_payload();CHECK(closing);
 fresh(ST_ENC);authed=chan_open=1;used=0;byte(94);u32(1);str("x");send_payload();CHECK(closing&&!exec_calls);
 fresh(ST_ENC);authed=chan_open=1;local_window=0;used=0;byte(94);u32(0);str("x");send_payload();CHECK(closing);
 fresh(ST_ENC);authed=chan_open=1;used=0;byte(98);u32(0);str("exec");byte(1);str("quiet");send_payload();CHECK(!closing&&exec_calls==1);
 fresh(ST_ENC);authed=chan_open=1;used=0;byte(98);u32(0);str("exec");byte(1);u32(3);byte('a');byte(0);byte('b');send_payload();CHECK(closing&&!exec_calls);
 fresh(ST_ENC);rx_seq=0xffffffffUL;used=0;byte(2);str("");send_payload();CHECK(closing&&rx_seq==0xffffffffUL);
 fresh(ST_ENC);reject();service();CHECK(closing&&!service_ready&&!txq_len&&!auth_calls);
 fresh(ST_ENC);service();CHECK(!closing&&service_ready);
 printf("PASS %u parser assertions\n",checks);
}
int LLVMFuzzerTestOneInput(const uint8_t *data,size_t size) {
 if(size<2||size>4096)return 0;
 unsigned mode=data[0]%5;size_t chunk=1+data[1]%31;data+=2;size-=2;
 fresh(mode==0?ST_VERSION:mode==1?ST_HEADER:ST_ENC);
 if(mode==1){kex_state=K_WAIT_KEXINIT;sha256_init();}
 if(mode>=2){
  service_ready=1;authed=mode>=3;chan_open=mode>=3;shell=mode==4;
  if(size>450)size=450;memcpy(payload,data,size);used=size;size=frame(1);
 }else memcpy(wire,data,size);
 feed(size,chunk);CHECK(rx_have<=RXMAX&&txq_len<=TXQMAX);
 if(closing){unsigned a=auth_calls,e=exec_calls;feed(size,chunk);CHECK(auth_calls==a&&exec_calls==e);}
 return 0;
}
#endif
#ifndef FUZZ
#ifndef PARSER_MAIN
#define PARSER_MAIN main
#endif
int PARSER_MAIN(int argc,char **argv) {
#ifdef BASELINE
 if(argc!=2)return 2;baseline_reproduce(argv[1]);
#else
 regression();uint32_t rng=0x5a202610;uint8_t data[1024];
 for(unsigned i=0;i<20000;i++) {
  for(unsigned j=0;j<sizeof data;j++){rng^=rng<<13;rng^=rng>>17;rng^=rng<<5;data[j]=rng;}
  LLVMFuzzerTestOneInput(data,2+rng%(sizeof data-1));
 }
 puts("PASS 20000 deterministic fuzz cases, seed 0x5a202610");
#endif
 return 0;
}
#endif
