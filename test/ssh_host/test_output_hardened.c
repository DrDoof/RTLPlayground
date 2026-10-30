/* Offline synthetic keys; production core included by parser fixture. */
#define PARSER_MAIN parser_regression_main
#include "test_parser.c"
#undef PARSER_MAIN
static uint8_t a[SSH_WIRE_MAX],b[SSH_WIRE_MAX];
static void output_source(void){ fresh(ST_ENC); authed=chan_open=1;src_len=64;src_pos=0;ssh_port_out=outbuf;memset(outbuf,'A',64); }
int main(void){
 unsigned n,m;
 output_source(); n=ssh_output(a,sizeof a,0);m=ssh_output(b,sizeof b,1);CHECK(n==m&&!memcmp(a,b,n));puts("PASS stable source retransmission control");
 memset(outbuf,'B',64);m=ssh_output(b,sizeof b,1);CHECK(n==m&&!memcmp(a,b,n));CHECK(tx_seq==0);puts("PASS immutable flight survives source mutation");
 output_source();memset(outbuf,'H',64);n=ssh_output(a,sizeof a,0);output_source();n=ssh_output(b,sizeof b,0);CHECK(memcmp(a,b,n));puts("CONTROL core source bytes affect unsent output; production source now private");
 output_source();outbuf[0]='\n';n=ssh_output(a,sizeof a,0);pty=1;m=ssh_output(b,sizeof b,1);CHECK(n==m&&!memcmp(a,b,n));puts("PASS immutable flight survives PTY-state mutation");
 output_source();n=ssh_output(a,sizeof a,0);used=0;byte(98);u32(0);str("exec");byte(0);str("second");send_payload();CHECK(exec_calls==0&&closing);puts("PASS repeated exec while source owned rejected");
 output_source();n=ssh_output(a,sizeof a,0);CHECK(fl_on);/* partial TCP ACK must not invoke ssh_acked; core has no byte-count API */m=ssh_output(b,sizeof b,1);CHECK(n==m&&!memcmp(a,b,n)&&fl_on);ssh_acked();CHECK(!fl_on&&src_pos==0&&src_len==0);CHECK(remote_window==4096-64);puts("PASS whole-ACK release; partial-ACK core contract retained");
 output_source();n=ssh_output(a,sizeof a,0);ssh_input_eof();CHECK(!fl_on&&!src_len&&!txq_len&&ssh_closing());puts("PASS EOF terminal output cleanup");
 fresh(ST_ENC);for(unsigned i=0;i<600&&!closing;i++)q_simple(2);CHECK(closing&&!txq_len&&!fl_on);puts("PASS bounded queue fail-closed");

 /* Actual parser transitions, not direct writes to shell/exec state. */
 fresh(ST_ENC);authed=chan_open=1;used=0;byte(98);u32(0);str("shell");byte(1);send_payload();CHECK(shell&&!closing);used=0;byte(98);u32(0);str("shell");byte(1);send_payload();CHECK(closing);puts("PASS second shell rejected");
 fresh(ST_ENC);authed=chan_open=1;used=0;byte(98);u32(0);str("exec");byte(1);str("quiet");send_payload();CHECK(exec_done&&!closing);used=0;byte(98);u32(0);str("exec");byte(1);str("quiet");send_payload();CHECK(closing&&exec_calls==1);puts("PASS second completed exec rejected");
 fresh(ST_ENC);authed=chan_open=shell=1;used=0;byte(98);u32(0);str("pty-req");byte(1);str("xterm");u32(80);u32(24);u32(0);u32(0);str("");send_payload();CHECK(closing&&!pty);puts("PASS late PTY rejected by actual parser");
 fresh(ST_ENC);for(unsigned j=0;j<100;j++)q_simple(2);n=ssh_output(a,sizeof a,0);CHECK(n<=sizeof a&&n>SSH_WIRE_MAX-64&&fl_on);m=ssh_output(b,sizeof b,1);CHECK(m==n&&!memcmp(a,b,n));puts("PASS bounded multi-packet flight");

 fresh(ST_ENC);service_ready=1;phase=2;phase_at=0;clock_tick=0;fragment_pending=stall_pending=0;
 for(unsigned j=1;j<12;j++){ssh_timeout(j*1000U);used=0;byte(50);str("test");str("ssh-connection");str("password");byte(0);str("wrong");send_payload();CHECK(!closing&&!authed);ssh_output(a,sizeof a,0);ssh_acked();}
 ssh_timeout(12000U);CHECK(closing&&!authed);puts("PASS failed-auth replies and ACKs do not extend absolute phase");
 printf("PASS %u assertions; ownership regression\n",checks);return 0;
}
