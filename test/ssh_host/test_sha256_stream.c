#include <stdio.h>
#include <stdlib.h>
#include "../../crypto/sha256.h"
int main(int argc,char **argv) {
 static unsigned char buf[4096],digest[32];size_t n;unsigned chunk=argc>1?strtoul(argv[1],0,10):4096;
 if(!chunk||chunk>sizeof buf)return 2;
 sha256_init();while((n=fread(buf,1,chunk,stdin)))sha256_update(buf,n);
 sha256_final(digest);for(unsigned i=0;i<32;i++)printf("%02x",digest[i]);puts("");return 0;
}
