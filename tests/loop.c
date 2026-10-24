#include <unistd.h>
#include <stdio.h>
int main(void){ long s=0; for(long i=0;i<1000;i++) s+=i*i - (i>>1); printf("sum=%ld\n", s); return 0; }
