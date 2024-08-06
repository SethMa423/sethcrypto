#include "random.h"
#include <stdlib.h>
#include "unistd.h"
/*#include <io.h>
#include <process.h>*/
#include <fcntl.h>
#include <time.h>
#include <string.h>

enum {
    N = 624,
    M = 397,
    R = 31,
    A = 0x9908B0DF,
    F = 1812433253,
    U = 11,
    S = 7,
    B = 0x9D2C5680,
    T = 15,
    C = 0xEFC60000,
    L = 18,
    MASK_LOWER = (1ull << R) - 1,
    MASK_UPPER = (1ull << R)
};

//Get the random (by meisen) seed, depend on systom random and systom time.
uint32_t my_seed(void){
   
   unsigned long seed;
   int fd = open("/dev/urandom", 0);
   if (fd < 0 || read(fd, &seed, sizeof(seed)) < 0) seed = time(0);
   if (fd >= 0) close(fd);
   srand((unsigned int)(seed+time(0)));
   return (uint32_t)rand();
}

/*uint32_t seed(void){

	unsigned long seed;

	seed = time(0);
	srand((unsigned int)(seed + time(0)));
	return (uint32_t)rand();
}*/

//Core meisen calculate
uint32_t rand32(void){
    
    int i = 0;
    uint32_t x, y, xA;
    uint32_t mt[N] = {0};
    
    mt[0] = my_seed();
    for(i = 1; i < N; i++ ){
        mt[i] = (F * (mt[i - 1] ^ (mt[i - 1] >> 30)) + i);
    }
    for(i = 0; i < N; i++ ){
        x = (mt[i] & MASK_UPPER) + (mt[(i + 1) % N] & MASK_LOWER);
        xA = x >> 1;
        if (x & 0x1) xA ^= A;
        mt[i] = mt[(i + M) % N] ^ xA;
    }
    y = mt[0];
    y ^= (y >> U);
    y ^= (y << S) & B;
    y ^= (y << T) & C;
    y ^= (y >> L);
    return y;
}

//Generate random by meisen
int my_random(OUT unsigned char * random,
            IN unsigned int len){
    
    if(random == NULL) return RANDOM_POINTER_NULL;
    if(len <= 0) return RANDOM_LEN_TOO_SMALL;
    if(len > (MAX_RANDOM_LEN * 4)) return RANDOM_LEN_TOO_BIG;
    
    int i = 0, n1 = len / 4, n2 = len % 4;
    uint32_t ran[MAX_RANDOM_LEN] = {0};
    if(n2 == 0) for( i = 0; i < n1; i ++) ran[i] = rand32();
    else for( i = 0; i < n1 + 1; i ++) ran[i] = rand32();
    memcpy(random, ran, len);
    return RANOM_SUCCESS;
}