#include <stdlib.h>
#include <string.h>
#include "des.h"

static const uint32_t bytebit[8] = {128,64,32,16,8,4,2,1};
static const uint32_t bigbyte[24] = {
    0x800000,0x400000,0x200000,0x100000,
    0x80000,0x40000,0x20000,0x10000,
    0x8000,0x4000,0x2000,0x1000,
    0x800,0x400,0x200,0x100,
    0x80,0x40,0x20,0x10,
    0x8,0x4,0x2,0x1};
static const uint8_t pc1[56] = {
    56,48,40,32,24,16, 8,0,57,49,41,33,25,17,9,1,58,50,42,34,26,18,10,2,59,51,43,35,
    62,54,46,38,30,22,14,6,61,53,45,37,29,21,13,5,60,52,44,36,28,20,12,4,27,19,11,3};
static const uint8_t totrot[16] = {1,2,4,6,8,10,12,14,15,17,19,21,23,25,27,28};
static const uint8_t pc2[48] = {
    13,16,10,23, 0, 4, 2,27,14, 5,20, 9,22,18,11, 3,25, 7,15, 6,26,19,12, 1,
    40,51,30,36,46,54,29,39,50,44,32,47,43,48,38,55,33,52,45,41,49,35,28,31};

static const uint32_t sp1[64] = {
    0x01010400,0x00000000,0x00010000,0x01010404,0x01010004,0x00010404,0x00000004,0x00010000,
    0x00000400,0x01010400,0x01010404,0x00000400,0x01000404,0x01010004,0x01000000,0x00000004,
    0x00000404,0x01000400,0x01000400,0x00010400,0x00010400,0x01010000,0x01010000,0x01000404,
    0x00010004,0x01000004,0x01000004,0x00010004,0x00000000,0x00000404,0x00010404,0x01000000,
    0x00010000,0x01010404,0x00000004,0x01010000,0x01010400,0x01000000,0x01000000,0x00000400,
    0x01010004,0x00010000,0x00010400,0x01000004,0x00000400,0x00000004,0x01000404,0x00010404,
    0x01010404,0x00010004,0x01010000,0x01000404,0x01000004,0x00000404,0x00010404,0x01010400,
    0x00000404,0x01000400,0x01000400,0x00000000,0x00010004,0x00010400,0x00000000,0x01010004};

static const uint32_t sp2[64] = {
    0x80108020,0x80008000,0x00008000,0x00108020,0x00100000,0x00000020,0x80100020,0x80008020,
    0x80000020,0x80108020,0x80108000,0x80000000,0x80008000,0x00100000,0x00000020,0x80100020,
    0x00108000,0x00100020,0x80008020,0x00000000,0x80000000,0x00008000,0x00108020,0x80100000,
    0x00100020,0x80000020,0x00000000,0x00108000,0x00008020,0x80108000,0x80100000,0x00008020,
    0x00000000,0x00108020,0x80100020,0x00100000,0x80008020,0x80100000,0x80108000,0x00008000,
    0x80100000,0x80008000,0x00000020,0x80108020,0x00108020,0x00000020,0x00008000,0x80000000,
    0x00008020,0x80108000,0x00100000,0x80000020,0x00100020,0x80008020,0x80000020,0x00100020,
    0x00108000,0x00000000,0x80008000,0x00008020,0x80000000,0x80100020,0x80108020,0x00108000};

static const uint32_t sp3[64] = {
    0x00000208,0x08020200,0x00000000,0x08020008,0x08000200,0x00000000,0x00020208,0x08000200,
    0x00020008,0x08000008,0x08000008,0x00020000,0x08020208,0x00020008,0x08020000,0x00000208,
    0x08000000,0x00000008,0x08020200,0x00000200,0x00020200,0x08020000,0x08020008,0x00020208,
    0x08000208,0x00020200,0x00020000,0x08000208,0x00000008,0x08020208,0x00000200,0x08000000,
    0x08020200,0x08000000,0x00020008,0x00000208,0x00020000,0x08020200,0x08000200,0x00000000,
    0x00000200,0x00020008,0x08020208,0x08000200,0x08000008,0x00000200,0x00000000,0x08020008,
    0x08000208,0x00020000,0x08000000,0x08020208,0x00000008,0x00020208,0x00020200,0x08000008,
    0x08020000,0x08000208,0x00000208,0x08020000,0x00020208,0x00000008,0x08020008,0x00020200};

static const uint32_t sp4[64] = {
    0x00802001,0x00002081,0x00002081,0x00000080,0x00802080,0x00800081,0x00800001,0x00002001,
    0x00000000,0x00802000,0x00802000,0x00802081,0x00000081,0x00000000,0x00800080,0x00800001,
    0x00000001,0x00002000,0x00800000,0x00802001,0x00000080,0x00800000,0x00002001,0x00002080,
    0x00800081,0x00000001,0x00002080,0x00800080,0x00002000,0x00802080,0x00802081,0x00000081,
    0x00800080,0x00800001,0x00802000,0x00802081,0x00000081,0x00000000,0x00000000,0x00802000,
    0x00002080,0x00800080,0x00800081,0x00000001,0x00802001,0x00002081,0x00002081,0x00000080,
    0x00802081,0x00000081,0x00000001,0x00002000,0x00800001,0x00002001,0x00802080,0x00800081,
    0x00002001,0x00002080,0x00800000,0x00802001,0x00000080,0x00800000,0x00002000,0x00802080};

static const uint32_t sp5[64] = {
    0x00000100,0x02080100,0x02080000,0x42000100,0x00080000,0x00000100,0x40000000,0x02080000,
    0x40080100,0x00080000,0x02000100,0x40080100,0x42000100,0x42080000,0x00080100,0x40000000,
    0x02000000,0x40080000,0x40080000,0x00000000,0x40000100,0x42080100,0x42080100,0x02000100,
    0x42080000,0x40000100,0x00000000,0x42000000,0x02080100,0x02000000,0x42000000,0x00080100,
    0x00080000,0x42000100,0x00000100,0x02000000,0x40000000,0x02080000,0x42000100,0x40080100,
    0x02000100,0x40000000,0x42080000,0x02080100,0x40080100,0x00000100,0x02000000,0x42080000,
    0x42080100,0x00080100,0x42000000,0x42080100,0x02080000,0x00000000,0x40080000,0x42000000,
    0x00080100,0x02000100,0x40000100,0x00080000,0x00000000,0x40080000,0x02080100,0x40000100};

static const uint32_t sp6[64] = {
    0x20000010,0x20400000,0x00004000,0x20404010,0x20400000,0x00000010,0x20404010,0x00400000,
    0x20004000,0x00404010,0x00400000,0x20000010,0x00400010,0x20004000,0x20000000,0x00004010,
    0x00000000,0x00400010,0x20004010,0x00004000,0x00404000,0x20004010,0x00000010,0x20400010,
    0x20400010,0x00000000,0x00404010,0x20404000,0x00004010,0x00404000,0x20404000,0x20000000,
    0x20004000,0x00000010,0x20400010,0x00404000,0x20404010,0x00400000,0x00004010,0x20000010,
    0x00400000,0x20004000,0x20000000,0x00004010,0x20000010,0x20404010,0x00404000,0x20400000,
    0x00404010,0x20404000,0x00000000,0x20400010,0x00000010,0x00004000,0x20400000,0x00404010,
    0x00004000,0x00400010,0x20004010,0x00000000,0x20404000,0x20000000,0x00400010,0x20004010};

static const uint32_t sp7[64] = {
    0x00200000,0x04200002,0x04000802,0x00000000,0x00000800,0x04000802,0x00200802,0x04200800,
    0x04200802,0x00200000,0x00000000,0x04000002,0x00000002,0x04000000,0x04200002,0x00000802,
    0x04000800,0x00200802,0x00200002,0x04000800,0x04000002,0x04200000,0x04200800,0x00200002,
    0x04200000,0x00000800,0x00000802,0x04200802,0x00200800,0x00000002,0x04000000,0x00200800,
    0x04000000,0x00200800,0x00200000,0x04000802,0x04000802,0x04200002,0x04200002,0x00000002,
    0x00200002,0x04000000,0x04000800,0x00200000,0x04200800,0x00000802,0x00200802,0x04200800,
    0x00000802,0x04000002,0x04200802,0x04200000,0x00200800,0x00000000,0x00000002,0x04200802,
    0x00000000,0x00200802,0x04200000,0x00000800,0x04000002,0x04000800,0x00000800,0x00200002};

static const uint32_t sp8[64] = {
    0x10001040,0x00001000,0x00040000,0x10041040,0x10000000,0x10001040,0x00000040,0x10000000,
    0x00040040,0x10040000,0x10041040,0x00041000,0x10041000,0x00041040,0x00001000,0x00000040,
    0x10040000,0x10000040,0x10001000,0x00001040,0x00041000,0x00040040,0x10040040,0x10041000,
    0x00001040,0x00000000,0x00000000,0x10040040,0x10000040,0x10001000,0x00041040,0x00040000,
    0x00041040,0x00040000,0x10041000,0x00001000,0x00000040,0x10040040,0x00001000,0x00041040,
    0x10001000,0x00000040,0x10000040,0x10040000,0x10040040,0x10000000,0x00040000,0x10001040,
    0x00000000,0x10041040,0x00040040,0x10000040,0x10040000,0x10001000,0x10001040,0x00000000,
    0x10041040,0x00041000,0x00041000,0x00001040,0x00001040,0x00040040,0x10000000,0x10041000};

#define GET(c)                   \
        (((uint32_t)(c)[0] << 24) ^ \
        ((uint32_t)(c)[1] << 16) ^  \
        ((uint32_t)(c)[2] <<  8) ^  \
        ((uint32_t)(c)[3]))

#define PUT(s,t)                     \
        (t)[0] = (uint8_t)((s) >> 24);  \
        (t)[1] = (uint8_t)((s) >> 16);  \
        (t)[2] = (uint8_t)((s) >>  8);  \
        (t)[3] = (uint8_t)(s)

#define SHL(x,n) (((x) & 0xFFFFFFFF) << n)
#define ROTL(x,n) (SHL((x),n) | ((x) >> (32 - n)))
#define SHR(x,n) (((x) & 0xFFFFFFFF) >> n)
#define ROTR(x,n) (SHR((x),n) | ((x) << (32 - n)))
#define DES_ENC_KEY  0
#define DES_DEC_KEY  1

void cookey(IN const uint32_t *raw1,
               OUT uint32_t *keyout){
    
    int i = 0;
    uint32_t *cook = NULL;
    const uint32_t *raw0 = NULL;
    uint32_t dough[32] = {0};
    
    cook = dough;
    for(i = 0; i < 16; i++,raw1++){
        raw0 = raw1++;
        *cook    = (*raw0 & 0x00fc0000) << 6;
        *cook   |= (*raw0 & 0x00000fc0) << 10;
        *cook   |= (*raw1 & 0x00fc0000) >> 10;
        *cook++ |= (*raw1 & 0x00000fc0) >> 6;
        *cook    = (*raw0 & 0x0003f000) << 12;
        *cook   |= (*raw0 & 0x0000003f) << 16;
        *cook   |= (*raw1 & 0x0003f000) >> 4;
        *cook++ |= (*raw1 & 0x0000003f);
    }
    memcpy(keyout, dough, sizeof(dough));
}

void get_des_key(IN const unsigned char *key,
                    IN int flag,
                    OUT uint32_t *keyout){
    
    uint32_t i = 0,j = 0,l = 0,m = 0,n = 0,kn[32] = {0};
    unsigned char pc1m[56] = {0}, pcr[56] = {0};
    
    for(j = 0; j < 56; j++){
        l = (unsigned int)pc1[j];
        m = l & 7;
        pc1m[j] = (unsigned char)((key[l >> 3] & bytebit[m]) == bytebit[m] ? 1 : 0);
    }
    for(i = 0; i < 16; i++){
        if(flag == DES_DEC_KEY) m = (15 - i) << 1;
        else m = i << 1;
        n = m + 1;
        kn[m] = kn[n] = 0;
        for(j = 0; j < 28; j++){
            l = j + (unsigned int)totrot[i];
            if(l < 28) pcr[j] = pc1m[l];
            else pcr[j] = pc1m[l - 28];
        }
        for(j = 28; j < 56; j++){
            l = j + (unsigned int)totrot[i];
            if(l < 56) pcr[j] = pc1m[l];
            else pcr[j] = pc1m[l - 28];
        }
        for(j = 0; j < 24; j++){
            if((int)pcr[(int)pc2[j]] != 0) kn[m] |= bigbyte[j];
            if((int)pcr[(int)pc2[j+24]] != 0) kn[n] |= bigbyte[j];
        }
    }
    cookey(kn, keyout);
}

//Get DES key
void des_key(IN const unsigned char *key,
                OUT uint32_t *ek,
                OUT uint32_t *dk){
    get_des_key(key, DES_ENC_KEY, ek);
    get_des_key(key, DES_DEC_KEY, dk);
}

//Get 3DES key
void des3_key(IN const unsigned char *key,
                 OUT uint32_t *ek,
                 OUT uint32_t *dk){
    get_des_key(key,DES_ENC_KEY,ek);
    get_des_key(key+8,DES_DEC_KEY,ek+32);
    get_des_key(key+16,DES_ENC_KEY,ek+64);
    get_des_key(key,DES_DEC_KEY,dk);
    get_des_key(key+8,DES_ENC_KEY,dk+32);
    get_des_key(key+16,DES_DEC_KEY,dk+64);
}

//DES single group
static void des_process(IN uint32_t *block,
                           IN const uint32_t *key){
    
    uint32_t work = 0,right = 0,leftt = 0;
    int cur_round = 0;
    
    leftt = block[0]; right = block[1];
    work = ((leftt >> 4)  ^ right) & 0x0f0f0f0f;
    right ^= work; leftt ^= (work << 4);
    work = ((leftt >> 16) ^ right) & 0x0000ffff;
    right ^= work; leftt ^= (work << 16);
    work = ((right >> 2)  ^ leftt) & 0x33333333;
    leftt ^= work; right ^= (work << 2);
    work = ((right >> 8)  ^ leftt) & 0x00ff00ff;
    leftt ^= work; right ^= (work << 8);
    right = ROTL(right, 1);
    work = (leftt ^ right) & 0xaaaaaaaa;
    leftt ^= work; right ^= work;
    leftt = ROTL(leftt, 1);
    
    for(cur_round = 0; cur_round < 8; cur_round++){
        work = ROTR(right,4) ^ *key++;
        leftt ^= sp7[work&0x3f] ^ sp5[(work>>8)&0x3f] ^ sp3[(work>>16)&0x3f] ^ sp1[(work>>24)&0x3f];
        work = right ^ *key++;
        leftt ^= sp8[work&0x3f] ^ sp6[(work>>8)&0x3f] ^ sp4[(work>>16)&0x3f] ^ sp2[(work>>24)&0x3f];
        work = ROTR(leftt,4) ^ *key++;
        right ^= sp7[work&0x3f] ^ sp5[(work>>8)&0x3f] ^ sp3[(work>>16)&0x3f] ^ sp1[(work>>24)&0x3f];
        work  = leftt ^ *key++;
        right ^= sp8[work&0x3f] ^ sp6[(work>>8)&0x3f] ^ sp4[(work>>16)&0x3f] ^ sp2[(work>>24)&0x3f];
    }
    right = ROTR(right, 1);
    work = (leftt ^ right) & 0xaaaaaaaa;
    leftt ^= work; right ^= work;
    leftt = ROTR(leftt, 1);
    work = ((leftt >> 8) ^ right) & 0x00ff00ff;
    right ^= work; leftt ^= (work << 8);
    work = ((leftt >> 2) ^ right) & 0x33333333;
    right ^= work; leftt ^= (work << 2);
    work = ((right >> 16) ^ leftt) & 0x0000ffff;
    leftt ^= work; right ^= (work << 16);
    work = ((right >> 4) ^ leftt) & 0x0f0f0f0f;
    leftt ^= work; right ^= (work << 4);
    block[0] = right;
    block[1] = leftt;
}

//DES encrypt
void des_enc(IN const unsigned char *inData,
                OUT unsigned char *outData,
                IN const uint32_t *ek,
                IN int Nr){
    
    uint32_t work[2] = {0};
    work[0] = GET(inData);
    work[1] = GET(inData+4);
    des_process(work, ek);
    PUT(work[0],outData);
    PUT(work[1],outData+4);
}

//DES decrypt
void des_dec(IN const unsigned char *inData,
                OUT unsigned char *outData,
                IN const uint32_t *dk,
                IN int Nr){
    des_enc(inData, outData, dk, Nr);
}

//3DES encrypt
void des3_enc(IN const unsigned char *inData,
                 OUT unsigned char *outData,
                 IN const uint32_t *ek,
                 IN int Nr){
    
    uint32_t work[2] = {0};
    work[0] = GET(inData);
    work[1] = GET(inData+4);
    des_process(work,ek);
    des_process(work,ek+32);
    des_process(work,ek+64);
    PUT(work[0],outData);
    PUT(work[1],outData+4);
}

//3DES decrypt
void des3_dec(IN const unsigned char *inData,
                 OUT unsigned char *outData,
                 IN const uint32_t *dk,
                 IN int Nr){
    des3_enc(inData, outData, dk, Nr);
}
