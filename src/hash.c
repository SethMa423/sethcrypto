#include <stdio.h>
#include <string.h>
#include "hash.h"

static const int endian_num = 1;

#define HASH_GROUP_SIZE  64
#define IS_LITTLE_ENDIAN (*(char *)&endian_num == 1)
#define CHANGE_ENDIAN_ORDER(v) ((ROTL(v,24)&0xFF00FF00)|(ROTL(v,8)&0x00FF00FF))
#define SHL(x,n) (((x) & 0xFFFFFFFF) << n)
#define ROTL(x,n) (SHL((x),n) | ((x) >> (32 - n)))
#define SHR(x,n) (((x) & 0xFFFFFFFF) >> n)
#define ROTR(x,n) (SHR((x),n) | ((x) << (32 - n)))
//SM3
#define FF0(x,y,z) ((x) ^ (y) ^ (z))
#define FF1(x,y,z) (((x) & (y)) | ((x) & (z)) | ((y) & (z)))
#define GG0(x,y,z) ((x) ^ (y) ^ (z))
#define GG1(x,y,z) (((x) & (y)) | ((~(x)) & (z)))
#define P0(x) ((x) ^  ROTL((x),9) ^ ROTL((x),17))
#define P1(x) ((x) ^  ROTL((x),15) ^ ROTL((x),23))
//SHA1
#define R(A,B,C,D,E) ROTL(A,5)+E+w[i]+(i<20?0x5A827999+((B&(C^D))^D):\
(i<40?0x6ED9EBA1+(B^C^D):(i<60?0x8F1BBCDC+(((B|C)&D)|(B&C)):0xCA62C1D6+(B^C^D))))
//SHA256
#define S0(x)  (ROTR((x), 2)^ROTR((x),13)^ROTR((x),22))
#define S1(x)  (ROTR((x), 6)^ROTR((x),11)^ROTR((x),25))
#define G0(x)  (ROTR((x), 7)^ROTR((x),18)^((x) >> 3))
#define G1(x)  (ROTR((x),17)^ROTR((x),19)^((x) >> 10))
#define CH(x,y,z) ((x&y)^(~(x)&z))
#define M(x,y,z) ((x&y)^(x&z)^(y&z))
static const uint32_t sha256_k[64] = {
     0x428a2f98,0x71374491,0xb5c0fbcf,0xe9b5dba5,0x3956c25b,0x59f111f1,0x923f82a4,0xab1c5ed5,
     0xd807aa98,0x12835b01,0x243185be,0x550c7dc3,0x72be5d74,0x80deb1fe,0x9bdc06a7,0xc19bf174,
     0xe49b69c1,0xefbe4786,0x0fc19dc6,0x240ca1cc,0x2de92c6f,0x4a7484aa,0x5cb0a9dc,0x76f988da,
     0x983e5152,0xa831c66d,0xb00327c8,0xbf597fc7,0xc6e00bf3,0xd5a79147,0x06ca6351,0x14292967,
     0x27b70a85,0x2e1b2138,0x4d2c6dfc,0x53380d13,0x650a7354,0x766a0abb,0x81c2c92e,0x92722c85,
     0xa2bfe8a1,0xa81a664b,0xc24b8b70,0xc76c51a3,0xd192e819,0xd6990624,0xf40e3585,0x106aa070,
     0x19a4c116,0x1e376c08,0x2748774c,0x34b0bcb5,0x391c0cb3,0x4ed8aa4a,0x5b9cca4f,0x682e6ff3,
     0x748f82ee,0x78a5636f,0x84c87814,0x8cc70208,0x90befffa,0xa4506ceb,0xbef9a3f7,0xc67178f2};
//MD5
#define P(a,b,c,d,k,s,t) {a += F(b,c,d) + X[k] + t; a = ROTL(a,s) + b;}
//MURMURHASH3
#define fmix32(h) {h^=h>>16;h*=0x85ebca6b;h^=h>>13;h*=0xc2b2ae35;h^=h>>16;}
#define fmix64(h) {h^=h>>33;h*=BIG_CONSTANT(0xff51afd7ed558ccd); \
                      h^=h>>33;h*=BIG_CONSTANT(0xc4ceb9fe1a85ec53);h^=h>>33;}
//for x86_128
static const uint32_t c1 = 0x239b961b; 
static const uint32_t c2 = 0xab0e9789;
static const uint32_t c3 = 0x38b34ae5; 
static const uint32_t c4 = 0xa1e38b93;
#define MURMURHASH32_SEED 1
#define MURMURHASH64_SEED 1

//Get little endian number. e.x: convert 0x12345678 to 0x78563412 on 
//little-end machine, finally would set the following char[4] to {12 34 56 78}
uint32_t get_big_endian(uint32_t group){
    if(IS_LITTLE_ENDIAN) return CHANGE_ENDIAN_ORDER(group);
    else return group;
}
//Get big endian number. e.x: convert 0x12345687 to 0x78563412 on 
//big-end machine, finally would set the following char[4] to {78 56 34 12}
uint32_t get_little_endian(uint32_t group){
    if(IS_LITTLE_ENDIAN) return group;
    else return CHANGE_ENDIAN_ORDER(group);
}

#include <stdio.h>
//Single group compress
static void sm3(IN uint32_t *ctx,
            OUT const unsigned char *group){
    
    int j = 0;
    uint32_t A = 0, B = 0, C = 0, D = 0, E = 0, F = 0, G = 0, H = 0;
    uint32_t SS1 = 0, SS2 = 0, TT1 = 0, TT2 = 0, W[68] = {0}, W1[64] = {0}, T[64] = {0};
    const uint32_t * group_temp = (const uint32_t *)group;
    
    //Message extern
    for(j = 0; j < 16; j++)
        W[j] = get_big_endian(group_temp[j]);
    for(j = 16; j < 68; j++)
        W[j] = P1(W[j-16] ^ W[j-9] ^ ROTL(W[j-3],15)) ^ ROTL(W[j - 13],7) ^ W[j-6];
    for(j = 0; j < 64; j++)
        W1[j] = W[j] ^ W[j+4];

    //Set initial value
    A = ctx[0]; B = ctx[1]; C = ctx[2]; D = ctx[3];
    E = ctx[4]; F = ctx[5]; G = ctx[6]; H = ctx[7];
    //Process
    for(j = 0; j < 64; j++){
        T[j] = ((j<16)?0x79CC4519:0x7A879D8A);
        SS1 = ROTL((ROTL(A,12) + E + ROTL(T[j],j%32)), 7);
        SS2 = SS1 ^ ROTL(A,12);
        TT1 = ((j<16)?FF0(A,B,C):FF1(A,B,C)) + D + SS2 + W1[j];
        TT2 = ((j<16)?GG0(E,F,G):GG1(E,F,G)) + H + SS1 + W[j];
        D = C;
        C = ROTL(B,9);
        B = A;
        A = TT1;
        H = G;
        G = ROTL(F,19);
        F = E;
        E = P0(TT2);
    }
    //Get process result
    ctx[0] ^= A; ctx[1] ^= B; ctx[2] ^= C; ctx[3] ^= D;
    ctx[4] ^= E; ctx[5] ^= F; ctx[6] ^= G; ctx[7] ^= H;
}

//Single group compress
static void sha1(IN uint32_t *ctx,
             OUT const unsigned char *group){
    
    int i = 0;
    uint32_t w[80] = {0};
    uint32_t a = 0, b = 0, c = 0, d = 0, e = 0, temp = 0;
    const uint32_t * group_temp = (const uint32_t *)group;
        
    //Message extern
    for(i = 0; i < 16; i++)
        w[i] = get_big_endian(group_temp[i]);
    for(i = 16; i < 80; i++)
        w[i] = ROTL(w[(i-3)]^w[(i-8)]^w[(i-14)]^w[i-16],1);
    //Set initial value
    a = ctx[0]; b = ctx[1]; c = ctx[2]; d = ctx[3]; e = ctx[4];
    //Process
    for(i = 0; i <= 79; i++){
        temp = R(a, b, c, d, e);
        e = d;
        d = c;
        c = ROTL(b,30);
        b = a;
        a = temp;
    }
    //Get process result
    ctx[0] += a; ctx[1] += b; ctx[2] += c; ctx[3] += d; ctx[4] += e;
}

//Single group compress
static void sha256(IN uint32_t *ctx,
               OUT const unsigned char *group){
    
    int i = 0;
    uint32_t w[64] = {0};
    uint32_t a = 0, b = 0, c = 0, d = 0, e = 0;
    uint32_t f = 0, g = 0, h = 0, t1 = 0, t2 = 0;
    const uint32_t * group_temp = (const uint32_t *)group;
        
    //Message extern
    for(i = 0; i < 16; i++)
        w[i] = get_big_endian(group_temp[i]);
    for(i = 16; i < 64; i++)
        w[i] = G1(w[i-2])+w[i-7]+G0(w[i-15])+w[i-16];
    //Set initial value
    a = ctx[0]; b = ctx[1]; c = ctx[2]; d = ctx[3];
    e = ctx[4]; f = ctx[5]; g = ctx[6]; h = ctx[7];
    //Process
    for(i = 0; i < 64; i++){
        t1 = h+S1(e)+CH(e,f,g)+sha256_k[i]+w[i];
        t2 = S0(a)+M(a,b,c);
        h = g;
        g = f;
        f = e;
        e = d+t1;
        d = c;
        c = b;
        b = a;
        a = t1+t2;
    }
    //Get process result
    ctx[0] += a; ctx[1] += b; ctx[2] += c; ctx[3] += d;
    ctx[4] += e; ctx[5] += f; ctx[6] += g; ctx[7] += h;
}

//Single group compress
static void md5(IN uint32_t *ctx,
            OUT const unsigned char *group){

    unsigned int X[16], A, B, C, D, i;
    const uint32_t * group_temp = (const uint32_t *)group;
    //Message extern
    for(i = 0; i < 16; i++)
        X[i] = get_little_endian(group_temp[i]);
    //Set initial value
    A = ctx[0]; B = ctx[1]; C = ctx[2]; D = ctx[3];
    //Process
    #define F(x,y,z) (z ^ (x & (y ^ z)))
    P( A, B, C, D,  0,  7, 0xD76AA478 ); P( D, A, B, C,  1, 12, 0xE8C7B756 );
    P( C, D, A, B,  2, 17, 0x242070DB ); P( B, C, D, A,  3, 22, 0xC1BDCEEE );
    P( A, B, C, D,  4,  7, 0xF57C0FAF ); P( D, A, B, C,  5, 12, 0x4787C62A );
    P( C, D, A, B,  6, 17, 0xA8304613 ); P( B, C, D, A,  7, 22, 0xFD469501 );
    P( A, B, C, D,  8,  7, 0x698098D8 ); P( D, A, B, C,  9, 12, 0x8B44F7AF );
    P( C, D, A, B, 10, 17, 0xFFFF5BB1 ); P( B, C, D, A, 11, 22, 0x895CD7BE );
    P( A, B, C, D, 12,  7, 0x6B901122 ); P( D, A, B, C, 13, 12, 0xFD987193 );
    P( C, D, A, B, 14, 17, 0xA679438E ); P( B, C, D, A, 15, 22, 0x49B40821 );
    #undef F
    #define F(x,y,z) (y ^ (z & (x ^ y)))
    P( A, B, C, D,  1,  5, 0xF61E2562 ); P( D, A, B, C,  6,  9, 0xC040B340 );
    P( C, D, A, B, 11, 14, 0x265E5A51 ); P( B, C, D, A,  0, 20, 0xE9B6C7AA );
    P( A, B, C, D,  5,  5, 0xD62F105D ); P( D, A, B, C, 10,  9, 0x02441453 );
    P( C, D, A, B, 15, 14, 0xD8A1E681 ); P( B, C, D, A,  4, 20, 0xE7D3FBC8 );
    P( A, B, C, D,  9,  5, 0x21E1CDE6 ); P( D, A, B, C, 14,  9, 0xC33707D6 );
    P( C, D, A, B,  3, 14, 0xF4D50D87 ); P( B, C, D, A,  8, 20, 0x455A14ED );
    P( A, B, C, D, 13,  5, 0xA9E3E905 ); P( D, A, B, C,  2,  9, 0xFCEFA3F8 );
    P( C, D, A, B,  7, 14, 0x676F02D9 ); P( B, C, D, A, 12, 20, 0x8D2A4C8A );
    #undef F
    #define F(x,y,z) (x ^ y ^ z)
    P( A, B, C, D,  5,  4, 0xFFFA3942 ); P( D, A, B, C,  8, 11, 0x8771F681 );
    P( C, D, A, B, 11, 16, 0x6D9D6122 ); P( B, C, D, A, 14, 23, 0xFDE5380C );
    P( A, B, C, D,  1,  4, 0xA4BEEA44 ); P( D, A, B, C,  4, 11, 0x4BDECFA9 );
    P( C, D, A, B,  7, 16, 0xF6BB4B60 ); P( B, C, D, A, 10, 23, 0xBEBFBC70 );
    P( A, B, C, D, 13,  4, 0x289B7EC6 ); P( D, A, B, C,  0, 11, 0xEAA127FA );
    P( C, D, A, B,  3, 16, 0xD4EF3085 ); P( B, C, D, A,  6, 23, 0x04881D05 );
    P( A, B, C, D,  9,  4, 0xD9D4D039 ); P( D, A, B, C, 12, 11, 0xE6DB99E5 );
    P( C, D, A, B, 15, 16, 0x1FA27CF8 ); P( B, C, D, A,  2, 23, 0xC4AC5665 );
    #undef F
    #define F(x,y,z) (y ^ (x | ~z))
    P( A, B, C, D,  0,  6, 0xF4292244 ); P( D, A, B, C,  7, 10, 0x432AFF97 );
    P( C, D, A, B, 14, 15, 0xAB9423A7 ); P( B, C, D, A,  5, 21, 0xFC93A039 );
    P( A, B, C, D, 12,  6, 0x655B59C3 ); P( D, A, B, C,  3, 10, 0x8F0CCC92 );
    P( C, D, A, B, 10, 15, 0xFFEFF47D ); P( B, C, D, A,  1, 21, 0x85845DD1 );
    P( A, B, C, D,  8,  6, 0x6FA87E4F ); P( D, A, B, C, 15, 10, 0xFE2CE6E0 );
    P( C, D, A, B,  6, 15, 0xA3014314 ); P( B, C, D, A, 13, 21, 0x4E0811A1 );
    P( A, B, C, D,  4,  6, 0xF7537E82 ); P( D, A, B, C, 11, 10, 0xBD3AF235 );
    P( C, D, A, B,  2, 15, 0x2AD7D2BB ); P( B, C, D, A,  9, 21, 0xEB86D391 );
    #undef F
    //Get initial value
    ctx[0] += A; ctx[1] += B; ctx[2] += C; ctx[3] += D;
}

//Single group compress
static void MurmurHash3_x86_128(IN uint32_t *ctx,
                                OUT const unsigned char *group){
    uint32_t X[4], k1, k2, k3, k4, i;
    //Message extern
    const uint32_t * group_temp = (const uint32_t *)group;
    for(i = 0; i < 4; i++)
        X[i] = get_big_endian(group_temp[i]);
    //Set initial value
    k1 = ctx[0]; k2 = ctx[1]; k3 = ctx[2]; k4 = ctx[3];
    //Process
    k1 *= c1;
    k1  = ROTL(k1,15);
    k1 *= c2;
    X[0] ^= k1;
    X[0] = ROTL(X[0],19);
    X[0] += X[1];
    X[0] = X[0]*5+0x561ccd1b;
    k2 *= c2;
    k2  = ROTL(k2,16);
    k2 *= c3;
    X[1] ^= k2;
    X[1] = ROTL(X[1],17);
    X[1] += X[2];
    X[1] = X[1]*5+0x0bcaa747;
    k3 *= c3;
    k3  = ROTL(k3,17);
    k3 *= c4;
    X[2] ^= k3;
    X[2] = ROTL(X[2],15);
    X[2] += X[3];
    X[2] = X[2]*5+0x96cd1c35;
    k4 *= c4;
    k4  = ROTL(k4,18);
    k4 *= c1;
    X[3] ^= k4;
    X[3] = ROTL(X[3],13);
    X[3] += X[0];
    X[3] = X[3]*5+0x32ac3b17;
    //Get initial value
    ctx[0] = X[0]; ctx[1] = X[1]; ctx[2] = X[2]; ctx[3] = X[3];
    return;
}

//Hash init
int hash_init(IN hash_context *ctx,
                 IN int algo){
    
    if(ctx == NULL) return HASH_INIT_CTX_NULL;
    ctx->group_num = 0;
    ctx->left_num = 0;
    //IV
    if(algo == SM3){
        ctx->digest[0] = 0x7380166F; ctx->digest[1] = 0x4914B2B9;
        ctx->digest[2] = 0x172442D7; ctx->digest[3] = 0xDA8A0600;
        ctx->digest[4] = 0xA96F30BC; ctx->digest[5] = 0x163138AA;
        ctx->digest[6] = 0xE38DEE4D; ctx->digest[7] = 0xB0FB0E4E;
        ctx->digestLen = 32;
        ctx->func = sm3;
    }else if(algo == SHA1){
        ctx->digest[0] = 0x67452301; ctx->digest[1] = 0xEFCDAB89;
        ctx->digest[2] = 0x98BADCFE; ctx->digest[3] = 0x10325476;
        ctx->digest[4] = 0xC3D2E1F0;
        ctx->digestLen = 20;
        ctx->func = sha1;
    }else if(algo == SHA256){
        ctx->digest[0] = 0x6a09e667; ctx->digest[1] = 0xbb67ae85;
        ctx->digest[2] = 0x3c6ef372; ctx->digest[3] = 0xa54ff53a;
        ctx->digest[4] = 0x510e527f; ctx->digest[5] = 0x9b05688c;
        ctx->digest[6] = 0x1f83d9ab; ctx->digest[7] = 0x5be0cd19;
        ctx->digestLen = 32;
        ctx->func = sha256;
    }else if(algo == MD5){
        ctx->digest[0] = 0x67452301;  ctx->digest[1] = 0xEFCDAB89;
        ctx->digest[2] = 0x98BADCFE;  ctx->digest[3] = 0x10325476;
        ctx->digestLen = 16;
        ctx->func = md5;
    }else if(algo == MURMURHASH3_x32_128){
        ctx->digest[0] = MURMURHASH32_SEED;
        ctx->digest[1] = MURMURHASH32_SEED;
        ctx->digest[2] = MURMURHASH32_SEED;
        ctx->digest[3] = MURMURHASH32_SEED;
        ctx->digestLen = 16;
        ctx->func = MurmurHash3_x86_128;
    }else{
        return HASH_ALGO_ERROR;
    }
    return HASH_SUCCESS;
}

//Hash update
int hash_update(IN hash_context *ctx,
                   IN const unsigned char *inData,
                   IN unsigned int dataLen){
    
    if(ctx == NULL) return HASH_UPDATE_CTX_NULL;
    if(inData == NULL) return HASH_UPDATE_INDATA_NULL;
    if(dataLen <= 0) return HASH_UPDATE_INDATA_LEN_ERROR;
    
    //Fill the group
    unsigned int fill_num = 0;
    if(ctx->left_num){
        fill_num = HASH_GROUP_SIZE - ctx->left_num;
        if(dataLen < fill_num){
            memcpy(ctx->current_group + ctx->left_num, inData, dataLen);
            ctx->left_num += dataLen;
            return HASH_SUCCESS;
        }else{
            memcpy(ctx->current_group + ctx->left_num, inData, fill_num);
            ctx->func(ctx->digest, ctx->current_group);
            ctx->group_num++;
            inData += fill_num;
            dataLen -= fill_num;
        }
    }
    //Compress the message
    while(dataLen >= HASH_GROUP_SIZE){
        ctx->func(ctx->digest, inData);
        ctx->group_num++;
        inData += HASH_GROUP_SIZE;
        dataLen -= HASH_GROUP_SIZE;
    }
    //Save the left message
    ctx->left_num = dataLen;
    if (dataLen) memcpy(ctx->current_group, inData, dataLen);
    return HASH_SUCCESS;
}

//Hash final
int hash_final(IN hash_context *ctx,
                  OUT unsigned char *hash,
                  OUT unsigned int *hashLen){
    
    if(ctx == NULL) return HASH_FINAL_CTX_NULL;
    if(hash == NULL) return HASH_FINAL_HASH_NULL;
    if(hashLen == NULL) return HASH_FINAL_HASH_LEN_NULL;
    
    int i = 0;
    uint32_t * pdigest = (uint32_t *)hash;
    uint32_t * count = (uint32_t *)(ctx->current_group + HASH_GROUP_SIZE - 8);
    
    //Fill '1' and '\0', 0x80 == 10000000(binary)
    ctx->current_group[ctx->left_num] = 0x80;
    if(ctx->left_num + 9 <= HASH_GROUP_SIZE){
        memset(ctx->current_group + ctx->left_num + 1, 0, HASH_GROUP_SIZE - ctx->left_num - 9);
    }else{
        memset(ctx->current_group + ctx->left_num + 1, 0, HASH_GROUP_SIZE - ctx->left_num - 1);
        ctx->func(ctx->digest, ctx->current_group);
        memset(ctx->current_group, 0, HASH_GROUP_SIZE - 8);
    }
    //Fill message length
    if (ctx->func == md5){
        count[1] = get_little_endian((ctx->group_num) >> 23);
        count[0] = get_little_endian((ctx->group_num << 9) + (ctx->left_num << 3));
    }else{
        count[0] = get_big_endian((ctx->group_num) >> 23);
        count[1] = get_big_endian((ctx->group_num << 9) + (ctx->left_num << 3));
    }
    //Get result
    ctx->func(ctx->digest, ctx->current_group);
    for(i = 0; i < ctx->digestLen/4; i++){
        if (ctx->func == md5)
            pdigest[i] = get_little_endian(ctx->digest[i]);
        else
            pdigest[i] = get_big_endian(ctx->digest[i]);
    }
    *hashLen = ctx->digestLen;
    return HASH_SUCCESS;
}

//Hash
int hash(IN int algo,
            IN const unsigned char *inData,
            IN unsigned int dataLen,
            OUT unsigned char *hash,
            OUT unsigned int *hashLen){
    
    int ret = HASH_SUCCESS;
    hash_context ctx;
    ret = hash_init(&ctx,algo);
    if(ret) return ret;
    ret = hash_update(&ctx,inData,dataLen);
    if(ret) return ret;
    ret = hash_final(&ctx,hash,hashLen);
    if(ret) return ret;
    memset(&ctx, 0, (size_t)sizeof(hash_context));
    return ret;
}
