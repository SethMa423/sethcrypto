#include "sm1.h"

typedef          char   int8;
typedef   signed char   sint8;
typedef unsigned char   uint8;
typedef          short  int16;
typedef   signed short  sint16;
typedef unsigned short  uint16;
typedef          int    int32;
typedef   signed int    sint32;
typedef unsigned int    uint32;

// Partially defined types. They are used when the decompiler does not know
// anything about the type except its size.
#define _BYTE  uint8
#define _WORD  uint16
#define _DWORD uint32
// Some convenience macros to make partial accesses nicer
#define LAST_IND(x,part_type)    (sizeof(x)/sizeof(part_type) - 1)
#if defined(__BYTE_ORDER) && __BYTE_ORDER == __BIG_ENDIAN
#  define LOW_IND(x,part_type)   LAST_IND(x,part_type)
#  define HIGH_IND(x,part_type)  0
#else
#  define HIGH_IND(x,part_type)  LAST_IND(x,part_type)
#  define LOW_IND(x,part_type)   0
#endif
// first unsigned macros:
#define BYTEn(x, n)   (*((_BYTE*)&(x)+n))
#define WORDn(x, n)   (*((_WORD*)&(x)+n))
#define DWORDn(x, n)  (*((_DWORD*)&(x)+n))

// #define LOBYTE(x)  BYTEn(x,LOW_IND(x,_BYTE))
// #define LOWORD(x)  WORDn(x,LOW_IND(x,_WORD))
// #define LODWORD(x) DWORDn(x,LOW_IND(x,_DWORD))
// #define HIBYTE(x)  BYTEn(x,HIGH_IND(x,_BYTE))
// #define HIWORD(x)  WORDn(x,HIGH_IND(x,_WORD))
// #define HIDWORD(x) DWORDn(x,HIGH_IND(x,_DWORD))

#define LOBYTE(w)           ((_BYTE)(w))
#define HIBYTE(w)           ((_BYTE)(((_DWORD)(w) >> 24) & 0xFF))
#define LOWORD(d)           ((_WORD)(d))
#define HIWORD(d)           ((_WORD)((((_DWORD)(d)) >> 16) & 0xFFFF))

#define BYTE1(x)   BYTEn(x,  1)         // byte 1 (counting from 0)
#define BYTE2(x)   BYTEn(x,  2)

unsigned char GS1[16] = {0x5, 0xd, 0x9, 0x1, 0x0, 0x2, 0xa, 0xf, 0x6, 0x7, 0xc, 0x8, 0xe, 0x3, 0xb, 0x4};
unsigned char GS2[16] = {0x2, 0x4, 0xf, 0x6, 0x8, 0xb, 0xe, 0x5, 0xa, 0xd, 0x3, 0xc, 0x9, 0x7, 0x1, 0x0};
unsigned char GS3[16] = {0x4, 0x3, 0x5, 0xd, 0xf, 0x0, 0x8, 0x9, 0xb, 0x2, 0x6, 0xe, 0xa, 0x1, 0xc, 0x7};
unsigned char GS4[16] = {0xf, 0xe, 0x0, 0xa, 0x1, 0x7, 0x3, 0xd, 0x4, 0xc, 0x8, 0x5, 0xb, 0x9, 0x6, 0x2};
unsigned char GS5[16] = {0x4, 0xC, 0x8, 0x0, 0x1, 0x3, 0xB, 0xE, 0x7, 0x6, 0xD, 0x9, 0xF, 0x2, 0xa, 0x5};
unsigned char GS6[16] = {0x1, 0x7, 0xC, 0x5, 0xB, 0x8, 0xD, 0x6, 0x9, 0xE, 0x0, 0xF, 0xA, 0x4, 0x2, 0x3};
unsigned char GS7[16] = {0xD, 0xA, 0xC, 0x4, 0x6, 0x9, 0x1, 0x0, 0x2, 0xB, 0xF, 0x7, 0x3, 0x8, 0x5, 0xe};
unsigned char GS8[16] = {0x9, 0x8, 0x6, 0xC, 0x7, 0x1, 0x5, 0xB, 0x2, 0xA, 0xE, 0x3, 0xD, 0xF, 0x0, 0x4};

unsigned char nGS1[16] = {0x4, 0x3, 0x5, 0xD, 0xF, 0x0, 0x8, 0x9, 0xB, 0x2, 0x6, 0xE, 0xA, 0x1, 0xc, 0x7};
unsigned char nGS2[16] = {0xF, 0xE, 0x0, 0xA, 0x1, 0x7, 0x3, 0xD, 0x4, 0xC, 0x8, 0x5, 0xB, 0x9, 0x6, 0x2};
unsigned char nGS3[16] = {0x5, 0xD, 0x9, 0x1, 0x0, 0x2, 0xA, 0xF, 0x6, 0x7, 0xC, 0x8, 0xE, 0x3, 0xb, 0x4};
unsigned char nGS4[16] = {0x2, 0x4, 0xF, 0x6, 0x8, 0xB, 0xE, 0x5, 0xA, 0xD, 0x3, 0xC, 0x9, 0x7, 0x1, 0x0};
unsigned char nGS5[16] = {0x3, 0x4, 0xD, 0x5, 0x0, 0xF, 0x9, 0x8, 0x2, 0xB, 0xE, 0x6, 0x1, 0xA, 0x7, 0xc};
unsigned char nGS6[16] = {0xA, 0x0, 0xE, 0xF, 0xD, 0x3, 0x7, 0x1, 0x5, 0x8, 0xC, 0x4, 0x2, 0x6, 0x9, 0xb};
unsigned char nGS7[16] = {0x7, 0x6, 0x8, 0xC, 0x3, 0xE, 0x4, 0xB, 0xD, 0x5, 0x1, 0x9, 0x2, 0x0, 0xF, 0xa};
unsigned char nGS8[16] = {0xE, 0x5, 0x8, 0xB, 0xF, 0x6, 0x2, 0x4, 0x1, 0x0, 0x9, 0x7, 0x3, 0xC, 0xA, 0xd};

unsigned char S[256] = {
    0x0B1, 0x8, 0x19, 0x39, 0x51, 0x0E5, 0x23, 0x7D, 0x1, 0x46, 0x9C,
    0x13, 0x87, 0x0E7, 0x48, 0x67, 0x0C8, 0x0FD, 0x95, 0x0B, 0x3A,
    0x0C5, 0x7A, 0x2A, 0x6F, 0x2, 0x0F9, 0x3B, 0x64, 0x44, 0x0FF, 0x49,
    0x4E, 0x57, 0x78, 0x6, 0x2E, 0x0B6, 0x88, 0x0DA, 0x0B7, 0x8D, 0x17,
    0x0C3, 0x98, 0x4D, 0x24, 0x6B, 0x0F5, 0x0F7, 0x0CD, 0x4C, 0x60,
    0x8E, 0x81, 0x0FE, 0x0FA, 0x3, 0x14, 0x1B, 0x5E, 0x41, 0x99, 0x50,
    0x97, 0x3D, 0x5B, 0x0CF, 0x1D, 0x0AA, 0x9, 0x0CA, 0x0E, 0x1F, 0x0A7,
    0x0F4, 0x33, 0x2D, 0x20, 0x83, 0x3F, 0x4, 0x0F2, 0x0CE, 0x8B, 0x9B,
    0x0C4, 0x21, 0x0F1, 0x0A5, 0x84, 0x42, 0x0AF, 0x0C9, 0x3C, 0x79,
    0x34, 0x0BC, 0x7E, 0x0B5, 0x1C, 0x9F, 0x0D8, 0x0F, 0x0B9, 0x0E6,
    0x93, 0x2F, 0x0E4, 0x0EF, 0x70, 0x18, 0x6E, 0x0A2, 0x0BD, 0x91,
    0x0B3, 0x0EB, 0x0A4, 0x0ED, 0x22, 0x5F, 0x16, 0x0EA, 0x0A6, 0x7,
    0x62, 0x8F, 0x0B2, 0x36, 0x92, 0x4F, 0x5A, 0x0E1, 0x90, 0x0C,
    0x26, 0x0A0, 0x0B4, 0x54, 0x0D3, 0x29, 0x35, 0x7F, 0x86, 0x73,
    0x82, 0x6A, 0x0DD, 0x12, 0x0BB, 0x40, 0x2C, 0x3E, 0x0D9, 0x55,
    0x0A, 0x0AD, 0x0D5, 0x65, 0x89, 0x0E3, 0x71, 0x0DE, 0x76, 0x59,
    0x7C, 0x4A, 0x0E0, 0x0E8, 0x45, 0x0F6, 0x0AE, 0x9D, 0x0AC, 0x5C,
    0x0C0, 0x0, 0x80, 0x74, 0x8A, 0x63, 0x25, 0x28, 0x0BE, 0x68, 0x0D6,
    0x96, 0x61, 0x72, 0x0B8, 0x0EC, 0x0B0, 0x0CC, 0x0F3, 0x2B, 0x56,
    0x15, 0x0DB, 0x0F0, 0x10, 0x5D, 0x47, 0x0D1, 0x0C1, 0x32, 0x53,
    0x43, 0x0DC, 0x0CB, 0x0EE, 0x8C, 0x0E2, 0x9E, 0x0BA, 0x0DF, 0x66,
    0x9A, 0x27, 0x0C6, 0x0D0, 0x94, 0x0A3, 0x0D7, 0x0A8, 0x85, 0x0D4,
    0x0A1, 0x6C, 0x5, 0x69, 0x0D, 0x0A9, 0x0FC, 0x7B, 0x75, 0x0BF,
    0x77, 0x0D2, 0x6D, 0x0C7, 0x58, 0x52, 0x0C2, 0x4B, 0x30, 0x0AB,
    0x31, 0x0FB, 0x1A, 0x38, 0x0F8, 0x0E9, 0x11, 0x37, 0x1E
};

 
//  static inline unsigned int chm_rotr( unsigned int value, int shift )
//  {
//     return (value >> shift) | (value <<  (32-shift));
// }
#define chm_rotr(X,n)   ((((unsigned int)X) >> n) | (((unsigned int)X) << (32-n)))

void * GHfun(int *a1, int *a2, int *a3, int *a4)
{
  int s[4]; // [rsp+20h] [rbp-10h] BYREF

  s[3] = a1[2] ^ a1[1] ^ *a1 ^ a1[3];
  s[0] = a1[2] ^ *a1 ^ a1[3];
  s[1] = a1[1] ^ *a1 ^ a1[3];
  s[2] = a1[1] ^ *a1 ^ a1[2];
  s[0] ^= *a3;
  s[1] ^= a3[1];
  s[2] ^= a3[2];
  s[3] = (16 * GS7[LOBYTE(s[3]) >> 4]) | (GS6[((unsigned int)s[3] >> 8) & 0xF] << 8) | (GS5[LOWORD(s[3]) >> 12] << 12) | (GS4[HIWORD(s[3]) & 0xF] << 16) | (GS3[((unsigned int)s[3] >> 20) & 0xF] << 20) | (GS2[HIBYTE(s[3]) & 0xF] << 24) | (GS1[(unsigned int)s[3] >> 28] << 28) | GS8[s[3] & 0xF];
  s[0] = chm_rotr(s[0], 24) ^ chm_rotr(s[3], 15);
  s[1] = chm_rotr(s[1], 25) ^ chm_rotr(s[3], 7);
  s[2] = chm_rotr(s[2], 31) ^ chm_rotr(s[3], 23);
  s[3] = chm_rotr(s[3], 31);
  s[3] ^= a3[3];
  *a4 = s[3];
  a4[1] = s[0];
  a4[2] = s[1];
  a4[3] = s[2];
  return NULL;
}

void * GGfun(int *a1, int *a2, int *a3, int *a4)
{
  int s[4]; // [rsp+20h] [rbp-10h] BYREF

  s[3] = a1[2] ^ a1[1] ^ *a1 ^ a1[3];
  s[0] = a1[2] ^ *a1 ^ a1[3];
  s[1] = a1[1] ^ *a1 ^ a1[3];
  s[2] = a1[1] ^ *a1 ^ a1[2];
  s[0] ^= *a2;
  s[1] ^= a2[1];
  s[2] ^= a2[2];
  s[3] = (16 * GS7[LOBYTE(s[3]) >> 4]) | (GS6[((unsigned int)s[3] >> 8) & 0xF] << 8) | (GS5[LOWORD(s[3]) >> 12] << 12) | (GS4[HIWORD(s[3]) & 0xF] << 16) | (GS3[((unsigned int)s[3] >> 20) & 0xF] << 20) | (GS2[HIBYTE(s[3]) & 0xF] << 24) | (GS1[(unsigned int)s[3] >> 28] << 28) | GS8[s[3] & 0xF];
  s[0] = chm_rotr(s[0], 24) ^ chm_rotr(s[3], 15);
  s[1] = chm_rotr(s[1], 25) ^ chm_rotr(s[3], 7);
  s[2] = chm_rotr(s[2], 31) ^ chm_rotr(s[3], 23);
  s[3] = chm_rotr(s[3], 31);
  s[3] ^= a2[3];
  *a4 = s[3];
  a4[1] = s[0];
  a4[2] = s[1];
  a4[3] = s[2];
  return NULL;
}

void * reGHfun(int *a1, int *a2, int *a3, int *a4)
{
  int s[4]; // [rsp+20h] [rbp-10h] BYREF

  s[0] = a1[1];
  s[1] = a1[2];
  s[2] = a1[3];
  s[3] = *a1;
  s[3] ^= a3[3];
  s[3] = chm_rotr(s[3], 1);
  s[2] ^= chm_rotr(s[3], 23);
  s[2] = chm_rotr(s[2], 1);
  s[1] ^= chm_rotr(s[3], 7);
  s[1] = chm_rotr(s[1], 7);
  s[0] ^= chm_rotr(s[3], 15);
  s[0] = chm_rotr(s[0], 8);
  s[0] ^= *a3;
  s[1] ^= a3[1];
  s[2] ^= a3[2];
  s[3] = (16 * nGS7[LOBYTE(s[3]) >> 4]) | (nGS6[((unsigned int)s[3] >> 8) & 0xF] << 8) | (nGS5[LOWORD(s[3]) >> 12] << 12) | (nGS4[HIWORD(s[3]) & 0xF] << 16) | (nGS3[((unsigned int)s[3] >> 20) & 0xF] << 20) | (nGS2[HIBYTE(s[3]) & 0xF] << 24) | (nGS1[(unsigned int)s[3] >> 28] << 28) | nGS8[s[3] & 0xF];
  *a4 = s[2] ^ s[1] ^ s[0];
  a4[1] = s[0] ^ s[3];
  a4[2] = s[1] ^ s[3];
  a4[3] = s[2] ^ s[3];
  return NULL;
}

void * reGGfun(int *a1, int *a2, int *a3, int *a4)
{
  int s[4]; // [rsp+20h] [rbp-10h] BYREF

  s[0] = a1[1];
  s[1] = a1[2];
  s[2] = a1[3];
  s[3] = *a1;
  s[3] ^= a2[3];
  s[3] = chm_rotr(s[3], 1);
  s[2] ^= chm_rotr(s[3], 23);
  s[2] = chm_rotr(s[2], 1);
  s[1] ^= chm_rotr(s[3], 7);
  s[1] = chm_rotr(s[1], 7);
  s[0] ^= chm_rotr(s[3], 15);
  s[0] = chm_rotr(s[0], 8);
  s[0] ^= *a2;
  s[1] ^= a2[1];
  s[2] ^= a2[2];
  s[3] = (16 * nGS7[LOBYTE(s[3]) >> 4]) | (nGS6[((unsigned int)s[3] >> 8) & 0xF] << 8) | (nGS5[LOWORD(s[3]) >> 12] << 12) | (nGS4[HIWORD(s[3]) & 0xF] << 16) | (nGS3[((unsigned int)s[3] >> 20) & 0xF] << 20) | (nGS2[HIBYTE(s[3]) & 0xF] << 24) | (nGS1[(unsigned int)s[3] >> 28] << 28) | nGS8[s[3] & 0xF];
  *a4 = s[2] ^ s[1] ^ s[0];
  a4[1] = s[0] ^ s[3];
  a4[2] = s[1] ^ s[3];
  a4[3] = s[2] ^ s[3];
  return NULL;
}

int SCB2_extendkey(unsigned char *key, unsigned char *a2, unsigned char *a3, unsigned char *enc_key, unsigned char *dec_key, int len)
{
  int v10[4]; // [rsp+30h] [rbp-A0h] BYREF
  int v11[4]; // [rsp+40h] [rbp-90h] BYREF
  int v12[4]; // [rsp+50h] [rbp-80h] BYREF
  int v13[4]; // [rsp+60h] [rbp-70h] BYREF
  int v14[4]; // [rsp+70h] [rbp-60h] BYREF
  int s[4]; // [rsp+80h] [rbp-50h] BYREF
  int v16[4]; // [rsp+90h] [rbp-40h]
//  int v17[4]; // [rsp+A0h] [rbp-30h]
  int v18[6]; // [rsp+B0h] [rbp-20h]
  int j; // [rsp+C8h] [rbp-8h]
  int i; // [rsp+CCh] [rbp-4h]

  for (i = 0; i < 4; i++)
  {
    v18[i] = 0;
  //  v17[i] = 0;
    v16[i] = 0;
  }
  for ( i = 0; i <= 3; ++i )
  {
    for ( j = 0; j <= 3; ++j )
    {
      v18[i] <<= 8;
      v18[i] += key[4 * i + j];
      // v17[i] <<= 8;
      // a2 always is 0
      // v17[i] += a2[4 * i + j];
      v16[i] <<= 8;
      v16[i] += a3[4 * i + j];
    }
  }
  for ( i = 0; i <= 3; ++i ) {
    v11[i] = v16[i] ^ v18[i];
    // v10[i] = v18[i] ^ v17[i];
    // v17[i] always is 0
    v10[i] = v18[i] ^ 0;
  }
  v14[0] = v11[2] ^ v11[1] ^ v11[3];
  v14[1] = chm_rotr(v11[1] ^ v11[0] ^ v11[2], 24);
  v14[2] = chm_rotr(v11[1] ^ v11[0] ^ v11[3], 16);
  v14[3] = chm_rotr(v11[2] ^ v11[0] ^ v11[3], 9);
  v13[3] = v10[2] ^ v10[0] ^ v10[3];
  v13[0] = chm_rotr(v10[2] ^ v10[1] ^ v10[3], 24);
  v13[1] = chm_rotr(v10[1] ^ v10[0] ^ v10[2], 16);
  v13[2] = chm_rotr(v10[1] ^ v10[0] ^ v10[3], 8);
  for ( i = 0; i <= 3; ++i )
    s[i] = v14[i];
  for ( i = 0; 8 / 2 + 1 > i; ++i )
  {
    GHfun(s, v14, v13, v12);
    for ( j = 0; j <= 3; ++j ) {
      *(_DWORD *)&enc_key[16 * i + 4 * j] = v12[j];
      s[j] = v12[j];
    }
  }
  for ( i = 8 / 2 + 1; 8 + 1 > i; ++i )
  {
    reGHfun(s, v14, v13, v12);
    for ( j = 0; j <= 3; ++j ) {
      *(_DWORD *)&dec_key[16 * i + 4 * j] = v12[j];
      s[j] = v12[j];
    }
  }
  for ( i = 0; i <= 3; ++i )
    s[i] = v13[i];
  for ( i = 0; 8 / 2 + 1 > i; ++i )
  {
    reGGfun(s, v14, v13, v12);
    for ( j = 0; j <= 3; ++j ) {
      *(_DWORD *)&dec_key[16 * i + 4 * j] = v12[j];
      s[j] = v12[j];
    }
  }
  for ( j = 0; j <= 3; ++j )
    *(_DWORD *)&dec_key[16 * (8 / 2) + 4 * j] = *(_DWORD *)&enc_key[16 * (8 / 2) + 4 * j];
  for ( i = 8 / 2 + 1; 8 + 1 > i; ++i )
  {
    GGfun(s, v14, v13, v12);
    for ( j = 0; j <= 3; ++j ) {
      *(_DWORD *)&enc_key[16 * i + 4 * j] = v12[j];
      s[j] = v12[j];
    }
  }
  for ( i = 0; 8 + 1 > i; ++i )
  {
    *(_DWORD *)&dec_key[16 * i] = chm_rotr(*(_DWORD *)&dec_key[16 * i], 1);
    *(_DWORD *)&dec_key[16 * i + 4] = chm_rotr(*(_DWORD *)&dec_key[16 * i + 4], 9);
    *(_DWORD *)&dec_key[16 * i + 8] = chm_rotr(*(_DWORD *)&dec_key[16 * i + 8], 17);
    *(_DWORD *)&dec_key[16 * i + 12] = chm_rotr(*(_DWORD *)&dec_key[16 * i + 12], 25);
  }
  return 0;
}

int SCB2_encrypt(unsigned char *input, int in_len, unsigned char *output, int *out_len, unsigned char *enc_key, int len)
{
//  int v7[16]; // [rsp+30h] [rbp-B0h] BYREF
  int v8[4]; // [rsp+70h] [rbp-70h] BYREF
  int v9[4]; // [rsp+80h] [rbp-60h] BYREF
  int v10[4]; // [rsp+90h] [rbp-50h] BYREF
  int v11[4]; // [rsp+A0h] [rbp-40h] BYREF
  int s[4]; // [rsp+B0h] [rbp-30h] BYREF
  int v13; // [rsp+C8h] [rbp-18h]
  int v14; // [rsp+CCh] [rbp-14h]
  int i; // [rsp+D0h] [rbp-10h]
  int j; // [rsp+D4h] [rbp-Ch]
  int l; // [rsp+D8h] [rbp-8h]
  int k; // [rsp+DCh] [rbp-4h]

  v14 = in_len & 0xFFFFFFF0;
  v13 = in_len & 0xF;
  *out_len = (in_len + 15) & 0xFFFFFFF0;
  for ( i = 0; i < v14; i += 16 )
  {
    // for ( j = 0; j <= 3; ++j )
    //   v10[j] = 0;
    memset(v10, 0, 16);
    for ( j = 0; j <= 15; ++j )
      v10[j / 4] = input[i + j] | (v10[j / 4] << 8);
    v11[0] = chm_rotr(v10[0], 31);
    v11[1] = chm_rotr(v10[1], 23);
    v11[2] = chm_rotr(v10[2], 15);
    v11[3] = chm_rotr(v10[3], 7);
    for ( k = 0; k < 8; ++k )
    {
      s[0] = v11[0] ^ *(_DWORD *)&enc_key[16 * k];
      s[1] = v11[1] ^ *(_DWORD *)&enc_key[16 * k + 4];
      s[2] = v11[2] ^ *(_DWORD *)&enc_key[16 * k + 8];
      s[3] = v11[3] ^ *(_DWORD *)&enc_key[16 * k + 12];
      v11[0] = s[2] ^ s[1] ^ s[3];
      v11[1] = s[1] ^ s[0] ^ s[2];
      v11[2] = s[1] ^ s[0] ^ s[3];
      v11[3] = s[2] ^ s[0] ^ s[3];
      s[0] = (S[(unsigned short)(LOWORD(s[2]) ^ LOWORD(s[1]) ^ LOWORD(s[3])) >> 8] << 8) | (S[BYTE2(v11[0])] << 16) | (S[HIBYTE(v11[0])] << 24) | S[LOBYTE(s[2]) ^ LOBYTE(s[1]) ^ LOBYTE(s[3])];
      s[1] = (S[BYTE1(v11[1])] << 8) | (S[BYTE2(v11[1])] << 16) | (S[HIBYTE(v11[1])] << 24) | S[LOBYTE(v11[1])];
      s[2] = (S[BYTE1(v11[2])] << 8) | (S[BYTE2(v11[2])] << 16) | (S[HIBYTE(v11[2])] << 24) | S[LOBYTE(v11[2])];
      s[3] = (S[BYTE1(v11[3])] << 8) | (S[BYTE2(v11[3])] << 16) | (S[HIBYTE(v11[3])] << 24) | S[LOBYTE(v11[3])];
      v11[0] = chm_rotr(s[2] ^ s[1] ^ s[3], 31);
      v11[1] = chm_rotr(s[1] ^ s[0] ^ s[2], 23);
      v11[2] = chm_rotr(s[1] ^ s[0] ^ s[3], 15);
      v11[3] = chm_rotr(s[2] ^ s[0] ^ s[3], 7);
    }
    v8[0] = v11[0] ^ *(_DWORD *)&enc_key[16 * 8];
    v8[1] = v11[1] ^ *(_DWORD *)&enc_key[16 * 8 + 4];
    v8[2] = v11[2] ^ *(_DWORD *)&enc_key[16 * 8 + 8];
    v8[3] = v11[3] ^ *(_DWORD *)&enc_key[16 * 8 + 12];
    for ( l = 0; l <= 15; ++l )
      output[i + l] = (unsigned char)((unsigned int)v8[l / 4] >> (8 * (3 - l % 4)));
  }
  if ( v13 )
  {
    for ( l = 0; l < v13; ++l )
      *((_BYTE *)v9 + l) = input[i + l];
    for ( l = v13; l <= 15; ++l )
      *((_BYTE *)v9 + l) = 32;
    // for ( j = 0; j <= 3; ++j )
    //   v10[j] = 0;
    memset(v10, 0, 16);
    for ( j = 0; j <= 15; ++j )
      v10[j / 4] = *((unsigned char *)v9 + j) | (v10[j / 4] << 8);
    v11[0] = chm_rotr(v10[0], 31);
    v11[1] = chm_rotr(v10[1], 23);
    v11[2] = chm_rotr(v10[2], 15);
    v11[3] = chm_rotr(v10[3], 7);
    for ( k = 0; k < 8; ++k )
    {
      s[0] = v11[0] ^ *(_DWORD *)&enc_key[16 * k];
      s[1] = v11[1] ^ *(_DWORD *)&enc_key[16 * k + 4];
      s[2] = v11[2] ^ *(_DWORD *)&enc_key[16 * k + 8];
      s[3] = v11[3] ^ *(_DWORD *)&enc_key[16 * k + 12];
      v11[0] = s[2] ^ s[1] ^ s[3];
      v11[1] = s[1] ^ s[0] ^ s[2];
      v11[2] = s[1] ^ s[0] ^ s[3];
      v11[3] = s[2] ^ s[0] ^ s[3];
      s[0] = (S[(unsigned short)(LOWORD(s[2]) ^ LOWORD(s[1]) ^ LOWORD(s[3])) >> 8] << 8) | (S[BYTE2(v11[0])] << 16) | (S[HIBYTE(v11[0])] << 24) | S[LOBYTE(s[2]) ^ LOBYTE(s[1]) ^ LOBYTE(s[3])];
      s[1] = (S[BYTE1(v11[1])] << 8) | (S[BYTE2(v11[1])] << 16) | (S[HIBYTE(v11[1])] << 24) | S[LOBYTE(v11[1])];
      s[2] = (S[BYTE1(v11[2])] << 8) | (S[BYTE2(v11[2])] << 16) | (S[HIBYTE(v11[2])] << 24) | S[LOBYTE(v11[2])];
      s[3] = (S[BYTE1(v11[3])] << 8) | (S[BYTE2(v11[3])] << 16) | (S[HIBYTE(v11[3])] << 24) | S[LOBYTE(v11[3])];
      v11[0] = chm_rotr(s[2] ^ s[1] ^ s[3], 31);
      v11[1] = chm_rotr(s[1] ^ s[0] ^ s[2], 23);
      v11[2] = chm_rotr(s[1] ^ s[0] ^ s[3], 15);
      v11[3] = chm_rotr(s[2] ^ s[0] ^ s[3], 7);
    }
    v8[0] = v11[0] ^ *(_DWORD *)&enc_key[16 * 8];
    v8[1] = v11[1] ^ *(_DWORD *)&enc_key[16 * 8 + 4];
    v8[2] = v11[2] ^ *(_DWORD *)&enc_key[16 * 8 + 8];
    v8[3] = v11[3] ^ *(_DWORD *)&enc_key[16 * 8 + 12];
    for ( l = 0; l <= 15; ++l )
      output[i + l] = (unsigned char)((unsigned int)v8[l / 4] >> (8 * (3 - l % 4)));
  }
  return 0;
}

int Crypt_Enc_Block_SM1(unsigned char *input, int in_len, unsigned char *output, int *out_len, unsigned char *key, int keylen)
{
    unsigned char v1[16] = {
        0x19,
        0x1A,
        0x4E,
        0xF3,
        0x67,
        0xEC,
        0xE2,
        0x81,
        0xC9,
        0x3,
        0xC4,
        0x6C,
        0x23,
        0x33,
        0x3C,
        0x2A
    };

    unsigned char v2[16] = { 0 };

    unsigned char dec_key[176] = {0};
    unsigned char enc_key[176] = {0};

    SCB2_extendkey(key, v2, v1, enc_key, dec_key, 8);

    SCB2_encrypt(input, in_len, output, out_len, enc_key, 8);

    return 0;
}

int SCB2_decrypt(unsigned char *input, int in_len, unsigned char *output, int *out_len, unsigned char *dec_key, int len)
{
//  int v7[16]; // [rsp+30h] [rbp-A0h] BYREF
  int v8[4]; // [rsp+70h] [rbp-60h] BYREF
  int v9[4]; // [rsp+80h] [rbp-50h] BYREF
  int v10[4]; // [rsp+90h] [rbp-40h] BYREF
  int s[4]; // [rsp+A0h] [rbp-30h] BYREF
  int v12; // [rsp+BCh] [rbp-14h]
  int i; // [rsp+C0h] [rbp-10h]
  int j; // [rsp+C4h] [rbp-Ch]
  int l; // [rsp+C8h] [rbp-8h]
  int k; // [rsp+CCh] [rbp-4h]

  i = 0;
  v12 = in_len;
  if ( (in_len & 0xF) != 0 )
    return -3;
  *out_len = (in_len + 15) & 0xFFFFFFF0;
  for ( i = 0; i < v12; i += 16 )
  {
    for ( j = 0; j <= 3; ++j )
      v9[j] = 0;
    for ( j = 0; j <= 15; ++j )
      v9[j / 4] = input[i + j] | (v9[j / 4] << 8);
    v10[0] = chm_rotr(v9[0], 1);
    v10[1] = chm_rotr(v9[1], 9);
    v10[2] = chm_rotr(v9[2], 17);
    v10[3] = chm_rotr(v9[3], 25);
    for ( k = 0; k < 8; ++k )
    {
      s[0] = v10[0] ^ *(_DWORD *)&dec_key[16 * k];
      s[1] = v10[1] ^ *(_DWORD *)&dec_key[16 * k + 4];
      s[2] = v10[2] ^ *(_DWORD *)&dec_key[16 * k + 8];
      s[3] = v10[3] ^ *(_DWORD *)&dec_key[16 * k + 12];
      v10[0] = s[2] ^ s[1] ^ s[3];
      v10[1] = s[1] ^ s[0] ^ s[2];
      v10[2] = s[1] ^ s[0] ^ s[3];
      v10[3] = s[2] ^ s[0] ^ s[3];
      s[0] = (S[(unsigned short)(LOWORD(s[2]) ^ LOWORD(s[1]) ^ LOWORD(s[3])) >> 8] << 8) | (S[BYTE2(v10[0])] << 16) | (S[HIBYTE(v10[0])] << 24) | S[LOBYTE(s[2]) ^ LOBYTE(s[1]) ^ LOBYTE(s[3])];
      s[1] = (S[BYTE1(v10[1])] << 8) | (S[BYTE2(v10[1])] << 16) | (S[HIBYTE(v10[1])] << 24) | S[LOBYTE(v10[1])];
      s[2] = (S[BYTE1(v10[2])] << 8) | (S[BYTE2(v10[2])] << 16) | (S[HIBYTE(v10[2])] << 24) | S[LOBYTE(v10[2])];
      s[3] = (S[BYTE1(v10[3])] << 8) | (S[BYTE2(v10[3])] << 16) | (S[HIBYTE(v10[3])] << 24) | S[LOBYTE(v10[3])];
      v10[0] = chm_rotr(s[2] ^ s[1] ^ s[3], 1);
      v10[1] = chm_rotr(s[1] ^ s[0] ^ s[2], 9);
      v10[2] = chm_rotr(s[1] ^ s[0] ^ s[3], 17);
      v10[3] = chm_rotr(s[2] ^ s[0] ^ s[3], 25);
    }
    v8[0] = v10[0] ^ *(_DWORD *)&dec_key[16 * 8];
    v8[1] = v10[1] ^ *(_DWORD *)&dec_key[16 * 8 + 4];
    v8[2] = v10[2] ^ *(_DWORD *)&dec_key[16 * 8 + 8];
    v8[3] = v10[3] ^ *(_DWORD *)&dec_key[16 * 8 + 12];
    for ( l = 0; l <= 15; ++l )
      output[i + l] = (unsigned char)((unsigned int)v8[l / 4] >> (8 * (3 - l % 4)));
  }
  return 0;
}

int Crypt_Dec_Block_SM1(unsigned char *input, int in_len, unsigned char *output, int *out_len, unsigned char *key, int keylen)
{
    unsigned char v1[16] = {
        0x19,
        0x1A,
        0x4E,
        0xF3,
        0x67,
        0xEC,
        0xE2,
        0x81,
        0xC9,
        0x3,
        0xC4,
        0x6C,
        0x23,
        0x33,
        0x3C,
        0x2A
    };

    unsigned char v2[16] = { 0 };

    unsigned char dec_key[176] = {0};
    unsigned char enc_key[176] = {0};

    SCB2_extendkey(key, v2, v1, enc_key, dec_key, 8);

    SCB2_decrypt(input, in_len, output, out_len, dec_key, 8);

    return 0;
}
