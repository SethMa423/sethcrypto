#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <errno.h>
#include <fcntl.h>
#include "base64.h"
 
/**
    base64 Encode a buffer (NUL terminated)
    @param in      The input buffer to encode
    @param inlen   The length of the input buffer
    @param out     [out] The destination of the base64 encoded data
    @param outlen  [in/out] The max size and resulting size
    @return OK_BASE64 if successful
*/
 int base64_encode(unsigned char *in,  unsigned int inlen,
                   unsigned char *out, unsigned int *outlen)
 {
    unsigned int i, len2, leven;
    unsigned char *p;
 
    /* valid output size ? */
    len2 = 4 * ((inlen + 2) / 3);
    if (*outlen < len2 + 1) {
       *outlen = len2 + 1;
       return ERR_BASE64_BUF_OVERFLOW;
    }
    p = out;
    leven = 3*(inlen / 3);
    for (i = 0; i < leven; i += 3) {
        *p++ = codes[(in[0] >> 2) & 0x3F];
        *p++ = codes[(((in[0] & 3) << 4) + (in[1] >> 4)) & 0x3F];
        *p++ = codes[(((in[1] & 0xf) << 2) + (in[2] >> 6)) & 0x3F];
        *p++ = codes[in[2] & 0x3F];
        in += 3;
    }
    /* Pad it if necessary...  */
    if (i < inlen) {
        unsigned a = in[0];
        unsigned b = (i+1 < inlen) ? in[1] : 0;
 
        *p++ = codes[(a >> 2) & 0x3F];
        *p++ = codes[(((a & 3) << 4) + (b >> 4)) & 0x3F];
        *p++ = (i+1 < inlen) ? codes[(((b & 0xf) << 2)) & 0x3F] : '=';
        *p++ = '=';
    }
 
    /* append a NULL byte */
    *p = '\0';
 
    /* return ok */
    *outlen = p - out;
    return OK_BASE64;
 }
 
 
 /**
    base64 decode a block of memory
    @param in       The base64 data to decode
    @param inlen    The length of the base64 data
    @param out      [out] The destination of the binary decoded data
    @param outlen   [in/out] The max size and resulting size of the decoded data
    @return OK_BASE64 if successful
 */
 int base64_decode(unsigned char *in,  unsigned int inlen,
                   unsigned char *out, unsigned int *outlen)
 {
    unsigned int t, x, y, z;
    unsigned char c;
    int           g;
 
    g = 3;
    for (x = y = z = t = 0; x < inlen; x++) {
        c = map[in[x]&0xFF];
        if (c == 255) continue;
        /* the final = symbols are read and used to trim the remaining bytes */
        if (c == 254) {
           c = 0;
           /* prevent g < 0 which would potentially allow an overflow later */
           if (--g < 0) {
              return ERR_BASE64_INVALID_DATA;
           }
        } else if (g != 3) {
           /* we only allow = to be at the end */
           return ERR_BASE64_INVALID_DATA;
        }
 
        t = (t<<6)|c;
 
        if (++y == 4) {
           if (z + g > *outlen) {
              return ERR_BASE64_BUF_OVERFLOW;
           }
           out[z++] = (unsigned char)((t>>16)&255);
           if (g > 1) out[z++] = (unsigned char)((t>>8)&255);
           if (g > 2) out[z++] = (unsigned char)(t&255);
           y = t = 0;
        }
    }
    if (y != 0) {
        return ERR_BASE64_INVALID_DATA;
    }
    *outlen = z;
    return OK_BASE64;
 }

unsigned char *b64_en(unsigned char *src, unsigned int srclen, unsigned int *outlen)
{
    unsigned int tmp_outlen = (srclen + 2) / 3 * 4 + 4;
    unsigned char *out = (unsigned char *)calloc(tmp_outlen, 1);

    if (base64_encode(src, srclen, out, &tmp_outlen)) {
        free(out);
        return NULL;
    }
    else {
        if (outlen != NULL)
            *outlen = tmp_outlen;
        return out;
    }
}

unsigned char *b64_de(unsigned char *src, unsigned int srclen, unsigned int *outlen)
{
    unsigned int tmp_outlen = srclen;
    unsigned char *out = (unsigned char *)calloc(tmp_outlen, 1);

    if (base64_decode(src, srclen, out, &tmp_outlen)) {
        free(out);
        return NULL;
    }
    else {
        if (outlen != NULL)
            *outlen = tmp_outlen;
        return out;
    }
}
