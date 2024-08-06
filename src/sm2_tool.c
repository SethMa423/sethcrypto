#include "sm2_tool.h"

//Standard params a,b,n,p,gx,gy
static const char p[32] = {0xFF,0xFF,0xFF,0xFE,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0x00,0x00,0x00,0x00,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF};
static const char a[32] = {0xFF,0xFF,0xFF,0xFE,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0x00,0x00,0x00,0x00,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFC};
static const char b[32] = {0x28,0xE9,0xFA,0x9E,0x9D,0x9F,0x5E,0x34,0x4D,0x5A,0x9E,0x4B,0xCF,0x65,0x09,0xA7,0xF3,0x97,0x89,0xF5,0x15,0xAB,0x8F,0x92,0xDD,0xBC,0xBD,0x41,0x4D,0x94,0x0E,0x93};
static const char n[32] = {0xFF,0xFF,0xFF,0xFE,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0x72,0x03,0xDF,0x6B,0x21,0xC6,0x05,0x2B,0x53,0xBB,0xF4,0x09,0x39,0xD5,0x41,0x23};
static const char gx[32] = {0x32,0xC4,0xAE,0x2C,0x1F,0x19,0x81,0x19,0x5F,0x99,0x04,0x46,0x6A,0x39,0xC9,0x94,0x8F,0xE3,0x0B,0xBF,0xF2,0x66,0x0B,0xE1,0x71,0x5A,0x45,0x89,0x33,0x4C,0x74,0xC7};
static const char gy[32] = {0xBC,0x37,0x36,0xA2,0xF4,0xF6,0x77,0x9C,0x59,0xBD,0xCE,0xE3,0x6B,0x69,0x21,0x53,0xD0,0xA9,0x87,0x7C,0xC6,0x2A,0x47,0x40,0x02,0xDF,0x32,0xE5,0x21,0x39,0xF0,0xA0};

//Get SM2 standard params
int std_param(OUT my_pbig mp_a,
              OUT my_pbig mp_b,
              OUT my_pbig mp_n,
              OUT my_pbig mp_p,
              OUT my_pbig mp_Xg,
              OUT my_pbig mp_Yg,
              IN my_gp *gp){
    
    if(mp_a != NULL)    {my_read_bin(32, a, mp_a, gp);   CHECK(gp->err_code);}
    if(mp_b != NULL)    {my_read_bin(32, b, mp_b, gp);   CHECK(gp->err_code);}
    if(mp_n != NULL)    {my_read_bin(32, n, mp_n, gp);   CHECK(gp->err_code);}
    if(mp_p != NULL)    {my_read_bin(32, p, mp_p, gp);   CHECK(gp->err_code);}
    if(mp_Xg != NULL)   {my_read_bin(32, gx, mp_Xg, gp); CHECK(gp->err_code);}
    if(mp_Yg != NULL)   {my_read_bin(32, gy, mp_Yg, gp); CHECK(gp->err_code);}

END:
    return gp->err_code;
}

//Generate random key
int get_random_key(IN my_pbig rand_k,
                   IN my_pbig mp_n,
                   IN my_gp *gp){
    
    int ret = SM2_TOOL_SUCCESS;
    my_pbig mp_rand_k = NULL;
    unsigned char rand_tar[32] = {0};
    
    mp_rand_k = my_init(0,gp);                              ret = gp->err_code; CHECK(ret);
    ret = my_random(rand_tar, 32);                                                   CHECK(ret);
    my_read_bin(32, (const char *)rand_tar, mp_rand_k, gp); ret = gp->err_code; CHECK(ret);
    my_div(mp_rand_k, mp_n, rand_k, gp);                    ret = gp->err_code; CHECK(ret);
    my_copy(mp_rand_k, rand_k);
    
END:
    my_clear(mp_rand_k);
    return ret;
}

//Big number change to byte array
int mp_2_bin(OUT unsigned char *bin,
                OUT unsigned int *binLen,
                IN my_pbig mp_src,
                IN my_gp *gp){
    
    int ret = SM2_TOOL_SUCCESS, lost = 0;
    char buff[128] = {0};
    int buffLen = 128;
    char tmp[128] = {0};
    
    my_to_redix(mp_src, buff, gp); ret = gp->err_code;  CHECK(ret);
    buffLen = (int)strlen(buff);
    if(64 > buffLen){
        lost = 64 - buffLen;
        memset(tmp, 0x30, lost);
        memcpy(tmp + lost, buff, buffLen);
    }else if(buffLen > 64){
        ret = SM2_MP_2_BIN_TOO_LONG;
        goto END;
    }else memcpy(tmp, buff, buffLen);
    tmp[64] = '\0';
    ret = hexstr_to_byte_arr((unsigned char *)tmp, 64, bin, binLen); CHECK(ret);
    
END:
    return ret;
}

/**
 Point check
 y^2 = x^3+a*x+b
 */
int check_point(IN my_pbig mp_X,
                   IN my_pbig mp_Y,
                   IN my_pbig mp_a,
                   IN my_pbig mp_b,
                   IN my_pbig mp_p,
                   IN my_gp *gp){
    
    int ret = SM2_TOOL_SUCCESS;
    my_pbig left = NULL, right = NULL, tmp = NULL, tmp1 = NULL, tmp2 = NULL, _zero = NULL;
    
    left = my_init(0,gp);   ret = gp->err_code;CHECK(ret);
    right = my_init(0,gp);  ret = gp->err_code;CHECK(ret);
    tmp = my_init(0,gp);    ret = gp->err_code;CHECK(ret);
    tmp1 = my_init(0,gp);   ret = gp->err_code;CHECK(ret);
    tmp2 = my_init(0,gp);   ret = gp->err_code;CHECK(ret);
    _zero = my_init(0,gp);  ret = gp->err_code;CHECK(ret);
    
    my_zero(_zero);
    if(0 == my_cmp(mp_X, _zero) && 0 == my_cmp(mp_Y, _zero)){
        ret = SM2_CHECK_POINT_ZERO;
        goto END;
    }
    if(!(((1 == my_cmp(mp_X, _zero) || 0 == my_cmp(mp_X, _zero)) && -1 == my_cmp(mp_X, mp_p)) &&
         ((1 == my_cmp(mp_Y, _zero) || 0 == my_cmp(mp_Y, _zero)) && -1 == my_cmp(mp_Y, mp_p)))){
        ret = SM2_CHECK_POINT_INVALID;
        goto END;
    }
    my_set_mod(mp_p, gp);               ret = gp->err_code; CHECK(ret);
    my_pn(mp_X, mp_X, gp);              ret = gp->err_code; CHECK(ret);
    my_pn(mp_Y, mp_Y, gp);              ret = gp->err_code; CHECK(ret);
    my_pn(mp_a, mp_a, gp);              ret = gp->err_code; CHECK(ret);
    my_pn(mp_b, mp_b, gp);              ret = gp->err_code; CHECK(ret);
    my_mulmodn(mp_Y, mp_Y, left, gp);   ret = gp->err_code; CHECK(ret);//left = y^2 mod p
    my_mulmodn(mp_X, mp_X, tmp, gp);    ret = gp->err_code; CHECK(ret);//mp_tmp = x^2 mod p
    my_mulmodn(tmp, mp_X, tmp1, gp);    ret = gp->err_code; CHECK(ret);//mp_tmp1 = x^3 mod p
    my_mulmodn(mp_a, mp_X, tmp, gp);    ret = gp->err_code; CHECK(ret);//mp_tmp = a*x mod p
    my_addmodn(tmp, tmp1, tmp2, gp);    ret = gp->err_code; CHECK(ret);//tmp2 = x^3+a*x mod p
    my_addmodn(tmp2, mp_b, right, gp);  ret = gp->err_code; CHECK(ret);//right = (x^3+a*x+b) mod p
    my_rn(left, left, gp);              ret = gp->err_code; CHECK(ret);
    my_rn(right, right, gp);            ret = gp->err_code; CHECK(ret);
    my_rn(mp_a, mp_a, gp);              ret = gp->err_code; CHECK(ret);
    my_rn(mp_b, mp_b, gp);              ret = gp->err_code; CHECK(ret);
    my_rn(mp_X, mp_X, gp);              ret = gp->err_code; CHECK(ret);
    my_rn(mp_Y, mp_Y, gp);              ret = gp->err_code; CHECK(ret);
    if(0 != my_cmp(left, right))        ret = SM2_CHECK_POINT_IS_NOT_ON_CURVE;//compare left and right
    
END:
    my_clear(left);my_clear(right);my_clear(tmp);
    my_clear(tmp1);my_clear(tmp2);my_clear(_zero);
    return ret;
}

//Byte point check
int check_byte_point(IN unsigned char *point,
                        IN unsigned int pointLen){
    
    if(point == NULL) return SM2_CHECK_POINT_P_NULL;
    if(pointLen != 64) return SM2_CHECK_POINT_P_LEN_ERROR;
    
    int ret = SM2_TOOL_SUCCESS;
    my_pbig mp_a = NULL, mp_b = NULL, mp_p = NULL, mp_x = NULL, mp_y = NULL;
    my_gp *gp = my_init_gp();
    if(gp == NULL){ret = SM2_TOOL_MEM_ALLOC_ERROR;goto END;}
    mp_a = my_init(0,gp);   ret = gp->err_code;CHECK(ret);
    mp_b = my_init(0,gp);   ret = gp->err_code;CHECK(ret);
    mp_p = my_init(0,gp);   ret = gp->err_code;CHECK(ret);
    mp_x = my_init(0,gp);   ret = gp->err_code;CHECK(ret);
    mp_y = my_init(0,gp);   ret = gp->err_code;CHECK(ret);
    
    ret = std_param(mp_a, mp_b, NULL, mp_p, NULL, NULL, gp);                CHECK(ret);
    my_read_bin(32, (const char *)point, mp_x, gp);     ret = gp->err_code; CHECK(ret);
    my_read_bin(32, (const char *)point+32, mp_y, gp);  ret = gp->err_code; CHECK(ret);
    ret = check_point(mp_x, mp_y, mp_a, mp_b, mp_p, gp);                    CHECK(ret);
    
END:
    my_clear(mp_a);my_clear(mp_b);my_clear(mp_p);
    my_clear(mp_x);my_clear(mp_y);my_gp_clear(gp);
    return ret;
}

/**
 SM2 sign sm3 core hash:
 1. Za = sm3(ENTL||ID||a||b||xG||yG||xA||yA)
 2. ENTL = ID*8 (bit number)
 */
int sm3_core_progress(OUT unsigned char za[32],
                         IN unsigned char *userID,
                         IN unsigned int IDLen,
                         IN my_pbig mp_XA,
                         IN my_pbig mp_YA,
                         IN my_gp *gp){
    
    int ret = SM2_TOOL_SUCCESS;
    unsigned char * tempSrc = NULL;
    unsigned int tempSrcLen = 0;
    unsigned char entl[10] = {0};
    unsigned int entlLen = 10;
    unsigned char tmp[10] = {0};
    unsigned char xa[32] = {0};
    unsigned int xaLen = 32;
    unsigned char ya[32] = {0};
    unsigned int yaLen = 32;
    
    ret = mp_2_bin(xa, &xaLen, mp_XA, gp);               CHECK(ret);
    if(xaLen != 32){ret = SM3_CORE_PROGRESS_XLEN_NOT_QT_32;goto END;}
    ret = mp_2_bin(ya, &yaLen, mp_YA, gp);               CHECK(ret);
    if(xaLen != 32){ret = SM3_CORE_PROGRESS_YLEN_NOT_QT_32;goto END;}
    sprintf((char *)tmp, "%4x",IDLen * 8);
    ret = hexstr_to_byte_arr(tmp, 4, entl, &entlLen);    CHECK(ret);
    tempSrcLen = entlLen + IDLen + 128 + xaLen + yaLen;
    tempSrc = (unsigned char *)calloc(1,tempSrcLen + 2);
    if(tempSrc == NULL){ret = SM2_TOOL_MEM_ALLOC_ERROR;goto END;}
    memcpy(tempSrc, entl, entlLen);
    memcpy(tempSrc+entlLen, userID, IDLen);
    memcpy(tempSrc+entlLen+IDLen, a, 32);
    memcpy(tempSrc+entlLen+IDLen+32, b, 32);
    memcpy(tempSrc+entlLen+IDLen+64, gx, 32);
    memcpy(tempSrc+entlLen+IDLen+96, gy, 32);
    memcpy(tempSrc+entlLen+IDLen+128, xa, xaLen);
    memcpy(tempSrc+entlLen+IDLen+128+xaLen, ya, yaLen);
    ret = hash(SM3, tempSrc, tempSrcLen, za, &yaLen); CHECK(ret);
    
END:
    if(NULL != tempSrc) free(tempSrc); tempSrc = NULL;
    return ret;
}

//SM2 sign sm3 byte hash
int sm3_byte_progress(OUT unsigned char za[32],
                         IN unsigned char pubkey[64],
                         IN unsigned char *userID,
                         IN unsigned int IDLen){
    
    int ret = SM2_TOOL_SUCCESS;
    my_pbig mp_XA = NULL, mp_YA = NULL;
    my_gp *gp = my_init_gp();
    if(gp == NULL){ret = SM2_TOOL_MEM_ALLOC_ERROR;goto END;}
    mp_XA = my_init(0, gp); ret = gp->err_code;CHECK(ret);
    mp_YA = my_init(0, gp); ret = gp->err_code;CHECK(ret);
    
    my_read_bin(32, (const char *)pubkey, mp_XA, gp);   ret = gp->err_code; CHECK(ret);
    my_read_bin(32, (const char *)pubkey+32, mp_YA, gp);ret = gp->err_code; CHECK(ret);
    ret = sm3_core_progress(za, userID, IDLen, mp_XA, mp_YA, gp);        CHECK(ret);
    
END:
    my_clear(mp_XA);my_clear(mp_YA);my_gp_clear(gp);
    return ret;
}

/**
 SM2 sign sm3 hash:
 e = sm3(Za||src)
 */
int sm3_progress(OUT unsigned char *e,
                    OUT unsigned int *eLen,
                    IN unsigned char *src,
                    IN unsigned int srcLen,
                    IN unsigned char *userID,
                    IN unsigned int IDLen,
                    IN my_pbig mp_XA,
                    IN my_pbig mp_YA,
                    IN my_gp *gp){
    
    int ret = SM2_TOOL_SUCCESS;
    unsigned char za[32] = {0};
    unsigned char * M = NULL;
    
    ret = sm3_core_progress(za, userID, IDLen, mp_XA, mp_YA, gp);    CHECK(ret);
    M = (unsigned char *)calloc(1,32 + srcLen);
    if(M == NULL){ret = SM2_TOOL_MEM_ALLOC_ERROR;goto END;}
    memcpy(M, za, 32);
    memcpy(M+32, src, srcLen);
    ret = hash(SM3, M, 32 + srcLen, e, eLen); CHECK(ret);
    
END:
    if(NULL != M) free(M); M = NULL;
    return ret;
}

/**
 SM2 encrypt or decrypt KDF:
 1. count = klen/32 (32 bits)
 2. mod = klen%32
 3. k = sub range(0,klen) of for(1 -- count+1){sm3(inData||count)}
 */
int sm2_kdf(OUT unsigned char *outData,
               IN unsigned char *inData,
               IN unsigned int inLen,
               IN unsigned int klen){
    
    int ret = SM2_TOOL_SUCCESS;
    int times = klen / 32;
    char ct_str[10] = {0};
    unsigned int ct = 1, ct_len = 0;
    unsigned int mod = klen % 32;
    unsigned char ct_buff[10] = {0};
    unsigned char tmp_buff[32];
    
    unsigned char * temp = (unsigned char *)calloc(1,inLen + 4);
    if(temp == NULL){ret = SM2_TOOL_MEM_ALLOC_ERROR;goto END;}
    for(ct = 1; ct <= times; ct++){
        sprintf(ct_str, "%8x", ct);
        ret = hexstr_to_byte_arr((unsigned char *)ct_str, 8, ct_buff, &ct_len);  CHECK(ret);
        memcpy(temp, inData, inLen);
        memcpy(temp+inLen, ct_buff, ct_len);
        ret = hash(SM3, temp, inLen+4, outData+(ct-1)*32, &ct_len);           CHECK(ret);
    }
    if(mod){
        sprintf(ct_str, "%8x", ct);
        ret = hexstr_to_byte_arr((unsigned char *)ct_str, 8, ct_buff, &ct_len);  CHECK(ret);
        memcpy(temp, inData, inLen);
        memcpy(temp+inLen, ct_buff, ct_len);
        ret = hash(SM3, temp, inLen+4, tmp_buff, &ct_len);                    CHECK(ret);
        memcpy(outData+(ct-1)*32, tmp_buff, mod);
    }
    
END:
    if(temp) free(temp); temp = NULL;
    return ret;
}
