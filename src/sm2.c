#include "sm2.h"

/*
 SM2 std math generate keypair:
 1. prikey dA = random
 2. pubkey PA = dA*G
 */
static int sm2_std_gen_mp_key_pair(OUT my_pbig mp_pri_dA,
                                      OUT my_pbig mp_XA,
                                      OUT my_pbig mp_YA,
                                      OUT my_pbig mp_Xg,
                                      IN my_pbig mp_Yg,
                                      IN my_pbig mp_a,
                                      IN my_pbig mp_b,
                                      IN my_pbig mp_n,
                                      IN my_pbig mp_p,
                                      IN my_gp *gp){
    
    int ret = SM2_SUCCESS;
    my_pbig mp_rand_k = NULL, pub_x = NULL, pub_y = NULL;
    my_point *G = NULL, *pubkey = NULL;
    
    mp_rand_k = my_init(0, gp); ret = gp->err_code;CHECK(ret);
    pub_x = my_init(0,gp);      ret = gp->err_code;CHECK(ret);
    pub_y = my_init(0,gp);      ret = gp->err_code;CHECK(ret);
    G = my_point_init(gp);      ret = gp->err_code;CHECK(ret);
    pubkey = my_point_init(gp); ret = gp->err_code;CHECK(ret);
    
    //privite key
    ret = get_random_key(mp_rand_k, mp_n, gp);               CHECK(ret);
    my_copy(mp_rand_k, mp_pri_dA);
    //public key
    my_ecc_init(mp_a, mp_b, mp_p, gp);      ret = gp->err_code; CHECK(ret);
    my_set_point(mp_Xg, mp_Yg, G, gp);      ret = gp->err_code; CHECK(ret);
    my_point_mul(mp_rand_k, G, pubkey, gp); ret = gp->err_code; CHECK(ret);
    my_get_point(pubkey, pub_x, pub_y, gp); ret = gp->err_code; CHECK(ret);
    ret = check_point(pub_x, pub_y, mp_a, mp_b, mp_p, gp);   CHECK(ret);
    my_copy(pub_x, mp_XA);
    my_copy(pub_y, mp_YA);
    
END:
    my_clear(mp_rand_k);my_clear(pub_x);my_clear(pub_y);
    my_point_clear(G);my_point_clear(pubkey);
    return ret;
}

/*
 SM2 std math signature:
 1. e = src hash
 2. genetate random k
 3. (x1,y1) = k*G
 4. r = (e+x1) mod n
 5. s = ((1+dA)^-1(k-rdA)) mod n
 6. signature = (r,s)
 */
static int sm2_std_mp_sign(OUT my_pbig mp_r,
                              OUT my_pbig mp_s,
                              IN my_pbig mp_e,
                              IN my_pbig mp_dA,
                              IN my_pbig mp_Xg,
                              IN my_pbig mp_Yg,
                              IN my_pbig mp_a,
                              IN my_pbig mp_b,
                              IN my_pbig mp_p,
                              IN my_pbig mp_n,
                              IN my_gp *gp){
    
    int ret = SM2_SUCCESS, try_num = 100;
    my_point * G = NULL, *P = NULL;
    my_pbig mp_x1 = NULL, mp_y1 = NULL, tmp1 = NULL, tmp2 = NULL, tmp3 = NULL, mp_rand_k = NULL;
    
    G = my_point_init(gp);      ret = gp->err_code;CHECK(ret);
    P = my_point_init(gp);      ret = gp->err_code;CHECK(ret);
    mp_x1 = my_init(0, gp);     ret = gp->err_code;CHECK(ret);
    mp_y1 = my_init(0, gp);     ret = gp->err_code;CHECK(ret);
    tmp1 = my_init(0, gp);      ret = gp->err_code;CHECK(ret);
    tmp2 = my_init(0, gp);      ret = gp->err_code;CHECK(ret);
    tmp3 = my_init(0, gp);      ret = gp->err_code;CHECK(ret);
    mp_rand_k = my_init(0, gp); ret = gp->err_code;CHECK(ret);
    
    do{
        do{
            try_num--;
            ret = get_random_key(mp_rand_k, mp_n, gp);           CHECK(ret);//random k
            my_ecc_init(mp_a, mp_b, mp_p, gp);  ret = gp->err_code; CHECK(ret);
            my_set_point(mp_Xg, mp_Yg, G, gp);  ret = gp->err_code; CHECK(ret);
            my_point_mul(mp_rand_k, G, P, gp);  ret = gp->err_code; CHECK(ret);//P
            my_get_point(P, mp_x1, mp_y1, gp);  ret = gp->err_code; CHECK(ret);//P_x & P_y
            my_set_mod(mp_n, gp);               ret = gp->err_code; CHECK(ret);
            my_pn(mp_e, mp_e, gp);              ret = gp->err_code; CHECK(ret);
            my_pn(mp_x1, mp_x1, gp);            ret = gp->err_code; CHECK(ret);
            my_addmodn(mp_e, mp_x1, mp_r, gp);  ret = gp->err_code; CHECK(ret);//mp_r = (e+x1) mod n
            my_rn(mp_r, mp_r, gp);              ret = gp->err_code; CHECK(ret);
            my_add(mp_r, mp_rand_k, tmp1, gp);  ret = gp->err_code; CHECK(ret);//tmp1 = r+k
            my_set_d(0, tmp2);
        }while((0 == my_cmp(mp_r, tmp2) || 0 == my_cmp(tmp1, mp_n)) && (try_num > 0));
        try_num--;
        my_set_d(1, tmp1);
        my_add(tmp1, mp_dA, tmp2, gp);          ret = gp->err_code; CHECK(ret);//tmp2 = 1+dA
        my_invmod(tmp2, mp_n, tmp2, gp);        ret = gp->err_code; CHECK(ret);//tmp2 = (1+dA)^-1
        my_pn(mp_r, mp_r, gp);                  ret = gp->err_code; CHECK(ret);
        my_pn(mp_dA, mp_dA, gp);                ret = gp->err_code; CHECK(ret);
        my_mulmodn(mp_r, mp_dA, tmp1, gp);      ret = gp->err_code; CHECK(ret);//tmp1 = r*dA mod n
        my_pn(mp_rand_k, mp_rand_k, gp);        ret = gp->err_code; CHECK(ret);
        my_submodn(mp_rand_k, tmp1, tmp3, gp);  ret = gp->err_code; CHECK(ret);//tmp3 = k-r*dA mog n
        my_pn(tmp2, tmp2, gp);                  ret = gp->err_code; CHECK(ret);
        my_mulmodn(tmp2, tmp3, mp_s, gp);       ret = gp->err_code; CHECK(ret);//mp_s = (1+dA)^-1*(k-r*dA) mod n
        my_rn(mp_s, mp_s, gp);                  ret = gp->err_code; CHECK(ret);
        my_rn(mp_r, mp_r, gp);                  ret = gp->err_code; CHECK(ret);
        my_set_d(0, tmp1);
    }while((0 == my_cmp(tmp1, mp_s)) && (try_num > 0));
    if(try_num <= 0) ret = SM2_STD_SIGN_TRY_MANY_TIMES;
    
END:
    my_clear(mp_x1);my_clear(mp_y1);my_clear(tmp1);my_clear(tmp2);my_clear(tmp3);my_clear(mp_rand_k);
    my_point_clear(G);my_point_clear(P);
    return ret;
}

/*
 SM2 std math verify signature:
 1. e' = src hash
 2. t = (r'+s') mod n, if t = 0 failed
 3. (x1, y1) = s'*G+t*PA
 4. R = (e'+x1) mod n
 5. if R = r' success else failed
 
 The derivation process:
 1. t = r'+s'
 2. r' = e+x1, s' = (1+dA)^-1(k-rdA)
 3. t = (1+dA)^-1(k-r'dA)+r'
 4. PA = dA*G
 5. t*PA = ((1+dA)^-1(k-r'dA)+r')*dA*G
 6. s'*G+t*PA = ((1+dA)^-1(k-r'dA)+r')*dA*G + (1+dA)^-1(k-r'dA)*G
 7. s'*G+t*PA = (1+dA)^-1(k-r'dA)*dA*G + r'dA*G + (1+dA)^-1(k-r'dA)*G
 8. s'*G+t*PA = [(1+dA)^-1(k-r'dA)*dA + r'dA + (1+dA)^-1(k-r'dA)]*G
 9. s'*G+t*PA = [(1+dA)^-1(k-r'dA)(dA+1) + r'dA]*G
 10. s'*G+t*PA = [(k-r'dA) + r'dA]*G
 10. s'*G+t*PA = k*G = (x1,y1)  ok!
 */
static int sm2_std_mp_verify(IN my_pbig mp_r,
                                IN my_pbig mp_s,
                                IN my_pbig mp_e,
                                IN my_pbig mp_XA,
                                IN my_pbig mp_YA,
                                IN my_pbig mp_Xg,
                                IN my_pbig mp_Yg,
                                IN my_pbig mp_a,
                                IN my_pbig mp_b,
                                IN my_pbig mp_p,
                                IN my_pbig mp_n,
                                IN my_gp *gp){
    
    if(1 != my_cmp(mp_n, mp_r)) return SM2_STD_VERIFY_R_GT_N;
    if(1 != my_cmp(mp_n, mp_s)) return SM2_STD_VERIFY_S_GT_N;
    
    int ret = SM2_SUCCESS;
    my_point *G = NULL, *P0 = NULL, *P1 = NULL;
    my_pbig mp_t = NULL, mp_x0 = NULL, mp_y0 = NULL;
    
    G = my_point_init(gp);  ret = gp->err_code; CHECK(ret);
    P0 = my_point_init(gp); ret = gp->err_code; CHECK(ret);
    P1 = my_point_init(gp); ret = gp->err_code; CHECK(ret);
    mp_t = my_init(0, gp);  ret = gp->err_code; CHECK(ret);
    mp_x0 = my_init(0, gp); ret = gp->err_code; CHECK(ret);
    mp_y0 = my_init(0, gp); ret = gp->err_code; CHECK(ret);
    
    my_set_mod(mp_n, gp);               ret = gp->err_code;CHECK(ret);
    my_pn(mp_r, mp_r, gp);              ret = gp->err_code;CHECK(ret);
    my_pn(mp_s, mp_s, gp);              ret = gp->err_code;CHECK(ret);//mp_t = r'+s' mod n
    my_addmodn(mp_r, mp_s, mp_t, gp);   ret = gp->err_code;CHECK(ret);
    my_rn(mp_t, mp_t, gp);              ret = gp->err_code;CHECK(ret);
    my_rn(mp_r, mp_r, gp);              ret = gp->err_code;CHECK(ret);
    my_rn(mp_s, mp_s, gp);              ret = gp->err_code;CHECK(ret);
    my_set_d(0, mp_x0);
    if(0 == my_cmp(mp_x0, mp_t)){ret = SM2_STD_VERIFY_T_QT_0;goto END;}
    my_ecc_init(mp_a, mp_b, mp_p, gp);  ret = gp->err_code;CHECK(ret);
    my_set_point(mp_Xg, mp_Yg, G, gp);  ret = gp->err_code;CHECK(ret);
    my_set_point(mp_XA, mp_YA, P1, gp); ret = gp->err_code;CHECK(ret);
    my_point_mul(mp_s, G, P0, gp);      ret = gp->err_code;CHECK(ret);//P0 = s'*G
    my_point_mul(mp_t, P1, G, gp);      ret = gp->err_code;CHECK(ret);//G = t*PA
    my_point_add(G, P0, gp);            ret = gp->err_code;CHECK(ret);//P0 = s'*G + t*PA
    my_get_point(P0, mp_x0, mp_y0, gp); ret = gp->err_code;CHECK(ret);
    my_set_mod(mp_n, gp);               ret = gp->err_code;CHECK(ret);
    my_pn(mp_e, mp_e, gp);              ret = gp->err_code;CHECK(ret);
    my_pn(mp_x0, mp_x0, gp);            ret = gp->err_code;CHECK(ret);
    my_addmodn(mp_e, mp_x0, mp_t, gp);  ret = gp->err_code;CHECK(ret);//mp_t = e'+x1 mod n
    my_rn(mp_t, mp_t, gp);              ret = gp->err_code;CHECK(ret);
    if(0 != my_cmp(mp_t, mp_r)) ret = SM2_STD_VERIFY_T_NOT_QT;
    
END:
    my_clear(mp_t);my_clear(mp_x0);my_clear(mp_y0);
    my_point_clear(G);my_point_clear(P0);my_point_clear(P1);
    return ret;
}

//SM2 std generate keypair
int sm2_gen_keypair(OUT unsigned char *prikey,
                       OUT unsigned int *priLen,
                       OUT unsigned char pubkey[64]){
    
    if(prikey == NULL) return SM2_STD_GEN_KEYPAIR_PRIKEY_NULL;
    if(priLen == NULL) return SM2_STD_GEN_KEYPAIR_PRILEN_NULL;
    if(pubkey == NULL) return SM2_STD_GEN_KEYPAIR_PUBKEY_NULL;
    
    unsigned char X[32] = {0}; unsigned int X_len = 32;
    unsigned char Y[32] = {0}; unsigned int Y_len = 32;
    
    int ret = SM2_SUCCESS;
    my_pbig mp_a = NULL, mp_b = NULL, mp_n = NULL, mp_p = NULL, mp_Xg = NULL;
    my_pbig mp_Yg = NULL, mp_pri_dA = NULL, mp_XA = NULL, mp_YA = NULL;
    my_gp *gp = my_init_gp();
    if(gp == NULL){ret = SM2_MEM_ALLOC_ERROR;goto END;}
    mp_a = my_init(0, gp);      ret = gp->err_code;CHECK(ret);
    mp_b = my_init(0, gp);      ret = gp->err_code;CHECK(ret);
    mp_n = my_init(0, gp);      ret = gp->err_code;CHECK(ret);
    mp_p = my_init(0, gp);      ret = gp->err_code;CHECK(ret);
    mp_Xg = my_init(0, gp);     ret = gp->err_code;CHECK(ret);
    mp_Yg = my_init(0, gp);     ret = gp->err_code;CHECK(ret);
    mp_pri_dA = my_init(0, gp); ret = gp->err_code;CHECK(ret);
    mp_XA = my_init(0, gp);     ret = gp->err_code;CHECK(ret);
    mp_YA = my_init(0, gp);     ret = gp->err_code;CHECK(ret);
    
    ret = std_param(mp_a, mp_b, mp_n, mp_p, mp_Xg, mp_Yg, gp);           CHECK(ret);
    ret = sm2_std_gen_mp_key_pair(mp_pri_dA, mp_XA, mp_YA, mp_Xg,
                                     mp_Yg, mp_a, mp_b, mp_n, mp_p, gp);    CHECK(ret);
    ret = mp_2_bin(Y, &Y_len, mp_YA, gp);                                CHECK(ret);
    if(Y_len != 32){ret = SM2_STD_GEN_KEYPAIR_YLEN_NOT_QT_32;goto END;}
    ret = mp_2_bin(X, &X_len, mp_XA, gp);                                CHECK(ret);
    if(X_len != 32){ret = SM2_STD_GEN_KEYPAIR_XLEN_NOT_QT_32;goto END;}
    ret = mp_2_bin(prikey, priLen, mp_pri_dA, gp);                       CHECK(ret);
    if(*priLen != 32){ret = SM2_STD_GEN_KEYPAIR_PRILEN_NOT_QT_32;goto END;}
    memcpy(pubkey, X, X_len);
    memcpy(pubkey + X_len, Y, Y_len);
    
END:
    my_clear(mp_a);my_clear(mp_b);my_clear(mp_n);my_clear(mp_p);my_clear(mp_Xg);
    my_clear(mp_Yg);my_clear(mp_pri_dA);my_clear(mp_XA);my_clear(mp_YA);
    my_gp_clear(gp);
    return ret;
}

//SM2 std signature
int sm2_sign(OUT unsigned char *signature,
                OUT unsigned int *signLen,
                IN unsigned char *src,
                IN unsigned int srcLen,
                IN unsigned char *userID,
                IN unsigned int IDLen,
                IN unsigned char *prikey,
                IN unsigned int priLen,
                IN unsigned char *pubkey,
                IN unsigned int hashFlag){
    
    if(signature == NULL) return SM2_STD_SIGN_SIGNATURE_NULL;
    if(signLen == NULL) return SM2_STD_SIGN_SIGNLEN_NULL;
    if(src == NULL) return SM2_STD_SIGN_SRC_NULL;
    if(prikey == NULL) return SM2_STD_SIGN_PRIKEY_NULL;
    if(priLen != 32) return SM2_STD_SIGN_PRIKEYLEN_NULL;
    if(hashFlag != WITH_HASH && hashFlag != NO_HASH) return SM2_STD_SIGN_HASHFLAG_ERROR;
    if(hashFlag == WITH_HASH && userID == NULL) return SM2_STD_SIGN_USERID_NULL;
    if(hashFlag == WITH_HASH && IDLen <= 0) return SM2_STD_SIGN_USERIDLEN_ERROR;
    if(hashFlag == WITH_HASH && srcLen <= 0) return SM2_STD_SIGN_SRCLEN_ERROR;
    if(hashFlag == NO_HASH && srcLen != 32) return SM2_STD_SIGN_SRCLEN_NOT_QT_32;
        
    int ret = SM2_SUCCESS;
    unsigned char e[32] = {0};
    unsigned int eLen = 32;
    unsigned int tempLen = 32;
    my_pbig mp_a = NULL, mp_b = NULL, mp_n = NULL, mp_p = NULL, mp_Xg = NULL, mp_Yg = NULL;
    my_pbig mp_XA = NULL, mp_YA = NULL, mp_dA = NULL, mp_r = NULL, mp_s = NULL, mp_e = NULL;
    my_point *G = NULL, *P = NULL;
    my_gp *gp = my_init_gp();
    if(gp == NULL){ret = SM2_MEM_ALLOC_ERROR;goto END;}
    mp_a = my_init(0, gp);  ret = gp->err_code;CHECK(ret);
    mp_b = my_init(0, gp);  ret = gp->err_code; CHECK(ret);
    mp_n = my_init(0, gp);  ret = gp->err_code; CHECK(ret);
    mp_p = my_init(0, gp);  ret = gp->err_code; CHECK(ret);
    mp_Xg = my_init(0, gp); ret = gp->err_code; CHECK(ret);
    mp_Yg = my_init(0, gp); ret = gp->err_code; CHECK(ret);
    mp_XA = my_init(0, gp); ret = gp->err_code; CHECK(ret);
    mp_YA = my_init(0, gp); ret = gp->err_code; CHECK(ret);
    mp_dA = my_init(0, gp); ret = gp->err_code; CHECK(ret);
    mp_r = my_init(0, gp);  ret = gp->err_code; CHECK(ret);
    mp_s = my_init(0, gp);  ret = gp->err_code; CHECK(ret);
    mp_e = my_init(0, gp);  ret = gp->err_code; CHECK(ret);
    G = my_point_init(gp);  ret = gp->err_code; CHECK(ret);
    P = my_point_init(gp);  ret = gp->err_code; CHECK(ret);
    
    ret = std_param(mp_a, mp_b, mp_n, mp_p, mp_Xg, mp_Yg, gp);                   CHECK(ret);
    my_read_bin((int)priLen, (const char *)prikey, mp_dA, gp);  ret = gp->err_code; CHECK(ret);
    
    if(hashFlag == NO_HASH){
        memcpy(e, src, srcLen);
    }else{
        if(pubkey != NULL){
            my_read_bin(32, (const char *)pubkey, mp_XA, gp);   ret = gp->err_code; CHECK(ret);
            my_read_bin(32, (const char *)pubkey+32, mp_YA, gp);ret = gp->err_code; CHECK(ret);
        }else{
            my_ecc_init(mp_a, mp_b, mp_p, gp);                  ret = gp->err_code; CHECK(ret);
            my_set_point(mp_Xg, mp_Yg, G, gp);                  ret = gp->err_code; CHECK(ret);
            my_point_mul(mp_dA, G, P, gp);                      ret = gp->err_code; CHECK(ret);
            my_get_point(P, mp_XA, mp_YA, gp);                  ret = gp->err_code; CHECK(ret);
        }
        ret = sm3_progress(e, &eLen, src, srcLen,
                              userID, IDLen, mp_XA, mp_YA, gp);                     CHECK(ret);
    }
    my_read_bin((int)eLen, (const char *)e, mp_e, gp);          ret = gp->err_code; CHECK(ret);
    ret = sm2_std_mp_sign(mp_r, mp_s, mp_e, mp_dA, mp_Xg,
                             mp_Yg, mp_a, mp_b, mp_p, mp_n, gp);                    CHECK(ret);
    ret = mp_2_bin(signature, &eLen, mp_r, gp);                                  CHECK(ret);
    if(eLen != 32){ret = SM2_STD_SIGN_RLEN_NOT_QT_32;goto END;}
    ret = mp_2_bin(signature + eLen, &tempLen, mp_s, gp);                        CHECK(ret);
    if(tempLen != 32){ret = SM2_STD_SIGN_SLEN_NOT_QT_32;goto END;}
    *signLen = eLen + tempLen;
    
END:
    my_clear(mp_a);my_clear(mp_b);my_clear(mp_n);my_clear(mp_p);my_clear(mp_Xg);my_clear(mp_Yg);
    my_clear(mp_XA);my_clear(mp_YA);my_clear(mp_dA);my_clear(mp_r);my_clear(mp_s);my_clear(mp_e);
    my_point_clear(G);my_point_clear(P);my_gp_clear(gp);
    return ret;
}

//SM2 std verify signature
int sm2_verify(IN unsigned char *signedData,
                  IN unsigned int signLen,
                  IN unsigned char *src,
                  IN unsigned int srcLen,
                  IN unsigned char *userID,
                  IN unsigned int IDLen,
                  IN unsigned char *pubkey,
                  IN unsigned int pubLen,
                  IN unsigned int hashFlag){
    
    if(signedData == NULL) return SM2_STD_VERIFY_SIGNDATA_NULL;
    if(signLen <= 0) return SM2_STD_VERIFY_SIGNDATA_LEN_ERROR;
    if(src == NULL) return SM2_STD_VERIFY_SRC_NULL;
    if(pubkey == NULL) return SM2_STD_VERIFY_PUBKEY_NULL;
    if(pubLen != 64) return SM2_STD_VERIFY_PUBLEN_NOT_QT_64;
    if(hashFlag != WITH_HASH && hashFlag != NO_HASH) return SM2_STD_VERIFY_HASHFLAG_ERROR;
    if(hashFlag == WITH_HASH && userID == NULL) return SM2_STD_VERIFY_USERID_NULL;
    if(hashFlag == WITH_HASH && IDLen <= 0) return SM2_STD_VERIFY_USERIDLEN_ERROR;
    if(hashFlag == WITH_HASH && srcLen <= 0) return SM2_STD_VERIFY_SRCLEN_ERROR;
    if(hashFlag == NO_HASH && srcLen != 32) return SM2_STD_VERIFY_SRCLEN_NOT_QT_32;
    
    int ret = SM2_SUCCESS;
    unsigned char e[32] = {0};
    unsigned int eLen = 32;
    my_pbig mp_a = NULL, mp_b = NULL, mp_n = NULL, mp_p = NULL, mp_Xg = NULL, mp_Yg = NULL;
    my_pbig mp_XA = NULL, mp_YA = NULL, mp_r = NULL, mp_s = NULL, mp_e = NULL;
    my_gp *gp = my_init_gp();
    if(gp == NULL){ret = SM2_MEM_ALLOC_ERROR;goto END;}
    mp_a = my_init(0, gp);  ret = gp->err_code;CHECK(ret);
    mp_b = my_init(0, gp);  ret = gp->err_code;CHECK(ret);
    mp_n = my_init(0, gp);  ret = gp->err_code;CHECK(ret);
    mp_p = my_init(0, gp);  ret = gp->err_code;CHECK(ret);
    mp_Xg = my_init(0, gp); ret = gp->err_code;CHECK(ret);
    mp_Yg = my_init(0, gp); ret = gp->err_code;CHECK(ret);
    mp_XA = my_init(0, gp); ret = gp->err_code;CHECK(ret);
    mp_YA = my_init(0, gp); ret = gp->err_code;CHECK(ret);
    mp_r = my_init(0, gp);  ret = gp->err_code;CHECK(ret);
    mp_s = my_init(0, gp);  ret = gp->err_code;CHECK(ret);
    mp_e = my_init(0, gp);  ret = gp->err_code;CHECK(ret);

    my_read_bin(32, (const char *)pubkey, mp_XA, gp);       ret = gp->err_code;CHECK(ret);
    my_read_bin(32, (const char *)pubkey+32, mp_YA, gp);    ret = gp->err_code;CHECK(ret);
    my_read_bin(32, (const char *)signedData, mp_r, gp);    ret = gp->err_code;CHECK(ret);
    my_read_bin(32, (const char *)signedData+32, mp_s, gp); ret = gp->err_code;CHECK(ret);
    ret = std_param(mp_a, mp_b, mp_n, mp_p, mp_Xg, mp_Yg, gp);              CHECK(ret);
    if(hashFlag == NO_HASH){
        memcpy(e, src, srcLen);
    }else{
        ret = sm3_progress(e, &eLen, src, srcLen, userID,
                              IDLen, mp_XA, mp_YA, gp);                        CHECK(ret);
    }
    my_read_bin((int)eLen, (const char *)e, mp_e, gp);      ret = gp->err_code;CHECK(ret);
    ret = sm2_std_mp_verify(mp_r, mp_s, mp_e, mp_XA, mp_YA, mp_Xg,
                               mp_Yg, mp_a, mp_b, mp_p, mp_n, gp);             CHECK(ret);
    
END:
    my_clear(mp_a);my_clear(mp_b);my_clear(mp_n);my_clear(mp_p);my_clear(mp_Xg);my_clear(mp_Yg);
    my_clear(mp_XA);my_clear(mp_YA);my_clear(mp_r);my_clear(mp_s);my_clear(mp_e);
    my_gp_clear(gp);
    return ret;
}

/*
SM2 std encrypt:
1. get random k
2. C1 = k*G
3. (x2,y2) = k*PA
4. t = KDF(x2||y2,klen)
5. C2 = M^t
6. C3 = Hash(x2||M||y2)
7. cipher = C1||C3||C2
*/
int sm2_enc(OUT unsigned char *encData,
               OUT unsigned int *encLen,
               IN unsigned char *src,
               IN unsigned int srcLen,
               IN unsigned char *pubkey,
               IN unsigned int pubLen){
    
    if(encData == NULL) return SM2_STD_ENC_ENCDATA_NULL;
    if(encLen == NULL) return SM2_STD_ENC_ENCLEN_NULL;
    if(src == NULL) return SM2_STD_ENC_SRC_NULL;
    if(srcLen <= 0) return SM2_STD_ENC_SRCLEN_ERROR;
    if(pubkey == NULL) return SM2_STD_ENC_PUBKEY_NULL;
    if(pubLen != 64) return SM2_STD_ENC_PUBLEN_NOT_QT_64;
    
    int ret = SM2_SUCCESS, flag = 1, i = 0;
    unsigned int len1 = 0, len2 = 0;
    unsigned char ptmp[100] = {0};
    unsigned char x2[32] = {0}; unsigned int x2Len = 32;
    unsigned char y2[32] = {0}; unsigned int y2Len = 32;
    unsigned char C1[65] = {0};
    unsigned char C3[32] = {0};
    unsigned char * C2 = (unsigned char *)calloc(1,srcLen);
    unsigned char * key = (unsigned char *)calloc(1,srcLen);
    unsigned char * tempHash = (unsigned char *)calloc(1,64+srcLen);
    
    my_point *G = NULL, *P1 = NULL, *P2 = NULL;
    my_pbig mp_a = NULL, mp_b = NULL, mp_n = NULL, mp_p = NULL, mp_Xg = NULL, mp_Yg = NULL;
    my_pbig mp_XB = NULL, mp_YB = NULL, mp_x1 = NULL, mp_y1 = NULL;
    my_pbig mp_x2 = NULL, mp_y2 = NULL, mp_rand_k = NULL;
    my_gp *gp = my_init_gp();
    if(gp == NULL){ret = SM2_MEM_ALLOC_ERROR;goto END;}
    G = my_point_init(gp);      ret = gp->err_code;CHECK(ret);
    P1 = my_point_init(gp);     ret = gp->err_code;CHECK(ret);
    P2 = my_point_init(gp);     ret = gp->err_code;CHECK(ret);
    mp_a = my_init(0, gp);      ret = gp->err_code;CHECK(ret);
    mp_b = my_init(0, gp);      ret = gp->err_code;CHECK(ret);
    mp_n = my_init(0, gp);      ret = gp->err_code;CHECK(ret);
    mp_p = my_init(0, gp);      ret = gp->err_code;CHECK(ret);
    mp_Xg = my_init(0, gp);     ret = gp->err_code;CHECK(ret);
    mp_Yg = my_init(0, gp);     ret = gp->err_code;CHECK(ret);
    mp_XB = my_init(0, gp);     ret = gp->err_code;CHECK(ret);
    mp_YB = my_init(0, gp);     ret = gp->err_code;CHECK(ret);
    mp_x1 = my_init(0, gp);     ret = gp->err_code;CHECK(ret);
    mp_y1 = my_init(0, gp);     ret = gp->err_code;CHECK(ret);
    mp_x2 = my_init(0, gp);     ret = gp->err_code;CHECK(ret);
    mp_y2 = my_init(0, gp);     ret = gp->err_code;CHECK(ret);
    mp_rand_k = my_init(0, gp); ret = gp->err_code;CHECK(ret);
    if(C2 == NULL || key == NULL || tempHash == NULL){ret = SM2_MEM_ALLOC_ERROR;goto END;}
    ret = std_param(mp_a, mp_b, mp_n, mp_p, mp_Xg, mp_Yg, gp);               CHECK(ret);
    my_read_bin(32, (const char *)pubkey, mp_XB, gp);       ret = gp->err_code; CHECK(ret);
    my_read_bin(32, (const char *)pubkey+32, mp_YB, gp);    ret = gp->err_code; CHECK(ret);
    
    do{
        ret = get_random_key(mp_rand_k, mp_n, gp);                           CHECK(ret);
        my_ecc_init(mp_a, mp_b, mp_p, gp);                  ret = gp->err_code; CHECK(ret);
        my_set_point(mp_Xg, mp_Yg, G, gp);                  ret = gp->err_code; CHECK(ret);
        my_set_point(mp_XB, mp_YB, P1, gp);                 ret = gp->err_code; CHECK(ret);
        my_point_mul(mp_rand_k, G, P2, gp);                 ret = gp->err_code; CHECK(ret);
        my_point_mul(mp_rand_k, P1, G, gp);                 ret = gp->err_code; CHECK(ret);
        my_get_point(P2, mp_x1, mp_y1, gp);                 ret = gp->err_code; CHECK(ret);
        my_get_point(G, mp_x2, mp_y2, gp);                  ret = gp->err_code; CHECK(ret);
        ret = mp_2_bin(x2, &x2Len, mp_x2, gp);                               CHECK(ret);
        if(x2Len != 32){ret = SM2_STD_ENC_X2LEN_NOT_QT_32;goto END;}
        ret = mp_2_bin(y2, &y2Len, mp_y2, gp);                               CHECK(ret);
        if(y2Len != 32){ret = SM2_STD_ENC_Y2LEN_NOT_QT_32;goto END;}
        memset(ptmp, 0x00 , 100);
        memcpy(ptmp, x2, x2Len);
        memcpy(ptmp+x2Len, y2, y2Len);
        ret = sm2_kdf(key, ptmp, x2Len+y2Len, srcLen);                       CHECK(ret);
        for(i = 0; i < srcLen; i++) if(key[i] != 0) flag = 0;
    }while(flag);
    C1[0] = 0x04;
    ret = mp_2_bin(C1+1, &len1, mp_x1, gp);                                  CHECK(ret);
    if(len1 != 32){ret = SM2_STD_ENC_X1LEN_NOT_QT_32;goto END;}
    ret = mp_2_bin(C1+1+len1, &len2, mp_y1, gp);                             CHECK(ret);
    if(len2 != 32){ret = SM2_STD_ENC_Y1LEN_NOT_QT_32;goto END;}
    for(i = 0; i < srcLen; i++ ) C2[i] = src[i]^key[i];
    memcpy(tempHash, x2, x2Len);
    memcpy(tempHash+x2Len, src, srcLen);
    memcpy(tempHash+x2Len+srcLen, y2, y2Len);
    ret = hash(SM3, tempHash, x2Len+srcLen+y2Len, C3, &len1);             CHECK(ret);
    memcpy(encData, C1, 65);
    memcpy(encData+65, C3, 32);
    memcpy(encData+97, C2, srcLen);
    *encLen = 97 + srcLen;
    
END:
    if(C2) free(C2); C2 = NULL;
    if(key) free(key); key = NULL;
    if(tempHash) free(tempHash); tempHash = NULL;
    my_clear(mp_a);my_clear(mp_b);my_clear(mp_n);my_clear(mp_p);my_clear(mp_Xg);
    my_clear(mp_Yg);my_clear(mp_XB);my_clear(mp_YB);my_clear(mp_x1);my_clear(mp_y1);
    my_clear(mp_x2);my_clear(mp_y2);my_clear(mp_rand_k);
    my_point_clear(G);my_point_clear(P1);my_point_clear(P2);my_gp_clear(gp);
    return ret;
}

/*
SM2 std decrypt:
1. check C1
2. (x2,y2) = dA*C1
3. t = KDF(x2||y2,klen)
4. M' = C2^t
5. u = Hash(x2||M'||y2)
6. if u == C3 success else failed

The derivation process:
1. (x2,y2) = k*PA = dA*k*G(encrypt)
2. (x2,y2) = dA*C1 (decrypt)
3. C1 = k*G
4. (x2,y2) = dA*k*G  ok!
*/
int sm2_dec(OUT unsigned char *plain,
               OUT unsigned int *plainLen,
               IN unsigned char *cipher,
               IN unsigned int cipherLen,
               IN unsigned char *d,
               IN unsigned int dLen){
    
    if(plain == NULL) return SM2_STD_DEC_PLAIN_NULL;
    if(plainLen == NULL) return SM2_STD_DEC_PLAIN_LEN_NULL;
    if(cipher == NULL) return SM2_STD_DEC_CIPHER_NULL;
    if(cipherLen <= 97) return SM2_STD_DEC_CIPHER_LEN_LT_98;
    if(d == NULL) return SM2_STD_DEC_D_NULL;
    if(dLen != 32) return SM2_STD_DEC_DLEN_NOT_QT_32;
    
    int ret = SM2_SUCCESS, flag = 1, i = 0;
    unsigned int C2Len = cipherLen - 97;
    unsigned char temp[64] = {0};
    unsigned char hashbuf[32] = {0};
    unsigned char x2[32] = {0}; unsigned int x2Len = 32;
    unsigned char y2[32] = {0}; unsigned int y2Len = 32;
    unsigned char * key = (unsigned char *)calloc(1,C2Len);
    unsigned char * temp_src = (unsigned char *)calloc(1,C2Len);
    unsigned char * temp_hash = (unsigned char *)calloc(1,C2Len+64);
    
    my_point *P1 = NULL, *P2 = NULL;
    my_pbig mp_dA = NULL, mp_x1 = NULL, mp_y1 = NULL, mp_x2 = NULL;
    my_pbig mp_y2 = NULL, mp_a = NULL, mp_b = NULL, mp_p = NULL;
    my_gp *gp = my_init_gp();
    if(gp == NULL){ret = SM2_MEM_ALLOC_ERROR;goto END;}
    P1 = my_point_init(gp); ret = gp->err_code; CHECK(ret);
    P2 = my_point_init(gp); ret = gp->err_code; CHECK(ret);
    mp_dA = my_init(0, gp); ret = gp->err_code; CHECK(ret);
    mp_x1 = my_init(0, gp); ret = gp->err_code; CHECK(ret);
    mp_y1 = my_init(0, gp); ret = gp->err_code; CHECK(ret);
    mp_x2 = my_init(0, gp); ret = gp->err_code; CHECK(ret);
    mp_y2 = my_init(0, gp); ret = gp->err_code; CHECK(ret);
    mp_a = my_init(0, gp);  ret = gp->err_code; CHECK(ret);
    mp_b = my_init(0, gp);  ret = gp->err_code; CHECK(ret);
    mp_p = my_init(0, gp);  ret = gp->err_code; CHECK(ret);
    if(key == NULL || temp_src == NULL || temp_hash == NULL){ret = SM2_MEM_ALLOC_ERROR;goto END;}
    ret = std_param(mp_a, mp_b, NULL, mp_p, NULL, NULL, gp);                    CHECK(ret);
    ret = check_byte_point(cipher+1, 64);                                       CHECK(ret);
    my_read_bin((int)dLen, (const char *)d, mp_dA, gp);     ret = gp->err_code; CHECK(ret);
    my_read_bin(32, (const char *)cipher+1, mp_x1, gp);     ret = gp->err_code; CHECK(ret);
    my_read_bin(32, (const char *)cipher+33, mp_y1, gp);    ret = gp->err_code; CHECK(ret);
    my_ecc_init(mp_a, mp_b, mp_p, gp);                      ret = gp->err_code; CHECK(ret);
    my_set_point(mp_x1, mp_y1, P1, gp);                     ret = gp->err_code; CHECK(ret);
    my_point_mul(mp_dA, P1, P2, gp);                        ret = gp->err_code; CHECK(ret);
    my_get_point(P2, mp_x2, mp_y2, gp);                     ret = gp->err_code; CHECK(ret);
    ret = mp_2_bin(x2, &x2Len, mp_x2, gp);                                      CHECK(ret);
    if(x2Len != 32){ret = SM2_STD_DEC_X2LEN_NOT_QT_32;goto END;}
    ret = mp_2_bin(y2, &y2Len, mp_y2, gp);                                      CHECK(ret);
    if(y2Len != 32){ret = SM2_STD_DEC_Y2LEN_NOT_QT_32;goto END;}
    memcpy(temp, x2, x2Len);
    memcpy(temp+x2Len, y2, y2Len);
    ret = sm2_kdf(key, temp, x2Len+y2Len, C2Len);                               CHECK(ret);
    for(i = 0; i < C2Len; i++) if(key[i] != 0) flag = 0;
    if(flag == 1) ret = SM2_STD_DEC_KDF_IS_NULL;                                CHECK(ret);
    for(i = 0; i < C2Len; i++) temp_src[i] = key[i] ^ cipher[97+i];
    memcpy(temp_hash, x2, x2Len);
    memcpy(temp_hash+x2Len, temp_src, C2Len);
    memcpy(temp_hash+x2Len+C2Len, y2, y2Len);
    ret = hash(SM3, temp_hash, x2Len+C2Len+y2Len, hashbuf, &x2Len);                CHECK(ret);
    if(0 != memcmp(hashbuf, cipher+65, 32)) {ret = SM2_STD_DEC_HASH_CMP_ERROR;     CHECK(ret);}
    memcpy(plain, temp_src, C2Len);
    *plainLen = C2Len;
    
END:
    if(key) free(key); key = NULL;
    if(temp_src) free(temp_src); temp_src = NULL;
    if(temp_hash) free(temp_hash); temp_hash = NULL;
    my_clear(mp_dA);my_clear(mp_x1);my_clear(mp_y1);my_clear(mp_x2);
    my_clear(mp_y2);my_clear(mp_a);my_clear(mp_b);my_clear(mp_p);
    my_point_clear(P1);my_point_clear(P2);my_gp_clear(gp);
    return ret;
}
