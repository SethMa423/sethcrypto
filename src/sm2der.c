//
//  sm2der.c
//  asn1_libTom
//
//  Created by ccit on 16/9/14.
//  Copyright © 2016年 ccit. All rights reserved.
//
// GM/T 0009-2012 :SM2 Cryptography algorithm application specification
#include <stdio.h>
#include "sm2der.h"
#include "asn1_util.h"

//example:
//DECODE:8wWBD3pqoyT6jAyjvzjmGMZ56MQZy+ptOIsG1pybfINP1dAgt8XSOXYxBR6hzmrKs7sQTPLGuKTsGTUsfkj8eg==
//ENCODE:MFkwEwYHKoZIzj0CAQYIKoEcz1UBgi0DQgAE8wWBD3pqoyT6jAyjvzjmGMZ56MQZy+ptOIsG1pybfINP1dAgt8XSOXYxBR6hzmrKs7sQTPLGuKTsGTUsfkj8eg==
int sm2EncodePubkey(unsigned char derPubkey[91], unsigned int * ulDerPubl,
                    unsigned char pub_XY[64])
{
    if (NULL == derPubkey || 0 == *ulDerPubl) {
        LOGE("sm2EncodePubkey param input error");
        return RETURN_INPUT_DATA_ERROR;
    }
    int ret = 0;
    
    unsigned char outtmp[100] = {0};
    unsigned int outtmpLen = sizeof(outtmp)/sizeof(outtmp[0]);
    
    unsigned int ecPubkey[6] = {1, 2, 840, 10045, 2, 1};               //1.2.840.10045.2.1
    unsigned int ecPubkeyLen = sizeof(ecPubkey)/sizeof(ecPubkey[0]);
    unsigned int sm2_OID[6] = {1, 2, 156, 10197, 1, 301};              //1.2.156.10197.1.301
    unsigned int sm2_OIDLen = sizeof(sm2_OID)/sizeof(sm2_OID[0]);
    
    unsigned char pubkey[65] = {0};
    unsigned int pubkeyLen = sizeof(pubkey)/sizeof(pubkey[0]);
    pubkey[0] = 0x04;
    memcpy(pubkey+1, pub_XY, 64);
    
    unsigned char bit[1024] = {0};
    unsigned int bitLen = sizeof(bit)/sizeof(bit[0]);
    ret = Byte2Bin((const char*)pubkey, pubkeyLen, bit, &bitLen);
    if (ret) {
        LOGE("Byte2 Bin error");
        return ret;
    }
    
    ltc_asn1_list alg[2];
    LTC_SET_ASN1(alg, 0, LTC_ASN1_OBJECT_IDENTIFIER, ecPubkey, ecPubkeyLen);
    LTC_SET_ASN1(alg, 1, LTC_ASN1_OBJECT_IDENTIFIER, sm2_OID, sm2_OIDLen);
    
    ret = der_encode_sequence_multi(outtmp, &outtmpLen, LTC_ASN1_SEQUENCE, 2, alg, LTC_ASN1_BIT_STRING, bitLen, bit, NULL);
    if (ret) {
        LOGE("sm2EncodePubkey error, ret:%d\n", ret);
        return RETURN_ENCODE_STRUCT_ERROR;
    }
    if (outtmpLen > *ulDerPubl || 91 != outtmpLen) {
        LOGE("Encode SM2 Pubnkey error, encode outlen:%d, buff len:%d", outtmpLen, *ulDerPubl);
        *ulDerPubl = outtmpLen;
        return RETURN_BUFF_TO_SMALL_ERROR;
    }
    else{
        memcpy(derPubkey, outtmp, outtmpLen);
        *ulDerPubl = outtmpLen;
    }
    return ret;
}

int sm2DecodePubkey(unsigned char pub_XY[64],
                    unsigned char * derPubkey, unsigned int ulDerPubl)
{
    if (NULL == derPubkey || 0 == ulDerPubl) {
        LOGE("sm2DecodePubkey param input error");
        return RETURN_INPUT_DATA_ERROR;
    }
    int ret = 0;
    ltc_asn1_list *listCert = NULL, *pB_asn1_list = NULL;
    unsigned char buff[128] = {0};
    unsigned int buffLen = sizeof(buff)/sizeof(buff[0]);

    ret = der_decode_sequence_flexi((const unsigned char*)derPubkey, &ulDerPubl, &listCert, 0);
    if (ret) {
        LOGE("parse sm2DecodePubkey ASN1 error, error code:%d", ret);
        ret = RETURN_INPUT_DATA_ERROR;
        goto END;
    }
    if (LTC_ASN1_SEQUENCE != listCert->type || NULL == listCert->child) {
        ret = RETURN_PARSE_STRUCT_ERROR;
        goto END;
    }
    pB_asn1_list = listCert->child;
    if (LTC_ASN1_SEQUENCE != pB_asn1_list->type || NULL == pB_asn1_list->next) {
        ret = RETURN_PARSE_STRUCT_ERROR;
        goto END;
    }
    if (LTC_ASN1_OBJECT_IDENTIFIER != pB_asn1_list->child->type || LTC_ASN1_OBJECT_IDENTIFIER != pB_asn1_list->child->next->type) {
        LOGE("This SM2 pubkey struct has problem!");
    }
    pB_asn1_list = pB_asn1_list->next;
    if (LTC_ASN1_BIT_STRING != pB_asn1_list->type || 65*8 != pB_asn1_list->size) {
        ret = RETURN_PARSE_STRUCT_ERROR;
        goto END;
    }
    buffLen = sizeof(buff)/sizeof(buff[0]);
    memset(buff, 0x00, buffLen);
    ret = Bin2Byte((const char*)pB_asn1_list->data, buff, &buffLen);
    if (ret || 65 != buffLen) {
        LOGE("sm2DecodePubkey Bin2Byte error, ret:%d\n", ret);
        goto END;
    }
    if (0x04 != buff[0]) {
        return RETURN_PARSE_STRUCT_ERROR;
    }
    memcpy(pub_XY, buff+1, 64);

END:
    if(listCert)
    {
        der_sequence_free(listCert);
        listCert = NULL;
    }
    return ret;
}

//ENCODE:
//example:MHgCAQECIQCLF6XbxVVNxP8V/0eJwc6NgpAl2aSJBqScfVjWLxlXTaAKBggqgRzPVQGCLaFEA0IABF7ThPcy7IxVqTvytH6YZoHXSbirSk8tnfsJrauO3AiUIekI3BKXxJYISlaoc2fIiomA98+IWKOIxT7Kd8azA4E=
//example:MHcCAQECIApaAXpEX32K8s8bEz8rAFLLqeGaRAeqbrOBEMbBzvpxoAoGCCqBHM9VAYItoUQDQgAEBOSAapkIIYzNGOWtO7SCWv4QXOEGKwtT19XqqGsSk9Jll34yf+fGVLjCf467oPYDoOH8+gDaggycRU18okEUFg==
int sm2EncodePrikey(unsigned char * derPrikey, unsigned int * ulDerPrikl,
                    unsigned char randPrikey[32], unsigned char pub_XY[64])
{

    if (NULL == derPrikey || 0 == *ulDerPrikl) {
        LOGE("sm2EncodePrikey input data error!");
        return RETURN_INPUT_DATA_ERROR;
    }
    int ret = 0;

    unsigned int sm2_OID[6] = {1, 2, 156, 10197, 1, 301};              //1.2.156.10197.1.301
    unsigned int sm2_OIDLen = sizeof(sm2_OID)/sizeof(sm2_OID[0]);
    const char version = 0x01;

    unsigned char tmp_prikey[33] = {0};
    unsigned int tmp_prikeyLen = sizeof(tmp_prikey)/sizeof(unsigned char);

    ltc_asn1_list tmp1_context[1];
    ltc_asn1_list tmp2_context[1];
    ltc_asn1_list alg[4];

    LTC_SET_ASN1(tmp1_context, 0, LTC_ASN1_OBJECT_IDENTIFIER, sm2_OID, sm2_OIDLen);

    unsigned char pubkey_Head[65] = {0};
    pubkey_Head[0] = 0x04;
    memcpy(pubkey_Head+1, pub_XY, 64);
    unsigned char bit[1024] = {0};
    unsigned int bitLen = sizeof(bit)/sizeof(bit[0]);
    ret = Byte2Bin((const char*)pubkey_Head, 65, bit, &bitLen);
    if (ret) {
        LOGE("sm2EncodePrikey Byte2 Bin error");
        return ret;
    }

    if (0x00 != (randPrikey[0]&0x80)) {
        memcpy(tmp_prikey+1, (const char*)randPrikey, 32);
        tmp_prikeyLen = 33;
    }
    else{
        memcpy(tmp_prikey, (const char*)randPrikey, 32);
        tmp_prikeyLen = 32;
    }
    LTC_SET_ASN1(tmp2_context, 0, LTC_ASN1_BIT_STRING, bit, bitLen);

    LTC_SET_ASN1(alg, 0, LTC_ASN1_INTEGER, &version, 1);
    LTC_SET_ASN1(alg, 1, LTC_ASN1_INTEGER, &tmp_prikey, tmp_prikeyLen);
    LTC_SET_ASN1(alg, 2, LTC_ASN1_CONTEXT_0XA0, tmp1_context, 1);
    LTC_SET_ASN1(alg, 3, LTC_ASN1_CONTEXT_0XA0, tmp2_context, 1);

    ret = der_encode_sequence(alg, 4,  derPrikey, ulDerPrikl);
    if (ret) {
        LOGE("sm2EncodePrikey der_encode_sequence failed, ret:%d\n", ret);
        return RETURN_ENCODE_STRUCT_ERROR;
    }

    return ret;
}

int sm2DecodePrikey(unsigned char sm2_prikey[32], unsigned char sm2_pubXY[64],
                    unsigned char * derPrikey, unsigned int ulderPrikeyLen)
{
    if (NULL == sm2_prikey || NULL == sm2_pubXY || NULL == derPrikey) {
        LOGE("sm2DecodePrikey 入参错误");
        return RETURN_INPUT_DATA_ERROR;
    }
    int ret = 0, loop = 0;
    ltc_asn1_list *listCert, *pB_asn1_list = NULL;
    unsigned int *pUnsignedLong = NULL;
    unsigned char buff[128] = {0};
    unsigned int buffLen = sizeof(buff)/sizeof(buff[0]);
    char tmp[128] = {0};
    unsigned int tmpLen = sizeof(tmp)/sizeof(tmp[0]);
    ret = der_decode_sequence_flexi((const unsigned char*)derPrikey, &ulderPrikeyLen, &listCert, 0);
    if (ret) {
        LOGE("parse sm2DecodePrikey ASN1 error, error code:%d", ret);
        return RETURN_INPUT_DATA_ERROR;
    }
    pB_asn1_list = listCert->child;
    if (NULL == pB_asn1_list || NULL == pB_asn1_list->next || LTC_ASN1_INTEGER != pB_asn1_list->type || LTC_ASN1_INTEGER != pB_asn1_list->next->type) {
        if(listCert)
        {
            der_sequence_free(listCert);
            listCert = NULL;
        }
        return RETURN_PARSE_STRUCT_ERROR;
    }
    pB_asn1_list = pB_asn1_list->next;

    tmpLen = pB_asn1_list->size;
    if (tmpLen < 32) {
        LOGE("len error, len:%u, should be > 32", tmpLen);
        if(listCert){
            der_sequence_free(listCert);
            listCert = NULL;
        }
        return RETURN_INPUT_DATA_ERROR;
    }
    memcpy(sm2_prikey, (const char*)pB_asn1_list->data+(tmpLen-32), 32);

    
    pB_asn1_list = pB_asn1_list->next;
    if (NULL == pB_asn1_list || LTC_ASN1_OBJECT_IDENTIFIER != pB_asn1_list->child->type) {
        if(listCert)
        {
            der_sequence_free(listCert);
            listCert = NULL;
        }
        return RETURN_PARSE_STRUCT_ERROR;
    }

    pUnsignedLong = (unsigned int *)pB_asn1_list->child->data;
    memset(buff, 0x00, sizeof(buff)/sizeof(buff[0]));
    tmpLen = sizeof(tmp)/sizeof(tmp[0]);
    for (loop = 0; loop<pB_asn1_list->child->size; loop++) {
        memset(tmp, 0x00, tmpLen);
        sprintf(tmp, "%d", *(pUnsignedLong++));
        strcat((char*)buff, tmp);
        if (loop < pB_asn1_list->child->size -1) {
            strcat((char*)buff, ".");
        }
    }
    if (0 != strcmp((const char*)buff, "1.2.156.10197.1.301")) {
        LOGE("Not sm2 prikey struct");
        if(listCert)
        {
            der_sequence_free(listCert);
            listCert = NULL;
        }
        return RETURN_PARSE_STRUCT_ERROR;
    }
    
    pB_asn1_list = pB_asn1_list->next;
    if ( NULL == pB_asn1_list || NULL == pB_asn1_list->child || LTC_ASN1_BIT_STRING != pB_asn1_list->child->type || 65*8 != pB_asn1_list->child->size) {
        if(listCert)
        {
            der_sequence_free(listCert);
            listCert = NULL;
        }
        return RETURN_PARSE_STRUCT_ERROR;
    }
    buffLen = sizeof(buff)/sizeof(buff[0]);
    memset(buff, 0x00, buffLen);
    ret = Bin2Byte((const char*)pB_asn1_list->child->data, buff, &buffLen);
    if (ret || 65 != buffLen) {
        LOGE("sm2DecodePrikey Bin2Byte error, ret:%d\n", ret);
        if(listCert)
        {
            der_sequence_free(listCert);
            listCert = NULL;
        }
        return ret;
    }
    if (0x04 != buff[0]) {
        return RETURN_PARSE_STRUCT_ERROR;
    }
    
    memcpy(sm2_pubXY, buff+1, 64);
    if(listCert)
    {
        der_sequence_free(listCert);
        listCert = NULL;
    }
    return ret;
}

//example:
//DECODE: (1)sm3Hash:c/T91C2qRf5uu8o/HJesq03R0QSOW+ByR2kZYTYcXPQ=
//        (2)pub_XY:6i6gGCTYcnqgP/qdnppacBxO6dxzb7sRGrbRJWsoT3bAfr6np8hdCtDgqgg2XCRPS3azWWWAyyZKzuTD9OP/5g==
//        (3)cipher:9Kb3/8E+JmZnKaLdF4UTEg==
//ENCODE:MHoCIQDqLqAYJNhyeqA/+p2emlpwHE7p3HNvuxEattElayhPdgIhAMB+vqenyF0K0OCqCDZcJE9LdrNZZYDLJkrO5MP04//mBCBz9P3ULapF/m67yj8cl6yrTdHRBI5b4HJHaRlhNhxc9AQQ9Kb3/8E+JmZnKaLdF4UTEg==
int sm2EncodeCipher(unsigned char * SM2CipherDer, unsigned int * ulSM2CipherDerLen,
                    unsigned char * Cipher, unsigned int ulCipherLen,
                    unsigned char pub_XY[64], unsigned char sm3hash[32])
{
    //108+ulCipherLen:2(Or more)+35(X)+35(Y)+34(HASH)+2(Cipher OID:OCT_STRING) + other(cipher) + 10(more)
    unsigned int len = 108 + ulCipherLen + 10;
    if (NULL == SM2CipherDer || len > *ulSM2CipherDerLen || NULL == Cipher || 0 == ulCipherLen) {
        LOGE("sm2EncodeCipher Input data error");
        return RETURN_INPUT_DATA_ERROR;
    }

    int ret = 0;
    unsigned char buff_X[33] = {0};
    unsigned int buff_XLen = sizeof(buff_X)/sizeof(unsigned char);
    unsigned char buff_Y[33] = {0};
    unsigned int buff_YLen = sizeof(buff_Y)/sizeof(unsigned char);
    if (0x00 != (pub_XY[0]&0x80)) {
        memcpy(buff_X+1, pub_XY, 32);
        buff_XLen = 33;
    }
    else{
        memcpy(buff_X, pub_XY, 32);
        buff_XLen = 32;
    }

    if (0x00 != (pub_XY[32]&0x80)) {
        memcpy(buff_Y+1, pub_XY+32, 32);
        buff_YLen = 33;
    }
    else{
        memcpy(buff_Y, pub_XY+32, 32);
        buff_YLen = 32;
    }
    
    ltc_asn1_list alg[4];
    LTC_SET_ASN1(alg, 0, LTC_ASN1_INTEGER, &buff_X, buff_XLen);
    LTC_SET_ASN1(alg, 1, LTC_ASN1_INTEGER, &buff_Y, buff_YLen);
    LTC_SET_ASN1(alg, 2, LTC_ASN1_OCTET_STRING, sm3hash, 32);
    LTC_SET_ASN1(alg, 3, LTC_ASN1_OCTET_STRING, Cipher, ulCipherLen);
    
    ret = der_encode_sequence(alg, 4,  SM2CipherDer, ulSM2CipherDerLen);
    if (ret) {
        LOGE("sm2Encode cipher error, ret:%d\n", ret);
        return RETURN_ENCODE_STRUCT_ERROR;
    }

    return ret;
}

int sm2DecodeCipher(unsigned char pub_XY[64], unsigned char sm3hash[32],
                    unsigned char *Cipher, unsigned int * ulCipherLen,
                    unsigned char * SM2CipherDer, unsigned int SM2CipherDerLen)
{
    if (NULL == pub_XY || NULL == sm3hash || NULL == Cipher) {
        LOGE("sm2DecodeCipher 入参错误");
        return RETURN_INPUT_DATA_ERROR;
    }
    int ret = 0;
    ltc_asn1_list *listCert = NULL, *pB_asn1_list = NULL;
    unsigned int tmpLen = 0;
    ret = der_decode_sequence_flexi((const unsigned char *)SM2CipherDer, 
                                    &SM2CipherDerLen, &listCert, 0);
    if (ret) {
        LOGE("parse sm2DecodeCipher ASN1 error, error code:%d", ret);
        if(listCert)
        {
            der_sequence_free(listCert);
            listCert = NULL;
        }
        return RETURN_INPUT_DATA_ERROR;
    }
    pB_asn1_list = listCert->child;
    if (NULL == pB_asn1_list || NULL == pB_asn1_list->next || 
        LTC_ASN1_INTEGER != pB_asn1_list->type || 
        LTC_ASN1_INTEGER != pB_asn1_list->next->type) {
        if(listCert)
        {
            der_sequence_free(listCert);
            listCert = NULL;
        }
        return RETURN_PARSE_STRUCT_ERROR;
    }

    tmpLen = pB_asn1_list->size;
    if (tmpLen < 32) {
        LOGE("len error 2, len:%u, should be > 32", tmpLen);
        if(listCert)
        {
            der_sequence_free(listCert);
            listCert = NULL;
        }
        return RETURN_INPUT_DATA_ERROR;
    }
    memcpy(pub_XY, (const char*)pB_asn1_list->data+(tmpLen-32), 32);

    pB_asn1_list = pB_asn1_list->next;
    if (NULL == pB_asn1_list || NULL == pB_asn1_list->next || 
        LTC_ASN1_INTEGER != pB_asn1_list->type || 
        LTC_ASN1_OCTET_STRING != pB_asn1_list->next->type) {
        if(listCert)
        {
            der_sequence_free(listCert);
            listCert = NULL;
        }
        return RETURN_PARSE_STRUCT_ERROR;
    }
    tmpLen = pB_asn1_list->size;
    if (tmpLen < 32) {
        LOGE("len error 2, len:%u, should be > 32", tmpLen);
        if(listCert)
        {
            der_sequence_free(listCert);
            listCert = NULL;
        }
        return RETURN_INPUT_DATA_ERROR;
    }
    memcpy(pub_XY+32, (const char*)pB_asn1_list->data+(tmpLen-32), 32);


    pB_asn1_list = pB_asn1_list->next;
    if (NULL == pB_asn1_list || LTC_ASN1_OCTET_STRING != pB_asn1_list->type || 
        32 != pB_asn1_list->size) {
        if(listCert)
        {
            der_sequence_free(listCert);
            listCert = NULL;
        }
        return RETURN_PARSE_STRUCT_ERROR;
    }
    memcpy(sm3hash, pB_asn1_list->data, pB_asn1_list->size);

    pB_asn1_list = pB_asn1_list->next;
    if (NULL == pB_asn1_list || LTC_ASN1_OCTET_STRING != pB_asn1_list->type) {
        if(listCert)
        {
            der_sequence_free(listCert);
            listCert = NULL;
        }
        return RETURN_PARSE_STRUCT_ERROR;
    }
    if (*ulCipherLen < pB_asn1_list->size) {
        *ulCipherLen = pB_asn1_list->size;
        if(listCert)
        {
            der_sequence_free(listCert);
            listCert = NULL;
        }
        return RETURN_BUFF_TO_SMALL_ERROR;
    }
    memcpy(Cipher, pB_asn1_list->data, pB_asn1_list->size);
    *ulCipherLen = pB_asn1_list->size;
    
    if(listCert)
    {
        der_sequence_free(listCert);
        listCert = NULL;
    }
    return ret;
}

//example:
//DECODE:67dvETXdA6q7M0Pi0pEUhDYXknEs4eYA5yOGHjywiDSAsFCRWj0hmwCAfZt82nTFZFpEZB72GLykpJbqJcFsW2Q=
//ENCODE:MEYCIQDrt28RNd0DqrszQ+LSkRSENheScSzh5gDnI4YePLCINAIhAICwUJFaPSGbAIB9m3zadMVkWkRkHvYYvKSkluolwWxb
int sm2EncodeSignature(unsigned char * derSig, unsigned int * ulderSigL, unsigned char sig[64])
{
    if (NULL == derSig || 0 == *ulderSigL) {
        LOGE("sm2EncodeSignature input param error!");
        return RETURN_INPUT_DATA_ERROR;
    }

    int ret = 0;
    unsigned char outtmp[80] = {0};
    unsigned int outtmpLen = sizeof(outtmp)/sizeof(outtmp[0]);
    
    unsigned char buff_R[33] = {0};
    unsigned int buff_RLen = sizeof(buff_R)/sizeof(unsigned char);
    unsigned char buff_S[33] = {0};
    unsigned int buff_SLen = sizeof(buff_S)/sizeof(unsigned char);

    //Integer:对于正数来说,最高位为1则多补一个0x00字节
    if (0x00 != (sig[0]&0x80)) {
        memcpy(buff_R+1, sig, 32);
        buff_RLen = 33;
    }
    else
    {
        memcpy(buff_R, sig, 32);
        buff_RLen = 32;
    }

    if (0x00 != (sig[32]&0x80)) {
        memcpy(buff_S+1, sig+32, 32);
        buff_SLen = 33;
    }
    else
    {
        memcpy(buff_S, sig+32, 32);
        buff_SLen = 32;
    }

    ltc_asn1_list alg[2];
    LTC_SET_ASN1(alg, 0, LTC_ASN1_INTEGER, &buff_R, buff_RLen);
    LTC_SET_ASN1(alg, 1, LTC_ASN1_INTEGER, &buff_S, buff_SLen);

    ret = der_encode_sequence(alg, 2, outtmp, &outtmpLen);
    if (ret) {
        LOGE("sm2 Encode signature error, ret:%d\n", ret);
        return RETURN_ENCODE_STRUCT_ERROR;
    }

    if (outtmpLen > *ulderSigL) {
        LOGE("sm2EncodeSignature buff too small, need len:%d, real len:%d", outtmpLen, *ulderSigL);
        ret = RETURN_BUFF_TO_SMALL_ERROR;
    }
    else{
        memcpy(derSig, outtmp, outtmpLen);
    }
    *ulderSigL = outtmpLen;

    return ret;
}

int sm2DecodeSignature(unsigned char sig[64], unsigned char * derSig, unsigned int ulderSigL)
{
    if (NULL == derSig) {
        LOGE("invalide parameters(s)");
        return RETURN_INPUT_DATA_ERROR;
    }
    
    int ret = 0;
    int len, padlen, trimlen;
    ltc_asn1_list *listCert = NULL;
    ltc_asn1_list *pB_asn1_list = NULL;
    memset(sig, 0, 64);

    do {
        ret = der_decode_sequence_flexi((const unsigned char*)derSig, &ulderSigL, &listCert, 0);
        if (ret) {
            LOGE("parse sm2DecodeSign ASN1 error, error code:%d", ret);
            ret = RETURN_INPUT_DATA_ERROR;
            break;
        }
        pB_asn1_list = listCert;

        if (NULL == pB_asn1_list->child || LTC_ASN1_INTEGER != pB_asn1_list->child->type) {
            ret = RETURN_PARSE_STRUCT_ERROR;
            break;
        }

        pB_asn1_list = pB_asn1_list->child;
        len = pB_asn1_list->size;
        if (len > 33) {
            LOGE("signature len error 1, len: %d, should not be over 33", len);
            ret = RETURN_INPUT_DATA_ERROR;
            break;
        }

        padlen = len < 32 ? (32 - len) : 0;
        trimlen = len > 32 ? 1 : 0;
        memcpy(sig + padlen, (unsigned char *)pB_asn1_list->data + trimlen, 32);
        
        pB_asn1_list = pB_asn1_list->next;
        if (NULL == pB_asn1_list || LTC_ASN1_INTEGER != pB_asn1_list->type) {
            ret = RETURN_PARSE_STRUCT_ERROR;
            break;
        }

        len = pB_asn1_list->size;
        if (len > 33) {
            LOGE("signature len error 2, len: %d, should not be over 33", len);
            ret = RETURN_INPUT_DATA_ERROR;
            break;
        }

        padlen = len < 32 ? (32 - len) : 0;
        trimlen = len > 32 ? 1 : 0;
        memcpy(sig + 32 + padlen, (unsigned char *)pB_asn1_list->data + trimlen, 32);
        
    } while (0);

    if (listCert) der_sequence_free(listCert); listCert = NULL;

    return ret;
}

int signatureAdapt(unsigned char *inputSign, unsigned int inputSignLen, 
                   unsigned char *outputSign, unsigned int *outputSignLen)
{
    if (*outputSignLen < 64 || outputSign == NULL) {
        printf("input parameter(s) invalid\n");
        return 1;
    }

    int ret = 0;

    if (inputSignLen == 64) {
        memcpy(outputSign, inputSign, 64);
        *outputSignLen = 64;
        return 0;
    }

    if (!(ret = sm2DecodeSignature(outputSign, inputSign, inputSignLen))) {
        *outputSignLen = 64;
        return 0;
    }

    printf("Unrecognized signature structure\n");
    return 1;
}

int pubkeyAdapt(unsigned char *inputPubkey, unsigned int inputPubkeyLen,
                unsigned char *outputPubkey, unsigned int *outputPubkeyLen)
{
    if (outputPubkey == NULL) {
        printf("input parameter(s) invalid\n");
        return 1;
    }

    int ret = 0;
    if (inputPubkeyLen == 64) {
        memcpy(outputPubkey, inputPubkey, 64);
        *outputPubkeyLen = 64;
        return 0;
    }

    if (!(ret = sm2DecodePubkey(outputPubkey, inputPubkey, inputPubkeyLen))) {
        *outputPubkeyLen = 64;
        return 0;
    }

    printf("Unrecognized sm2 public key structure\n");
    return 1;
}