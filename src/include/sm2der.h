//
//  sm2der.h
//  asn1_libTom
//
//  Created by ccit on 16/9/14.
//  Copyright © 2016年 ccit. All rights reserved.
//

#ifndef sm2der_h
#define sm2der_h

#include <stdio.h>
#include "asn1_util.h"

#ifdef __cplusplus
extern "C"{
#endif
    
//everywhere And everything is OK
int sm2EncodePubkey(unsigned char derPubkey[91], unsigned int * ulDerPubl,
                    unsigned char pub_XY[64]);
//OK
int sm2DecodePubkey(unsigned char pub_XY[64],
                    unsigned char * derPubkey, unsigned int ulDerPubl);

int sm2EncodePrikey(unsigned char * derPrikey, unsigned int * ulDerPrikl,
                    unsigned char randPrikey[32], unsigned char pub_XY[64]);
//ok
int sm2DecodePrikey(unsigned char sm2_prikey[32], unsigned char sm2_pubXY[64],
                    unsigned char * derPrikey, unsigned int ulderPrikeyLen);

//c1||c3||c2
int sm2EncodeCipher(unsigned char * SM2CipherDer, unsigned int * ulSM2CipherDerLen,
                    unsigned char * Cipher, unsigned int ulCipherLen,
                    unsigned char pub_XY[64], unsigned char sm3hash[32]);
int sm2DecodeCipher(unsigned char pub_XY[64], unsigned char sm3hash[32],
                    unsigned char * Cipher, unsigned int * ulCipherLen,
                    unsigned char * SM2CipherDer, unsigned int SM2CipherDerLen);

// R\S will always be positive
int sm2EncodeSignature(unsigned char * derSig, unsigned int * ulderSigL,
                       unsigned char sig[64]);
int sm2DecodeSignature(unsigned char sig[64],
                       unsigned char * derSig, unsigned int ulderSigL);
    
int signatureAdapt(unsigned char *inputSign, unsigned int inputSignLen, 
                   unsigned char *outputSign, unsigned int *outputSignLen);
int pubkeyAdapt(unsigned char *inputPubkey, unsigned int inputPubkeyLen,
                unsigned char *outputPubkey, unsigned int *outputPubkeyLen);

#ifdef __cplusplus
}
#endif


#endif /* sm2der_h */
