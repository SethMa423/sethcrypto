#include <string.h>
#include "symmetric.h"
#include "sm4.h"
#include "aes.h"
#include "des.h"
#include "sm1.h"


//Add PKCS5 padding
void add_pkcs5_padding(IN int blocks,
                          IN const unsigned char *inData,
                          IN unsigned int inDataLen,
                          OUT unsigned char *outData,
                          OUT unsigned int *outDataLen){
    
    unsigned int padlen = inDataLen % blocks;
    if(0 == padlen){
        memcpy(outData,inData,inDataLen);
        memset(outData + inDataLen, blocks, blocks);
        *outDataLen = inDataLen + blocks;
    }else{
        memcpy(outData,inData,inDataLen);
        memset(outData + inDataLen, blocks - padlen, blocks - padlen);
        *outDataLen = inDataLen + blocks - padlen;
    }
}

//Remove PKCS5 padding
int remove_pkcs5_padding(IN int blocks,
                            IN const unsigned char *inData,
                            IN unsigned int inDataLen,
                            OUT unsigned char *outData,
                            OUT unsigned int *outDataLen){
    
    unsigned int rl = (unsigned int)inData[inDataLen - 1];
    if(rl > blocks || rl <= 0) return REMOVE_PKCS5_PADDING_ERROR;
    *outDataLen = inDataLen - rl;
    memcpy(outData, inData, *outDataLen);
    return SYM_SUCCESS;
}

//symmetric encrypt
int sym_encrypt(IN int algo,
                   IN int mode,
                   IN const unsigned char *key,
                   IN unsigned int keyLen,
                   IN const char *IV,
                   IN unsigned int IVLen,
                   IN unsigned int padding,
                   IN const unsigned char *inData,
                   IN unsigned int inDataLen,
                   OUT unsigned char *outData,
                   OUT unsigned int *outDataLen){
    
    unsigned int outLen = 0;
    sym_ctx ctx;
    int res;
    if (algo == SM1) {
        res = Crypt_Enc_Block_SM1((unsigned char *)inData, inDataLen, outData, outDataLen, 
                                  (unsigned char *)key, keyLen);
    }
    else {
        res = sym_init(&ctx, algo, mode, key, keyLen, IV, IVLen, padding, ENC);
        if(res) return res;
        res = sym_update(&ctx, inData, inDataLen, outData, outDataLen);
        if(res) return res;
        res = sym_final(&ctx, outData + *outDataLen, &outLen);
        *outDataLen += outLen;
    }
    return res;
}

//symmetric decrypt
int sym_decrypt(IN int algo,
                   IN int mode,
                   IN const unsigned char *key,
                   IN unsigned int keyLen,
                   IN const char *IV,
                   IN unsigned int IVLen,
                   IN unsigned int padding,
                   IN const unsigned char *inData,
                   IN unsigned int inDataLen,
                   OUT unsigned char *outData,
                   OUT unsigned int *outDataLen){
    
    unsigned int outLen = 0;
    sym_ctx ctx;
    int res;
    if (algo == SM1) {
        res = Crypt_Dec_Block_SM1((unsigned char *)inData, inDataLen, outData, outDataLen, 
                                  (unsigned char *)key, keyLen);
    }
    else {
        res = sym_init(&ctx, algo, mode, key, keyLen, IV, IVLen, padding, DEC);
        if(res) return res;
        res = sym_update(&ctx, inData, inDataLen, outData, outDataLen);
        if(res) return res;
        res = sym_final(&ctx, outData + *outDataLen, &outLen);
        *outDataLen += outLen;
    }
    return res;
}

//symmetric init
int sym_init(IN sym_ctx *ctx,
                IN int algo,
                IN int mode,
                IN const unsigned char *key,
                IN unsigned int keyLen,
                IN const char *IV,
                IN unsigned int IVLen,
                IN unsigned int padding,
                IN unsigned int encFlag){
    
    if(ctx == NULL) return SYM_INIT_CONTEXT_NULL;
    if(key == NULL) return SYM_INIT_KEY_NULL;
    if(algo != SM4 && algo != DES && algo != AES && algo != DES3) return SYM_INIT_ALGO_ERROR;
    if(mode != ECB && mode != CBC && mode != CFB && mode != OFB) return SYM_INIT_MODE_ERROR;
    if((algo == SM4) && (keyLen != 16)) return SYM_INIT_SM4_KEYLEN_ERROR;
    if((algo == AES) && (keyLen != 16 && keyLen != 24 && keyLen != 32)) return SYM_INIT_AES_KEYLEN_ERROR;
    if((algo == DES) && (keyLen != 8)) return SYM_INIT_DES_KEYLEN_ERROR;
    if((algo == DES3) && (keyLen != 24)) return SYM_INIT_3DES_KEYLEN_ERROR;
    
    if(padding != 0 && padding != 1) padding = 1;
    ctx->mode = mode;
    ctx->encFlag = encFlag;
    ctx->padding = padding;
    ctx->left_num = 0;
    memset(ctx->left, 0, 16);
    memset(ctx->iv, 0, 16);
    if(IV) memcpy(ctx->iv, IV, (IVLen > 16) ? 16 : IVLen);
    
    if(algo == SM4){
        sm4_key(key, ctx->ek, ctx->dk);
        ctx->encfunc = sm4_enc;
        ctx->decfunc = sm4_dec;
        ctx->groupLen = 16;
    }else if(algo == AES){
        aes_key(key, keyLen, ctx->ek, ctx->dk, &ctx->Nr);
        ctx->encfunc = aes_enc;
        ctx->decfunc = aes_dec;
        ctx->groupLen = 16;
    }else if(algo == DES){
        des_key(key, ctx->ek, ctx->dk);
        ctx->encfunc = des_enc;
        ctx->decfunc = des_dec;
        ctx->groupLen = 8;
    }else if(algo == DES3){
        des3_key(key, ctx->ek, ctx->dk);
        ctx->encfunc = des3_enc;
        ctx->decfunc = des3_dec;
        ctx->groupLen = 8;
    }else return SYM_INIT_ALGO_ERROR;
    return SYM_SUCCESS;
}

//symmetric update
int sym_update(IN sym_ctx *ctx,
                  IN const unsigned char *inData,
                  IN unsigned int inDataLen,
                  OUT unsigned char *outData,
                  OUT unsigned int *outDataLen){
    
    if(ctx == NULL) return SYM_UPDATE_CONTEXT_NULL;
    if(inData == NULL) return SYM_UPDATE_INDATA_NULL;
    if(outData == NULL) return SYM_UPDATE_OUTDATA_NULL;
    if(outDataLen == NULL) return SYM_UPDATE_OUTDATA_LEN_NULL;
    if(inDataLen <= 0) return SYM_UPDATE_INDATA_LEN_LT0;
    if(ctx->padding == 0
       && inDataLen % ctx->groupLen != 0
       && (ctx->mode == ECB || ctx->mode == CBC)) return SYM_UPDATE_INDATA_GROUPLEN_ERROR;
    
    int i = 0;
    uint8_t flag = 0;
    unsigned int fill_num = 0;
    unsigned char tmp[16] = {0};
    *outDataLen = 0;
    
    if(ctx->left_num){
        fill_num = ctx->groupLen - ctx->left_num;
        if(inDataLen < fill_num){
            memcpy(ctx->left + ctx->left_num, inData, inDataLen);
            ctx->left_num += inDataLen;
            return SYM_SUCCESS;
        }else{
            memcpy(ctx->left + ctx->left_num, inData, fill_num);
            if(ctx->mode == ECB){
                if((fill_num == inDataLen) && (ctx->encFlag == 0)){
                    ctx->left_num += inDataLen;
                    return SYM_SUCCESS;
                }
                if(ctx->encFlag) ctx->encfunc((const unsigned char *)ctx->left, outData, ctx->ek, ctx->Nr);
                else ctx->decfunc((const unsigned char *)ctx->left, outData, ctx->dk, ctx->Nr);
            }else if(ctx->mode == CBC){
                if(ctx->encFlag){
                    for(i = 0; i < ctx->groupLen; i++) ctx->iv[i] ^= ctx->left[i];
                    ctx->encfunc((const unsigned char *)ctx->iv, outData, ctx->ek, ctx->Nr);
                    memcpy(ctx->iv, outData, ctx->groupLen);
                }else{
                    if(fill_num == inDataLen){
                        ctx->left_num += inDataLen;
                        return SYM_SUCCESS;
                    }
                    ctx->decfunc(ctx->left, tmp, ctx->dk, ctx->Nr);
                    for(i = 0; i < ctx->groupLen; i++) outData[i] = tmp[i] ^ ctx->iv[i];
                    memcpy(ctx->iv, ctx->left, ctx->groupLen);
                }
            }else if(ctx->mode == CFB){
                ctx->encfunc((const unsigned char *)ctx->iv, tmp, ctx->ek, ctx->Nr);
                for(i = 0; i < ctx->groupLen; i++) outData[i] = ctx->left[i] ^ tmp[i];
                ctx->encFlag ? memcpy(ctx->iv, outData, ctx->groupLen) : memcpy(ctx->iv, ctx->left, ctx->groupLen);
            }else if(ctx->mode == OFB){
                ctx->encfunc((const unsigned char *)ctx->iv, tmp, ctx->ek, ctx->Nr);
                for(i = 0; i < ctx->groupLen; i++) outData[i] = ctx->left[i] ^ tmp[i];
                memcpy(ctx->iv, tmp, ctx->groupLen);
            }
            inData      += fill_num;
            inDataLen   -= fill_num;
            outData     += ctx->groupLen;
            *outDataLen += ctx->groupLen;
        }
    }
    flag = (!(ctx->encFlag) && (ctx->mode == ECB || ctx->mode == CBC));
    while(flag ? inDataLen > ctx->groupLen : inDataLen >= ctx->groupLen){
        if(ctx->mode == ECB){
            if(ctx->encFlag) ctx->encfunc(inData, outData, ctx->ek, ctx->Nr);
            else ctx->decfunc(inData, outData, ctx->dk, ctx->Nr);
        }else if(ctx->mode == CBC){
            if(ctx->encFlag){
                for(i = 0; i < ctx->groupLen; i++) ctx->iv[i] ^= inData[i];
                ctx->encfunc((const unsigned char *)ctx->iv, outData, ctx->ek, ctx->Nr);
                memcpy(ctx->iv, outData, ctx->groupLen);
            }else{
                ctx->decfunc(inData, tmp, ctx->dk, ctx->Nr);
                for (i = 0; i < ctx->groupLen; i++) outData[i] = tmp[i] ^ ctx->iv[i];
                memcpy(ctx->iv, inData, ctx->groupLen);
            }
        }else if(ctx->mode == CFB){
            ctx->encfunc((const unsigned char *)ctx->iv, tmp, ctx->ek, ctx->Nr);
            for(i = 0; i < ctx->groupLen; i++) outData[i] = inData[i] ^ tmp[i];
            ctx->encFlag ? memcpy(ctx->iv, outData, ctx->groupLen) : memcpy(ctx->iv, inData, ctx->groupLen);
        }else if(ctx->mode == OFB){
            ctx->encfunc((const unsigned char *)ctx->iv, tmp, ctx->ek, ctx->Nr);
            for(i = 0; i < ctx->groupLen; i++) outData[i] = inData[i] ^ tmp[i];
            memcpy(ctx->iv, tmp, ctx->groupLen);
        }
        inData      += ctx->groupLen;
        inDataLen   -= ctx->groupLen;
        outData     += ctx->groupLen;
        *outDataLen += ctx->groupLen;
    }
    ctx->left_num = inDataLen;
    if(inDataLen) memcpy(ctx->left, inData, inDataLen);
    return SYM_SUCCESS;
}

//symmetric final
int sym_final(IN sym_ctx *ctx,
                 OUT unsigned char *outData,
                 OUT unsigned int *outDataLen){
    
    if(ctx == NULL) return SYM_FINAL_CONTEXT_NULL;
    if(outData == NULL) return SYM_FINAL_OUTDATA_NULL;
    if(outDataLen == NULL) return SYM_FINAL_OUTDATA_LEN_NULL;
    
    int i = 0;
    unsigned char pad[16] = {0};
    unsigned int padLen = 16;
    unsigned char tmp[16] = {0};
    
    if(ctx->mode == ECB){
        if(ctx->encFlag){
            if(ctx->left_num >= ctx->groupLen) return SYM_ECB_FINAL_LEFT_GT_GROUPLEN;
            if(ctx->padding){
                add_pkcs5_padding(ctx->groupLen, ctx->left, ctx->left_num, pad, &padLen);
                ctx->encfunc(pad, outData, ctx->ek, ctx->Nr);
                *outDataLen = ctx->groupLen;
            }else{
                if(ctx->left_num != 0) return SYM_ECB_FINAL_LEFT_NOT_QT_0;
                *outDataLen = 0;
            }
        }else{
            if(ctx->left_num != ctx->groupLen) return SYM_ECB_FINAL_LEFT_NOT_QT_GROUPLEN;
            if(ctx->padding){
                ctx->decfunc(ctx->left, pad, ctx->dk, ctx->Nr);
                return remove_pkcs5_padding(ctx->groupLen, pad, ctx->groupLen, outData, outDataLen);
            }else{
                ctx->decfunc(ctx->left, outData, ctx->dk, ctx->Nr);
                *outDataLen = ctx->groupLen;
            }
        }
    }else if(ctx->mode == CBC){
        if(ctx->encFlag){
            if(ctx->left_num >= ctx->groupLen) return SYM_CBC_FINAL_LEFT_GT_GROUPLEN;
            if(ctx->padding){
                add_pkcs5_padding(ctx->groupLen, ctx->left, ctx->left_num, pad, &padLen);
                for(i = 0; i < ctx->groupLen; i++) ctx->iv[i] ^= pad[i];
                ctx->encfunc(ctx->iv, outData, ctx->ek, ctx->Nr);
                *outDataLen = ctx->groupLen;
            }else{
                if(ctx->left_num != 0) return SYM_CBC_FINAL_LEFT_NOT_QT_0;
                *outDataLen = 0;
            }
        }else{
            if(ctx->left_num != ctx->groupLen) return SYM_CBC_FINAL_LEFT_NOT_QT_GROUPLEN;
            ctx->decfunc(ctx->left, tmp, ctx->dk, ctx->Nr);
            if(ctx->padding){
                for(i = 0; i < ctx->groupLen; i++) pad[i] = tmp[i] ^ ctx->iv[i];
                return remove_pkcs5_padding(ctx->groupLen, pad, ctx->groupLen, outData, outDataLen);
            }else{
                for(i = 0; i < ctx->groupLen; i++) outData[i] = tmp[i] ^ ctx->iv[i];
                *outDataLen = ctx->groupLen;
            }
        }
    }else{
        if(ctx->left_num){
            ctx->encfunc((const unsigned char *)ctx->iv, tmp, ctx->ek, ctx->Nr);
            for(i = 0; i < ctx->left_num; i++) outData[i] = ctx->left[i] ^ tmp[i];
        }
        ctx->feedBackLen = ctx->left_num;
        *outDataLen = ctx->left_num;
    }
    return SYM_SUCCESS;
}
