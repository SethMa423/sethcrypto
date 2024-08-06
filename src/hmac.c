#include <string.h>
#include "hmac.h"

//HMAC_k(m) = H((k ^ opad), H((k ^ ipad), m))
#define IPAD    0x36
#define OPAD    0x5C

//HMac init
int hmac_init(IN hmac_ctx_t *ctx,
                 IN int algo,
                 IN const unsigned char *key,
                 IN unsigned int keyLen){
    
    if(ctx == NULL) return HMAC_INIT_CTX_NULL;
    if(algo != SM3 && algo != SHA1 && algo != SHA256) return HMAC_INIT_ALGO_ERROR;
    if(key == NULL) return HMAC_INIT_KEY_NULL;
    if(keyLen <= 0) return HMAC_INIT_KEY_LEN_ERROR;
    
    int i = 0,ret = HMAC_SUCCESS;
    unsigned int len = 0;
    //process key
    ctx->algo = algo;
    if (keyLen <= 64) {
        memcpy(ctx->key, key, keyLen);
        memset(ctx->key + keyLen, 0, 64 - keyLen);
    }else{
        ret = hash_init(&ctx->hash_ctx,algo);
        if(ret) return ret;
        ret = hash_update(&ctx->hash_ctx,key,keyLen);
        if(ret) return ret;
        ret = hash_final(&ctx->hash_ctx,ctx->key,&len);
        if(ret) return ret;
        memset(ctx->key + len, 0, 64-len);
    }
    for (i = 0; i < 64; i++) ctx->key[i] ^= IPAD;
    ret = hash_init(&ctx->hash_ctx,algo);
    if(ret) return ret;
    return hash_update(&ctx->hash_ctx, ctx->key, 64);
}

//HMac update
int hmac_update(IN hmac_ctx_t *ctx,
                   IN const unsigned char *inData,
                   IN unsigned int dataLen){
    
    if(ctx == NULL) return HMAC_UPDATE_CTX_NULL;
    if(inData == NULL) return HMAC_UPDATE_INDATA_NULL;
    if(dataLen <= 0) return HMAC_UPDATE_INDATA_LEN_ERROR;
    
    return hash_update(&ctx->hash_ctx, inData, dataLen);
}

//HMac final
int hmac_final(IN hmac_ctx_t *ctx,
                   OUT unsigned char *mac,
                   OUT unsigned int *macLen){
    
    if(ctx == NULL) return HMAC_FINAL_CTX_NULL;
    if(mac == NULL) return HMAC_FINAL_MAC_NULL;
    if(macLen == NULL) return HMAC_FINAL_MAC_LEN_NULL;
    
    int i = 0, ret = HMAC_SUCCESS;
    for(i = 0; i < 64; i++) ctx->key[i] ^= (IPAD ^ OPAD);
    ret = hash_final(&ctx->hash_ctx, mac, macLen);
    if(ret) return ret;
    ret = hash_init(&ctx->hash_ctx, ctx->algo);
    if(ret) return ret;
    ret = hash_update(&ctx->hash_ctx, ctx->key, 64);
    if(ret) return ret;
    ret = hash_update(&ctx->hash_ctx, mac, *macLen);
    if(ret) return ret;
    return hash_final(&ctx->hash_ctx, mac, macLen);
}

//HMac
int hmac(IN int algo,
            IN const unsigned char *inData,
            IN unsigned int dataLen,
            IN const unsigned char *key,
            IN unsigned int keyLen,
            OUT unsigned char *mac,
            OUT unsigned int *macLen){
    
    int ret = HMAC_SUCCESS;
    hmac_ctx_t ctx;
    ret = hmac_init(&ctx,algo,key,keyLen);
    if(ret) return ret;
    ret = hmac_update(&ctx,inData,dataLen);
    if(ret) return ret;
    return hmac_final(&ctx,mac,macLen);
}
