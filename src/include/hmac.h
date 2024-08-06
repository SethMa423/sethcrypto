#ifndef hmac_h
#define hmac_h

#include "hash.h"
#include "define.h"

#define HMAC_SUCCESS                                        0
#define HMAC_INIT_CTX_NULL                                  500
#define HMAC_INIT_ALGO_ERROR                                501
#define HMAC_INIT_KEY_NULL                                  502
#define HMAC_INIT_KEY_LEN_ERROR                             503
#define HMAC_UPDATE_CTX_NULL                                504
#define HMAC_UPDATE_INDATA_NULL                             505
#define HMAC_UPDATE_INDATA_LEN_ERROR                        506
#define HMAC_FINAL_CTX_NULL                                 507
#define HMAC_FINAL_MAC_NULL                                 508
#define HMAC_FINAL_MAC_LEN_NULL                             509

#ifdef __cplusplus
extern "C" {
#endif

typedef struct{
    int algo;                   //摘要算法标识
    hash_context hash_ctx;   //摘要运算过程变量结构体
    unsigned char key[64];      //HMac运算的密钥
}hmac_ctx_t;

/// HMac 初始化运算
/// @param ctx HMac运算过程变量结构体
/// @param algo 摘要算法标识
/// @param key Mac运算密钥
/// @param keyLen Mac运算密钥长度
/// @return 结果码
int hmac_init(IN hmac_ctx_t *ctx,
                 IN int algo,
                 IN const unsigned char *key,
                 IN unsigned int keyLen);

/// HMac 单组运算
/// @param ctx HMac运算过程变量结构体
/// @param inData 单组运算数据
/// @param dataLen 单组运算数据长度
/// @return 结果码
int hmac_update(IN hmac_ctx_t *ctx,
                   IN const unsigned char *inData,
                   IN unsigned int dataLen);

/// HMac 结束单组运算
/// @param ctx HMac运算过程变量结构体
/// @param mac Mac值
/// @param macLen Mac值长度
/// @return 结果码
int hmac_final(IN hmac_ctx_t *ctx,
                  OUT unsigned char *mac,
                  OUT unsigned int *macLen);

/// HMac运算
/// @param algo 摘要算法标识
/// @param inData 待运算数据
/// @param dataLen 待运算数据长度
/// @param key Mac运算密钥
/// @param keyLen Mac运算密钥长度
/// @param mac Mac值
/// @param macLen Mac值长度
/// @return 结果码
int hmac(IN int algo,
            IN const unsigned char *inData,
            IN unsigned int dataLen,
            IN const unsigned char *key,
            IN unsigned int keyLen,
            OUT unsigned char *mac,
            OUT unsigned int *macLen);

#ifdef __cplusplus
}
#endif

#endif

