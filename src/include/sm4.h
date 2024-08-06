#ifndef sm4_h
#define sm4_h

#include <stdint.h>
#include "define.h"

#ifdef __cplusplus
extern "C" {
#endif

/// 获取SM4密钥
/// @param key SM4密钥原材料
/// @param ek 加密密钥
/// @param dk 解密密钥
void sm4_key(IN const unsigned char *key,
                OUT uint32_t *ek,
                OUT uint32_t *dk);

/// SM4加密
/// @param inData 待加密数据
/// @param outData 密文数据
/// @param rk 加密密钥
/// @param Nr 加密轮数(随便传)
void sm4_enc(IN const unsigned char *inData,
                OUT unsigned char *outData,
                IN const uint32_t *rk,
                IN int Nr);

/// SM4解密
/// @param inData 待解密的密文数据
/// @param outData 明文数据
/// @param rk 解密密钥
/// @param Nr 加密轮数(随便传)
void sm4_dec(IN const unsigned char *inData,
                OUT unsigned char *outData,
                IN const uint32_t *rk,
                IN int Nr);

#ifdef __cplusplus
}
#endif

#endif
