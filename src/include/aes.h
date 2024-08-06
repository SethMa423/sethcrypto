#ifndef aes_h
#define aes_h

#include <stdio.h>
#include <stdint.h>
#include "define.h"

#ifdef __cplusplus
extern "C" {
#endif

/// 获取AES加密密钥和解密密钥
/// @param key AES密钥原材料
/// @param keylen AES密钥原材料长度
/// @param ek AES加密密钥
/// @param dk AES解密密钥
/// @param Nr 密钥轮数
void aes_key(IN const unsigned char *key,
                IN unsigned int keylen,
                OUT uint32_t *ek,
                OUT uint32_t *dk,
                OUT int *Nr);

/// AES加密
/// @param inData 待加密数据
/// @param outData 密文数据
/// @param ek 加密密钥
/// @param Nr 加密轮数
void aes_enc(IN const unsigned char *inData,
                OUT unsigned char *outData,
                IN const uint32_t *ek,
                IN int Nr);

/// AES解密
/// @param inData 待解密数据
/// @param outData 明文数据
/// @param dk 解密密钥
/// @param Nr 解密轮数
void aes_dec(IN const unsigned char *inData,
                OUT unsigned char *outData,
                IN const uint32_t *dk,
                IN int Nr);

#ifdef __cplusplus
}
#endif

#endif
