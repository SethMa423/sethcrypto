#ifndef des_h
#define des_h

#include <stdint.h>
#include "define.h"

#ifdef __cplusplus
extern "C" {
#endif

/// 获取DES加密密钥和解密密钥
/// @param key DES密钥原材料
/// @param ek DES加密密钥
/// @param dk DES解密密钥
void des_key(IN const unsigned char *key,
                OUT uint32_t *ek,
                OUT uint32_t *dk);

/// DES加密
/// @param inData 待加密数据
/// @param outData 密文数据
/// @param ek 加密密钥
/// @param Nr 加密轮数
void des_enc(IN const unsigned char *inData,
                OUT unsigned char *outData,
                IN const uint32_t *ek,
                IN int Nr);

/// AES解密
/// @param inData 待解密数据
/// @param outData 明文数据
/// @param dk 解密密钥
/// @param Nr 加密轮数
void des_dec(IN const unsigned char *inData,
                OUT unsigned char *outData,
                IN const uint32_t *dk,
                IN int Nr);

/// 获取3DES加密密钥和解密密钥
/// @param key 3DES密钥原材料
/// @param ek 3DES加密密钥
/// @param dk 3DES解密密钥
void des3_key(IN const unsigned char *key,
                OUT uint32_t *ek,
                OUT uint32_t *dk);

/// 3DES加密
/// @param inData 待加密数据
/// @param outData 密文数据
/// @param ek 加密密钥
/// @param Nr 加密轮数
void des3_enc(IN const unsigned char *inData,
                 OUT unsigned char *outData,
                 IN const uint32_t *ek,
                 IN int Nr);

/// 3DES解密
/// @param inData 待解密数据
/// @param outData 明文数据
/// @param dk 解密密钥
/// @param Nr 加密轮数
void des3_dec(IN const unsigned char *inData,
                 OUT unsigned char *outData,
                 IN const uint32_t *dk,
                 IN int Nr);
    
#ifdef __cplusplus
}
#endif

#endif
