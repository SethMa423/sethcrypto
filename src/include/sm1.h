#ifndef __CRYPTO_SM1_H__
#define __CRYPTO_SM1_H__

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define SM1_ENCRYPT     1
#define SM1_DECRYPT     0

#define SM1_KEY_LENGTH  16
#define SM1_BLOCK_SIZE  16

#ifdef __cplusplus
extern "C" {
#endif

/*
参数说明：
    1.  input:待加密或待解密的数据（明文、密文）
    2.  in_len:当前输入数据input的数据长度
    3.  output:通过运算加密或解密的输出结果（密文、明文）
    4.  out_len:输出结果的数据长度
    5.  key:加密或解密秘钥
    6.  keylen:秘钥长度
功能说明：当前接口为SM1算法ECB模式下的加解密接口，算法加密完成返回：
    1.  output输出值
    2.  成功标志：0
*/
int Crypt_Enc_Block_SM1(unsigned char *input, int in_len, unsigned char *output, int *out_len, unsigned char *key, int keylen);
int Crypt_Dec_Block_SM1(unsigned char *input, int in_len, unsigned char *output, int *out_len, unsigned char *key, int keylen);

#ifdef __cplusplus
}
#endif

#endif
