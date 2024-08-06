#ifndef symmetric_h
#define symmetric_h

#include <stdint.h>
#include "define.h"

#define SYM_SUCCESS                                         0
#define SYM_INIT_CONTEXT_NULL                               7000
#define SYM_INIT_ALGO_ERROR                                 7001
#define SYM_INIT_MODE_ERROR                                 7002
#define SYM_INIT_KEY_NULL                                   7003
#define SYM_INIT_SM4_KEYLEN_ERROR                           7004
#define SYM_INIT_AES_KEYLEN_ERROR                           7005
#define SYM_INIT_DES_KEYLEN_ERROR                           7006
#define SYM_INIT_3DES_KEYLEN_ERROR                          7007
#define SYM_UPDATE_CONTEXT_NULL                             7008
#define SYM_UPDATE_INDATA_NULL                              7009
#define SYM_UPDATE_OUTDATA_NULL                             7010
#define SYM_UPDATE_OUTDATA_LEN_NULL                         7011
#define SYM_UPDATE_INDATA_LEN_LT0                           7012
#define SYM_UPDATE_INDATA_GROUPLEN_ERROR                    7013
#define SYM_FINAL_CONTEXT_NULL                              7014
#define SYM_FINAL_OUTDATA_NULL                              7015
#define SYM_FINAL_OUTDATA_LEN_NULL                          7016
#define REMOVE_PKCS5_PADDING_ERROR                          7017
#define SYM_ECB_FINAL_LEFT_GT_GROUPLEN                      7018
#define SYM_ECB_FINAL_LEFT_NOT_QT_0                         7019
#define SYM_ECB_FINAL_LEFT_NOT_QT_GROUPLEN                  7020
#define SYM_CBC_FINAL_LEFT_GT_GROUPLEN                      7021
#define SYM_CBC_FINAL_LEFT_NOT_QT_0                         7022
#define SYM_CBC_FINAL_LEFT_NOT_QT_GROUPLEN                  7023

#ifdef __cplusplus
extern "C" {
#endif

#define ENC              1   //加密
#define DEC              0   //解密
#define PKCS5_PADDING    1   //pkcs5填充
#define NO_PADDING       0   //无填充
#define ECB  111     //Electronic Code Book(电子密码本模式)
#define CBC  112     //Cipher Block Chaining(加密块链模式)
#define CFB  113     //Cipher Feedback Mode(加密反馈模式)
#define OFB  114     //Output Feedback Mode(输出反馈模式)
#define SM4  222     //SM4算法标识
#define AES  333     //AES算法标识
#define DES  444     //DES算法标识
#define DES3 555     //3DES算法标识
#define SM1  666     //SM1算法标识

typedef void(*sym_func)(const unsigned char *, unsigned char *, const uint32_t *, int);

typedef struct {
    uint32_t ek[96];            //加密密钥
    uint32_t dk[96];            //解密密钥
    int Nr;                     //密钥轮数
    int groupLen;               //单组数据长度
    unsigned int keylen;        //对称密钥长度
    sym_func decfunc;        //加密函数指针
    sym_func encfunc;        //解密函数指针
    unsigned char left[16];     //单次分组剩余字节数组
    unsigned int left_num;      //单次分组剩余字节数
    unsigned char iv[16];       //初始化向量
    unsigned int mode;          //encrpt mode,ECB:111,CBC:112,CFB:113,OFB:114
    unsigned int padding;       //1:pkcs5 padding, 0:no padding
    unsigned int encFlag;       //1:encrypt, 0:decrypt
    unsigned int feedBackLen;   //Feed back value length
}sym_ctx;

/// 对称加密
/// @param algo 加密算法标识
/// @param mode 对称加密模式(ECB:111,CBC:112,CFB:113,OFB:114)
/// @param key 对称密钥
/// @param keyLen 对称密钥长度
/// @param IV 对称运算初始向量(ECB模式可为空)
/// @param IVLen 对称运算初始向量长度
/// @param padding 是否有pkcs5填充,PKCS5_PADDING:pkcs5填充,NO_PADDING:无填充
/// @param inData 待加密数据
/// @param inDataLen 待加密数据长度
/// @param outData 密文数据
/// @param outDataLen 密文数据长度指针
/// @return 结果码
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
                   OUT unsigned int *outDataLen);

/// 对称解密
/// @param algo 加密算法标识
/// @param mode 对称加密模式(ECB:111,CBC:112,CFB:113,OFB:114)
/// @param key 对称密钥
/// @param keyLen 对称密钥长度
/// @param IV 对称运算初始向量(ECB模式可为空)
/// @param IVLen 对称运算初始向量长度
/// @param padding 是否有pkcs5填充,PKCS5_PADDING:pkcs5填充,NO_PADDING:无填充
/// @param inData 待加密数据
/// @param inDataLen 待加密数据长度
/// @param outData 密文数据
/// @param outDataLen 密文数据长度指针
/// @return 结果码
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
                   OUT unsigned int *outDataLen);

/// 对称运算初始化
/// @param ctx 对称运算过程变量结构体
/// @param algo 加密算法标识
/// @param mode 对称运算模式(ECB:111,CBC:112,CFB:113,OFB:114)
/// @param key 对称密钥
/// @param keyLen 对称密钥长度
/// @param IV 对称运算初始向量(ECB模式可为空)
/// @param IVLen 对称运算初始向量长度
/// @param padding 是否有pkcs5填充,PKCS5_PADDING:pkcs5填充,NO_PADDING:无填充
/// @param encFlag 加密标识,ENC:加密,DEC:解密
/// @return 结果码
int sym_init(IN sym_ctx *ctx,
                IN int algo,
                IN int mode,
                IN const unsigned char *key,
                IN unsigned int keyLen,
                IN const char *IV,
                IN unsigned int IVLen,
                IN unsigned int padding,
                IN unsigned int encFlag);

/// 对称分组运算
/// @param ctx 对称运算过程变量结构体
/// @param inData 单组对称运算数据
/// @param inDataLen 单组对称运算数据长度
/// @param outData 单组对称运算结果
/// @param outDataLen 单组对称运算结果长度指针
/// @return 结果码
int sym_update(IN sym_ctx *ctx,
                  IN const unsigned char *inData,
                  IN unsigned int inDataLen,
                  OUT unsigned char *outData,
                  OUT unsigned int *outDataLen);

/// 对称分组运算结束
/// @param ctx 对称运算过程变量结构体
/// @param outData 最后一组对称运算结果
/// @param outDataLen 最后一组对称运算结果长度指针
/// @return 结果码
int sym_final(IN sym_ctx *ctx,
                 OUT unsigned char *outData,
                 OUT unsigned int *outDataLen);

#ifdef __cplusplus
}
#endif

#endif

