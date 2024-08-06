#ifndef sm2_tool_h
#define sm2_tool_h

#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#include "hash.h"
#include "random.h"
#include "my_math.h"
#include "tool.h"

#define SM2_TOOL_SUCCESS                                    0
#define SM2_MP_2_BIN_TOO_LONG                               8000
#define SM2_CHECK_POINT_ZERO                                8001
#define SM2_CHECK_POINT_INVALID                             8002
#define SM2_CHECK_POINT_IS_NOT_ON_CURVE                     8003
#define SM2_CHECK_POINT_P_NULL                              8004
#define SM2_CHECK_POINT_P_LEN_ERROR                         8005
#define SM3_CORE_PROGRESS_XLEN_NOT_QT_32                    8006
#define SM3_CORE_PROGRESS_YLEN_NOT_QT_32                    8007
#define SM2_SPLIT_KEY_PRIKEY_NULL                           8008
#define SM2_SPLIT_KEY_PRIKEY_LEN_ERROR                      8009
#define SM2_SPLIT_KEY_PUBKEY_NULL                           8010
#define SM2_SPLIT_KEY_PUBKEY_LEN_ERROR                      8011
#define SM2_SPLIT_KEY_SIGN_KEY_NULL                         8012
#define SM2_SPLIT_KEY_ENC_KEY_NULL                          8013
#define CHECK_KEYPAIR_TX_LEN_NOT_QT_32                      8014
#define CHECK_KEYPAIR_TY_LEN_NOT_QT_32                      8015
#define CHECK_KEYPAIR_FAILED                                8016
#define SM2_SPLIT_KEY_T3_LEN_NOT_QT_32                      8017
#define SM2_SPLIT_KEY_W2_LEN_NOT_QT_32                      8018
#define SM2_SPLIT_KEY_W3_LEN_NOT_QT_32                      8019
#define SET_DEVICE_FACTOR_PKEY_NULL                         8020
#define SET_DEVICE_FACTOR_F2_NULL                           8021
#define SET_DEVICE_FACTOR_F4_NULL                           8022
#define SET_DEVICE_FACTOR_F6_NULL                           8023
#define SET_PIN_FACTOR_PKEY_NULL                            8024
#define SET_PIN_FACTOR_D1_NULL                              8025
#define SET_PIN_FACTOR_D5_NULL                              8026
#define SET_PIN_FACTOR_T5_NULL                              8027
#define SM2_TOOL_MEM_ALLOC_ERROR                            8028

#ifdef __cplusplus
extern "C" {
#endif

#define FAST 1
#define NO_HASH      1   //函数外部做摘要运算
#define WITH_HASH    0   //函数内部做摘要运算
#define CHECK(x) if(x) goto END

typedef struct sm2_enc_key{
    unsigned int priKeyCipherLen;       //private key cipher length
    unsigned char priKeyCipher[256];    //private key cipher
    unsigned int symKeyCipherLen;       //symKey cipher length
    unsigned char symKeyCipher[256];    //symKey cipher
    unsigned int pubKeyLength;          //encrypt public key length
    unsigned char pubKey[128];          //encrypt public key
    unsigned char check[32];            //check bits
}sm2_enc_key, *sm2_enc_pkey;

/// 获取标准参数
/// @param mp_a SM2曲线参数a
/// @param mp_b SM2曲线参数b
/// @param mp_n 基点G的阶
/// @param mp_p 大素数
/// @param mp_Xg 基点G的x坐标
/// @param mp_Yg 基点G的y坐标
/// @param gp 大数库运算参数
/// @return 结果码
int std_param(OUT my_pbig mp_a,
              OUT my_pbig mp_b,
              OUT my_pbig mp_n,
              OUT my_pbig mp_p,
              OUT my_pbig mp_Xg,
              OUT my_pbig mp_Yg,
              IN my_gp *gp);

/// 获取不大于基点G的阶数的随机数
/// @param rand_k 随机数
/// @param mp_n 基点G的阶数
/// @param gp 大数库运算参数
/// @return 结果码
int get_random_key(IN my_pbig rand_k,
                   IN my_pbig mp_n,
                   IN my_gp *gp);

/// 将大数转换成无符号的字符数组
/// @param bin 字符数组
/// @param binLen 字符数组长度
/// @param mp_src 大数
/// @param gp 大数库运算参数
/// @return 结果码
int mp_2_bin(OUT unsigned char *bin,
             OUT unsigned int *binLen,
             IN my_pbig mp_src,
             IN my_gp *gp);

/// 校验点是否在曲线上
/// @param mp_X 点的x坐标
/// @param mp_Y 点的y坐标
/// @param mp_a 椭圆曲线参数a
/// @param mp_b 椭圆曲线参数b
/// @param mp_p 大素数
/// @param gp 大数库运算参数
/// @return 结果码
int check_point(IN my_pbig mp_X,
                IN my_pbig mp_Y,
                IN my_pbig mp_a,
                IN my_pbig mp_b,
                IN my_pbig mp_p,
                IN my_gp *gp);

/// 校验点是否在曲线上
/// @param point 待校验的点
/// @param pointLen 点的长度
/// @return 结果码
int check_byte_point(IN unsigned char *point,
                     IN unsigned int pointLen);

/// SM2签名预处理ZA
/// @param za 预处理结果ZA
/// @param userID 用户标识
/// @param IDLen 用户表示长度
/// @param mp_XA 公钥x坐标
/// @param mp_YA 公钥y坐标
/// @param gp 大数库运算参数
/// @return 结果码
int sm3_core_progress(OUT unsigned char za[32],
                      IN unsigned char *userID,
                      IN unsigned int IDLen,
                      IN my_pbig mp_XA,
                      IN my_pbig mp_YA,
                      IN my_gp *gp);

/// SM2签名预处理ZA
/// @param za 预处理结果ZA
/// @param pubkey 用户公钥
/// @param userID 用户标识
/// @param IDLen 用户标识长度
/// @return 结果码
int sm3_byte_progress(OUT unsigned char za[32],
                      IN unsigned char pubkey[64],
                      IN unsigned char *userID,
                      IN unsigned int IDLen);

/// SM2签名预处理
/// @param e 预处理结果
/// @param eLen 预处理结果长度
/// @param src 签名原文
/// @param srcLen 签名原文长度
/// @param userID 用户标识
/// @param IDLen 用户标识长度
/// @param mp_XA 公钥x坐标
/// @param mp_YA 公钥y坐标
/// @param gp 大数库运算参数
/// @return 结果码
int sm3_progress(OUT unsigned char *e,
                 OUT unsigned int *eLen,
                 IN unsigned char *src,
                 IN unsigned int srcLen,
                 IN unsigned char *userID,
                 IN unsigned int IDLen,
                 IN my_pbig mp_XA,
                 IN my_pbig mp_YA,
                 IN my_gp *gp);

/// SM2密钥派生函数
/// @param outData 密钥数据
/// @param inData 密钥派生参数
/// @param inLen 密钥派生参数长度
/// @param klen 派生密钥长度
/// @return 结果码
int sm2_kdf(OUT unsigned char *outData,
            IN unsigned char *inData,
            IN unsigned int inLen,
            IN unsigned int klen);

#ifdef __cplusplus
}
#endif

#endif
