#ifndef sm2_h
#define sm2_h

#include "sm2_tool.h"

#define SM2_SUCCESS                                         0
#define SM2_STD_GEN_KEYPAIR_PRIKEY_NULL                     9000
#define SM2_STD_GEN_KEYPAIR_PRILEN_NULL                     9001
#define SM2_STD_GEN_KEYPAIR_PUBKEY_NULL                     9002
#define SM2_STD_SIGN_TRY_MANY_TIMES                         9003
#define SM2_STD_SIGN_SIGNATURE_NULL                         9004
#define SM2_STD_SIGN_SIGNLEN_NULL                           9005
#define SM2_STD_SIGN_SRC_NULL                               9006
#define SM2_STD_SIGN_PRIKEY_NULL                            9007
#define SM2_STD_SIGN_PRIKEYLEN_NULL                         9008
#define SM2_STD_SIGN_HASHFLAG_ERROR                         9009
#define SM2_STD_SIGN_USERID_NULL                            9010
#define SM2_STD_SIGN_USERIDLEN_ERROR                        9011
#define SM2_STD_SIGN_SRCLEN_ERROR                           9012
#define SM2_STD_SIGN_SRCLEN_NOT_QT_32                       9013
#define SM2_STD_VERIFY_R_GT_N                               9014
#define SM2_STD_VERIFY_S_GT_N                               9015
#define SM2_STD_VERIFY_T_QT_0                               9016
#define SM2_STD_VERIFY_T_NOT_QT                             9017
#define SM2_STD_VERIFY_SIGNDATA_NULL                        9018
#define SM2_STD_VERIFY_SIGNDATA_LEN_ERROR                   9019
#define SM2_STD_VERIFY_SRC_NULL                             9020
#define SM2_STD_VERIFY_PUBKEY_NULL                          9021
#define SM2_STD_VERIFY_PUBLEN_NOT_QT_64                     9022
#define SM2_STD_VERIFY_HASHFLAG_ERROR                       9023
#define SM2_STD_VERIFY_USERID_NULL                          9024
#define SM2_STD_VERIFY_USERIDLEN_ERROR                      9025
#define SM2_STD_VERIFY_SRCLEN_ERROR                         9026
#define SM2_STD_VERIFY_SRCLEN_NOT_QT_32                     9027
#define SM2_STD_ENC_ENCDATA_NULL                            9028
#define SM2_STD_ENC_ENCLEN_NULL                             9029
#define SM2_STD_ENC_SRC_NULL                                9030
#define SM2_STD_ENC_SRCLEN_ERROR                            9031
#define SM2_STD_ENC_PUBKEY_NULL                             9032
#define SM2_STD_ENC_PUBLEN_NOT_QT_64                        9033
#define SM2_STD_ENC_X1LEN_NOT_QT_32                         9034
#define SM2_STD_DEC_PLAIN_NULL                              9035
#define SM2_STD_DEC_PLAIN_LEN_NULL                          9036
#define SM2_STD_DEC_CIPHER_NULL                             9037
#define SM2_STD_DEC_CIPHER_LEN_LT_98                        9038
#define SM2_STD_DEC_D_NULL                                  9039
#define SM2_STD_DEC_DLEN_NOT_QT_32                          9040
#define SM2_STD_DEC_KDF_IS_NULL                             9041
#define SM2_STD_DEC_HASH_CMP_ERROR                          9042

#define SM2_STD_SIGN_RLEN_NOT_QT_32                         9121
#define SM2_STD_SIGN_SLEN_NOT_QT_32                         9122
#define SM2_STD_GEN_KEYPAIR_YLEN_NOT_QT_32                  9128
#define SM2_STD_GEN_KEYPAIR_XLEN_NOT_QT_32                  9129
#define SM2_STD_GEN_KEYPAIR_PRILEN_NOT_QT_32                9130
#define SM2_STD_ENC_X2LEN_NOT_QT_32                         9131
#define SM2_STD_ENC_Y2LEN_NOT_QT_32                         9132
#define SM2_STD_ENC_Y1LEN_NOT_QT_32                         9133
#define SM2_STD_DEC_X2LEN_NOT_QT_32                         9134
#define SM2_STD_DEC_Y2LEN_NOT_QT_32                         9135
#define SM2_MEM_ALLOC_ERROR                                 9136

#ifdef __cplusplus
extern "C" {
#endif

/// 标准算法--SM2生成秘钥对
/// @param prikey SM2私钥
/// @param priLen SM2私钥长度
/// @param pubkey SM2公钥
/// @return 结果码
int sm2_gen_keypair(OUT unsigned char *prikey,
                       OUT unsigned int *priLen,
                       OUT unsigned char pubkey[64]);

/// @param signature SM2签名值
/// @param signLen SM2签名值长度
/// @param src 签名原文
/// @param srcLen 签名原文长度
/// @param userID 签名者ID,签名预处理在函数外部进行时可为空
/// @param IDLen 签名者ID长度
/// @param prikey 签名私钥
/// @param priLen 签名私钥长度
/// @param pubkey 用户公钥,非必传
/// @param hashFlag 签名预处理标识,NO_HASH:函数内部做预处理,WITH_HASH:函数外部做预处理
/// @return 结果码
int sm2_sign(OUT unsigned char *signature,
                OUT unsigned int *signLen,
                IN unsigned char *src,
                IN unsigned int srcLen,
                IN unsigned char *userID,
                IN unsigned int IDLen,
                IN unsigned char *prikey,
                IN unsigned int priLen,
                IN unsigned char *pubkey,
                IN unsigned int hashFlag);

/// 标准算法--SM2验签
/// @param signedData 签名值
/// @param signLen 签名之长度
/// @param src 原文
/// @param srcLen 原文长度
/// @param userID 签名者ID,签名预处理在函数外部进行时可为空
/// @param IDLen 签名者ID长度
/// @param pubkey 签名公钥
/// @param pubLen 签名公钥长度
/// @param hashFlag 签名预处理标识,NO_HASH:函数外部做预处理,WITH_HASH:函数内部做预处理
/// @return 结果码
int sm2_verify(IN unsigned char *signedData,
                  IN unsigned int signLen,
                  IN unsigned char *src,
                  IN unsigned int srcLen,
                  IN unsigned char *userID,
                  IN unsigned int IDLen,
                  IN unsigned char *pubkey,
                  IN unsigned int pubLen,
                  IN unsigned int hashFlag);

/// @param encData 密文
/// @param encLen 密文长度
/// @param src 原文
/// @param srcLen 原文长度
/// @param pubkey 加密公钥
/// @param pubLen 加密公钥长度
/// @return 结果码
int sm2_enc(OUT unsigned char *encData,
               OUT unsigned int *encLen,
               IN unsigned char *src,
               IN unsigned int srcLen,
               IN unsigned char *pubkey,
               IN unsigned int pubLen);

/// @param plain 原文
/// @param plainLen 原文长度
/// @param cipher 密文
/// @param cipherLen 密文长度
/// @param d 加密私钥
/// @param dLen 加密私钥长度
/// @return 结果码
int sm2_dec(OUT unsigned char *plain,
               OUT unsigned int *plainLen,
               IN unsigned char *cipher,
               IN unsigned int cipherLen,
               IN unsigned char *d,
               IN unsigned int dLen);

#ifdef __cplusplus
}
#endif

#endif
