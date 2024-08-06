#ifndef hash_h
#define hash_h

#include <stdint.h>
#include "define.h"

#define HASH_SUCCESS                                        0
#define HASH_INIT_CTX_NULL                                  401
#define HASH_ALGO_ERROR                                     402
#define HASH_UPDATE_CTX_NULL                                403
#define HASH_UPDATE_INDATA_NULL                             404
#define HASH_UPDATE_INDATA_LEN_ERROR                        405
#define HASH_FINAL_CTX_NULL                                 406
#define HASH_FINAL_HASH_NULL                                407
#define HASH_FINAL_HASH_LEN_NULL                            408

#ifdef __cplusplus
extern "C" {
#endif

#define SM3                  100 //SM3算法标识
#define SHA1                 200 //SHA1算法标识
#define SHA256               300 //SHA256算法标识
#define MD5                  400 //MD5算法标识
#define MURMURHASH2_x32_32   500 //Murmur Hash2算法标识
#define MURMURHASH3_x32_32   510 //Murmur Hash3算法标识
#define MURMURHASH3_x32_128  511 //Murmur Hash3算法标识
#define MURMURHASH3_x64_128  512 //Murmur Hash3算法标识

typedef void(*hash_func)(uint32_t *,const unsigned char *);

typedef struct{
    unsigned int group_num;             //分组数量
    unsigned int left_num;              //不够单次分组的剩余字节数量
    unsigned int digestLen;             //摘要数据长度
    hash_func func;                  //摘要函数指针
    uint32_t digest[8];                 //运算结果
    unsigned char current_group[64];    //当前分组字节数组
}hash_context;

/// 摘要运算初始化
/// @param ctx 摘要运算过程变量结构体
/// @param algo 摘要算法标识
/// @return 结果码
int hash_init(IN hash_context *ctx,
                 IN int algo);

/// 摘要分组运算
/// @param ctx 摘要运算过程变量结构体
/// @param inData 单次分组数据
/// @param dataLen 单次分组数据长度
/// @return 结果码
int hash_update(IN hash_context *ctx,
                   IN const unsigned char *inData,
                   IN unsigned int dataLen);

/// 摘要分组运算结束
/// @param ctx 摘要运算过程变量结构体
/// @param hash 摘要值
/// @param hashLen 摘要值长度
/// @return 结果码
int hash_final(IN hash_context *ctx,
                  OUT unsigned char *hash,
                  OUT unsigned int *hashLen);

/// 摘要运算
/// @param algo 摘要算法标识
/// @param inData 待摘要数据
/// @param dataLen 待摘要数据长度
/// @param hash 摘要值
/// @param hashLen 摘要值长度
/// @return 结果码
int hash(IN int algo,
         IN const unsigned char *inData,
         IN unsigned int dataLen,
         OUT unsigned char *hash,
         OUT unsigned int *hashLen);

#ifdef __cplusplus
}
#endif

#endif
