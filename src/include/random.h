#ifndef random_h
#define random_h

#include <stdio.h>
#include <stdint.h>
#include "define.h"

#define RANOM_SUCCESS                                       0
#define RANDOM_POINTER_NULL                                 601
#define RANDOM_LEN_TOO_SMALL                                602
#define RANDOM_LEN_TOO_BIG                                  603

#define MAX_RANDOM_LEN   1000

#ifdef __cplusplus
extern "C" {
#endif

/// 生成指定长度的随机数
/// @param random 随机数
/// @param len 随机数长度
/// @return 结果码
int my_random(OUT unsigned char * random,
            IN unsigned int len);
    
#ifdef __cplusplus
}
#endif

#endif
