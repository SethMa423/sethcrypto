#ifndef tool_h
#define tool_h

#include <stdio.h>
#include "define.h"

#define TOOL_SUCCESS                                        0
#define HEX_STR_TO_BYTE_ARR_INDATA_NULL                     801
#define HEX_STR_TO_BYTE_ARR_INDATA_LEN_ERROR                802
#define HEX_STR_TO_BYTE_ARR_OUTDATA_NULL                    803
#define HEX_STR_TO_BYTE_ARR_OUTDATA_LEN_NULL                804
#define HEX_STR_TO_BYTE_ARR_FAILED                          805
#define BYTE_ARR_TO_HEX_STR_INDATA_NULL                     806
#define BYTE_ARR_TO_HEX_STR_INDATA_LEN_ERROR                807
#define BYTE_ARR_TO_HEX_STR_OUTDATA_NULL                    808
#define BYTE_ARR_TO_HEX_STR_OUTDATA_LEN_NULL                809

#ifdef __cplusplus
extern "C" {
#endif

/// 十六进制字符串转换成无符号的字符数组
/// @param inData 十六进制字符串数据
/// @param inLen 十六进制字符串数据长度
/// @param outData 字符数组
/// @param outLen 字符串数组长度
/// @return 结果码
int hexstr_to_byte_arr(IN unsigned char *inData,
                          IN unsigned int inLen,
                          OUT unsigned char *outData,
                          OUT unsigned int *outLen);

/// 无符号的字符数组转换成十六进制字符串
/// @param inData 字符数组
/// @param inLen 字符数组长度
/// @param outData 十六进制字符串
/// @param outLen 十六进制字符串长度
/// @return 结果码
int byte_arr_to_hexstr(IN unsigned char *inData,
                          IN unsigned int inLen,
                          OUT unsigned char *outData,
                          OUT unsigned int *outLen);


void print_byte(const char *Name, unsigned char *Src, unsigned int SrcLen);

#ifdef __cplusplus
}
#endif

#endif
