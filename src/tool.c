#include "tool.h"

/**
 Hex string change to unsigned char array:
 Hex char:
 a b c d e f A B C D E F 0 1 2 3 4 5 6 7 8 9
 note:
 1. add space support(change space to 0)
 2. support sm2 encrypt or decrypt kdf and signature src pretreatment
 */
int hexstr_to_byte_arr(IN unsigned char *inData,
                          IN unsigned int inLen,
                          OUT unsigned char *outData,
                          OUT unsigned int *outLen){
    
    if(inData == NULL) return HEX_STR_TO_BYTE_ARR_INDATA_NULL;
    if(0 != inLen % 2) return HEX_STR_TO_BYTE_ARR_INDATA_LEN_ERROR;
    if(outData == NULL) return HEX_STR_TO_BYTE_ARR_OUTDATA_NULL;
    if(outLen == NULL) return HEX_STR_TO_BYTE_ARR_OUTDATA_LEN_NULL;
    
    int j = 0, i = 0;
    unsigned char h = 0;
    unsigned char l = 0;
    
    for(i = 0; i < inLen; i += 2){
        if(inData[i] >= 0x30 && inData[i] <= 0x39)      h = inData[i] - 0x30;
        else if(inData[i] >= 0x41 && inData[i] <= 0x46) h = inData[i] - 0x37;
        else if(inData[i] >= 0x61 && inData[i] <= 0x66) h = inData[i] - 0x57;
        else if(inData[i] == 0x20)                      h = 0x00;
        else return HEX_STR_TO_BYTE_ARR_FAILED;
        if(inData[i+1] >= 0x30 && inData[i+1] <= 0x39)      l = inData[i+1] - 0x30;
        else if(inData[i+1] >= 0x41 && inData[i+1] <= 0x46) l = inData[i+1] - 0x37;
        else if(inData[i+1] >= 0x61 && inData[i+1] <= 0x66) l = inData[i+1] - 0x57;
        else if(inData[i+1] == 0x20)                        l = 0x00;
        else return HEX_STR_TO_BYTE_ARR_FAILED;
        outData[j] = (h << 4) + l;
        j++;
    }
    *outLen = j;
    return TOOL_SUCCESS;
}

//Unsigned char array change to hex string
int byte_arr_to_hexstr(IN unsigned char *inData,
                          IN unsigned int inLen,
                          OUT unsigned char *outData,
                          OUT unsigned int *outLen){
    
    if(inData == NULL) return BYTE_ARR_TO_HEX_STR_INDATA_NULL;
    if(inLen <= 0) return BYTE_ARR_TO_HEX_STR_INDATA_LEN_ERROR;
    if(outData == NULL) return BYTE_ARR_TO_HEX_STR_OUTDATA_NULL;
    if(outLen == NULL) return BYTE_ARR_TO_HEX_STR_OUTDATA_LEN_NULL;
    
    int j = 0, i = 0;
    unsigned char tmp = 0;
    
    for(i = 0 ; i< inLen; i++){
        tmp = inData[i]>>4;
        if(tmp >= 0 && tmp <= 9) outData[j] = tmp + 0x30;
        else outData[j] = tmp + 0x37;
        tmp = inData[i] & 0x0f;
        if(tmp >= 0 && tmp <= 9) outData[j+1] = tmp + 0x30;
        else outData[j+1] = tmp + 0x37;
        j += 2;
    }
    outData[j] = '\0';
    *outLen = inLen * 2;
    return TOOL_SUCCESS;
}

void print_byte(const char *Name, unsigned char *Src, unsigned int SrcLen)
{
    int i;
    printf("%s:\n", Name);
    for (i = 0; i < SrcLen; i++) {
        printf("%02X", Src[i]);
    }
    printf("\n");
}