#ifndef diffie_hellman_h
#define diffie_hellman_h

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <math.h>
#include <tommath.h>
#include "hash.h"
#include "random.h"

// error code
#define DH_SUCCESS                                          0
#define ERR_PARM_SMALL                                      301
#define ERR_PARM_INVALID                                    302
#define ERR_PARM_NULL                                       303
#define ERR_MEMORY                                          304
#define ERR_FAILED_GEN_PRIME                                305
#define ERR_NOT_PRIME                                       306
#define ERR_Q_INVALID                                       307
#define ERR_VALIDATION_FAILED                               308
#define ERR_BUFFER_NOT_ENOUGH                               309
#define ERR_PUBKEY_LESS_THAN_2                              310
#define ERR_PUBKEY_GREATER_THAN_P_MINUS_2                   311
#define ERR_PUBKEY_NOT_EQ_1_MOD_P                           312
#define ERR_ZZ_EQ_1                                         313

#define CHECK(x) if(x) goto END

#ifdef __cplusplus
extern "C" {
#endif

int prime_generation(unsigned int L, unsigned int m, 
                     unsigned char* p, unsigned int* p_len,
                     unsigned char* q, unsigned int* q_len, 
                     unsigned char* seed, unsigned int* seed_len, 
                     unsigned int* pgenCounter);

int prime_validation(unsigned char* p, unsigned int p_len, 
                     unsigned char* q, unsigned int q_len, 
                     unsigned char* seed, unsigned int seed_len,
                     unsigned int L, unsigned int m,
                     unsigned int pgenCounter);

int select_generator(unsigned char* p, unsigned int p_len, 
                     unsigned char* q, unsigned int q_len,
                     unsigned char* g, unsigned int* g_len);

int generate_key_pair(unsigned char* p, unsigned int p_len,
                     unsigned char* q, unsigned int q_len,
                     unsigned char* g, unsigned int g_len,
                     unsigned char* pubkey, unsigned int* pubkey_len,
                     unsigned char* prikey, unsigned int* prikey_len);

int public_key_validation(unsigned char* p, unsigned int p_len,
                          unsigned char* q, unsigned int q_len,
                          unsigned char* g, unsigned int g_len,
                          unsigned char* seed, unsigned int seed_len,
                          unsigned char* pubkey, unsigned int pubkey_len);

int calculate_zz(unsigned char* p, unsigned int p_len,
                 unsigned char* q, unsigned int q_len,
                 unsigned char* g, unsigned int g_len,
                 unsigned char* v_pubkey, unsigned int v_pubkey_len,
                 unsigned char* u_prikey, unsigned int u_prikey_len,
                 unsigned char* zz, unsigned int* zz_len);

#ifdef __cplusplus
}
#endif

#endif // diffie_hellman_h