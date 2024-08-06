#ifndef my_math_h
#define my_math_h

#include <stdio.h>
#include "define.h"

#define MY_MATH_CALLOC_ERROR                                1000
#define MY_MATH_UINT_SIZE_NOT_QT_4                          1001
#define MY_MATH_2UINT_SIZE_LT_ULONG_SIZE                    1002
#define MY_MATH_READ_BIN_TOO_LONG                           1003
#define MY_MATH_DUVUSOR_QT_0                                1004
#define MY_MATH_BIG_NUMBER_TOO_LONG                         1005
#define MY_MATH_BIG_MEM_NOT_ENOUGH                          1006
#define MY_MATH_SUB_U_Y_GT_X                                1007
#define MY_MATH_DIV_X_QT_Y                                  1008

#ifdef __cplusplus
extern "C" {
#endif

typedef int BOOL;
typedef unsigned int my_uint;
typedef unsigned long long my_ullong;

union my_dword{
    my_ullong r;
    my_uint f[2];
};

typedef struct bignumber{
    my_uint l;//四字节的标识位,最高位代表符号位,低31位代表数据的长度（也就是d包含的my_uint数量）
    my_uint *d;
}my_big, *my_pbig;

typedef struct {
    int flag;
    my_pbig X;
    my_pbig Y;
    my_pbig Z;
}my_point;

typedef struct {
    int err_code;
    BOOL ff;
    my_uint LN;
    char *room;
    my_pbig P1,P2,N,tmp;
    int PL1,PL2,MNE,MNN;
    my_pbig p0,p1,p2,p3,p4,p5,p6,p7,p8;
    my_pbig p9,p10,p11,p12,p13,p14,p15;
}my_gp;

//Init a big number ---------------------------------
my_pbig my_init(int iv, my_gp *gp);
//Init my_gp struct ---------------------------------
my_gp * my_init_gp(void);
//Set mod number n
my_uint my_set_mod(my_pbig n, my_gp *gp);
//x = 0 ---------------------------------
void my_zero(my_pbig x);
//free x ---------------------------------
void my_clear(my_pbig x);
//free gp ---------------------------------
void my_gp_clear(my_gp *gp);
//y = -x ---------------------------------
void my_neg(my_pbig x, my_pbig y);
//y = x ---------------------------------
void my_copy(my_pbig x, my_pbig y);
//free p
void my_point_clear(my_point * p);
//x = n ---------------------------------
void my_set_d(int n, my_pbig x);
//z = x + y ---------------------------------
void my_add(my_pbig x, my_pbig y, my_pbig z, my_gp *gp);
//z = x + n ---------------------------------
void my_add_d(my_pbig x, int n, my_pbig z, my_gp *gp);
//z = x - y ---------------------------------
void my_sub(my_pbig x, my_pbig y, my_pbig z, my_gp *gp);
//z = x - n ---------------------------------
void my_sub_d(my_pbig x, int n, my_pbig z, my_gp *gp);
//z = x * y
void my_mul(my_pbig x, my_pbig y, my_pbig z, my_gp *gp);
//x = x % y, z = x / y
void my_div(my_pbig x, my_pbig y, my_pbig z, my_gp *gp);
//Modular inverse operation
int my_invmod(my_pbig x, my_pbig y, my_pbig z, my_gp *gp);
//Montgomery number pretreatment
void my_pn(my_pbig x, my_pbig y, my_gp *gp);
//Montgomery number reverse processing
void my_rn(my_pbig x, my_pbig y, my_gp *gp);
//w = (x + y) mod (gp->N) = rn(pn(w)) = rn((pn(x) + pn(y)) mod (gp->N))
void my_addmodn(my_pbig x, my_pbig y, my_pbig w, my_gp *gp);
//w = (x - y) mod (gp->N) = rn(pn(w)) = rn((pn(x) - pn(y)) mod (gp->N))
void my_submodn(my_pbig x, my_pbig y, my_pbig w, my_gp *gp);
//w = (x * y) mod (gp->N) = rn(pn(w)) = rn((pn(x) * pn(y)) mod (gp->N))
void my_mulmodn(my_pbig x, my_pbig y, my_pbig w, my_gp *gp);
//Comparison of x and y: if x > y return 1, if x = y return 0, if x < y return -1 ---------------------------------
int my_cmp(my_pbig x, my_pbig y);
//Assign char array's value to a big number ---------------------------------
void my_read_bin(int len, const char *ptr, my_pbig x, my_gp *gp);
//Turn big number into HEX string
int my_to_redix(my_pbig x, char * string, my_gp *gp);
//Initialize elliptic curve
void my_ecc_init(my_pbig a, my_pbig b, my_pbig p, my_gp *gp);
//Initialize a point
my_point * my_point_init(my_gp *gp);
//Set a point, p->X = x, p->Y = y
BOOL my_set_point(my_pbig x, my_pbig y, my_point *p, my_gp *gp);
//pa = p + pa
int my_point_add(my_point *p,my_point *pa, my_gp *gp);
//x = p->X, y = p->Y
int my_get_point(my_point *p, my_pbig x, my_pbig y, my_gp *gp);
//pt = e * pa
int my_point_mul(my_pbig e, my_point *pa, my_point *pt, my_gp *gp);

//----------------add by xiao yun song-------------------
void my_judge_prime(my_pbig a, int t, my_gp *gp);

#ifdef __cplusplus
}
#endif

#endif
