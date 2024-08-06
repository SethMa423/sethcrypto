#include "my_math.h"
#include <stdlib.h>
#include <string.h>

/*
说明：
1.该大数库只支持字节存储小端, int占4个字节, long long至少占8个字节的机器
2.在调用大数库方法时除接口说明的特殊要求外,调用者应保证所传参数的有效性,大数库内不进行严格的参数判断
*/

#define MY_L 0
#define MY_H 1
#define MY_OVER                 (1<<30)             //01000000 00000000 00000000 00000000
#define MY_OBITS                (MY_INBITS-1)       //01111111 11111111 11111111 11111111
#define MY_INBITS               ((my_uint)1<<(31))  //10000000 00000000 00000000 00000000
#define MY_UMAX                 ((my_uint)1<<(31))  //10000000 00000000 00000000 00000000
#define MY_PV(x)                ((x) < 0 ? (-(x)) : (x))//取正值
#define MY_LSIZE                sizeof(long)
#define MY_GROW_PSIZE(n,m)      ((n)*MY_PSIZE(m)+MY_LSIZE)
#define MY_GROW_BIG_SIZE(n,m)   ((n)*MY_BIG_SIZE(m)+MY_LSIZE)
#define MY_BIG_SIZE(n)          (((sizeof(my_big)+((n)+2)*sizeof(int))-1)/MY_LSIZE+1)*MY_LSIZE
#define MY_PSIZE(n)             (((sizeof(my_point)+MY_GROW_BIG_SIZE(3,(n)))-1)/MY_LSIZE+1)*MY_LSIZE

#define MY_BIG_N    63//默认的大数k空间值,对应280个字节

//获取一个大数的符号,1是正数;-1是负数
int my_get_sym(my_pbig x){
    
    if((x->l & (MY_INBITS)) == 0) return 1;
    else return (-1);
}

//设置一个大数的符号位
void my_set_sym(int s, my_pbig x){
    
    if(x->l == 0) return;
    if(s < 0) x->l |= MY_INBITS;
    else x->l &= MY_OBITS;
}

int my_size(my_pbig x){
    
    int n = 0,m = 0;
    my_uint s = 0;
    if(x == NULL) return 0;
    s = (x->l & MY_INBITS);
    m = (int)(x->l & MY_OBITS);
    if(m == 0) return 0;
    if(m == 1 && x->d[0] < (my_uint)MY_OVER) n = (int)x->d[0];
    else n = MY_OVER;
    if(s == MY_INBITS) return (-n);
    return n;
}

//判断一个大数长度位的高15位是否有值(判断大数实际使用的uintc数量是否大于65535)
BOOL my_jint(my_pbig x){
    
    if((((x->l & (MY_OBITS)) >> (16)) & (0xFFFF)) != 0) return 1;
    return 0;
}

//计算x使用的my_unint数量,使用长度等于除符号位外的高15位值+低16位的值
int my_len(my_pbig x){
    my_uint lx = (x->l & (MY_OBITS));
    return (int)((lx & 0xFFFF) + ((lx >> 16) & 0xFFFF));
}

//修改一个大数的使用长度为真实的使用长度,去掉高位全是0状态下的大数长度值异常
void my_lzero(my_pbig x){
    
    my_uint s = 0;
    int m = 0;
    s = (x->l & (MY_INBITS));
    m = (int)(x->l & (MY_OBITS));
    while(m > 0 && x->d[m-1] == 0) m--;
    x->l = m;
    if(m > 0) x->l |= s;
}

//z=x*sn,一个大数乘以一个无符号的整数
void my_mul_u(my_pbig x, my_uint sn, my_pbig z, my_gp *gp){
    
    int m = 0,xl = 0;
    my_uint sx = 0;
    my_uint carry = 0, *xg = NULL, *zg = NULL;
    union my_dword dble;
    
    if(x != z){
        my_zero(z);
        if(sn == 0) return;
    }else if(sn == 0){
        my_zero(z);
        return;
    }
    sx = x->l & MY_INBITS;
    xl = (int)(x->l & MY_OBITS);
    xg = x->d; zg = z->d;
    for(m = 0; m < xl; m++){
        dble.r = (my_ullong)x->d[m] * sn + carry;
        carry = dble.f[MY_H];
        z->d[m] = dble.f[MY_L];
    }
    if(carry > 0){
        m = xl;
        if(m >= 64 && gp->ff){
            gp->err_code = MY_MATH_BIG_NUMBER_TOO_LONG;
            return;
        }
        z->d[m] = carry;
        z->l = m+1;
    }else z->l = xl;
    if(z->l != 0) z->l |= sx;
}

my_uint my_nor(my_pbig x, my_pbig y, my_gp *gp){
    
    int len = 0;
    my_uint norm = 0,r = 0;
    
    if(x != y) my_copy(x,y);
    len = (int)(y->l & MY_OBITS);
    if((r = y->d[len-1] + 1) == 0) norm = 1;
    else norm = (my_uint)(((my_ullong)1 << 32) / r);
    if(norm != 1) my_mul_u(y, norm, y, gp);
    return norm;
}

/*
 z=x+y
 注：此方法实现的是两个无符号的大数相加
 */
void my_add_u(my_pbig x, my_pbig y, my_pbig z, my_gp *gp){
    
    int i = 0,lx = 0,ly = 0,lz = 0,la = 0;
    my_uint carry = 0,psum = 0;
    my_uint *gx = NULL,*gy = NULL,*gz = NULL;
    
    lx = (int)x->l;
    ly = (int)y->l;
    //y的值大于x的情况
    if(ly > lx){
        lz = ly;
        la = lx;
        if(x != z) my_copy(y,z);
        else la = ly;
    }else{//y的值不大于x的情况
        lz = lx;
        la = ly;
        if(y != z) my_copy(x,z);
        else la = lx;
    }
    z->l = lz;
    gx = x->d; gy = y->d; gz = z->d;
    if(lz < 64 || !gp->ff) z->l++;
    for(i = 0; i < la; i++){
        psum = gx[i] + gy[i] + carry;
        if(psum > gx[i]) carry = 0;
        else if(psum < gx[i]) carry = 1;
        gz[i] = psum;
    }
    //这里gx的空间足够使用,不用担心溢出的问题
    for( ; i < lz && carry > 0; i++){
        psum = gx[i] + gy[i] + carry;
        if(psum > gx[i]) carry = 0;
        else if(psum < gx[i]) carry = 1;
        gz[i] = psum;
    }
    if(carry){
        if(gp->ff && i >= 64){
            gp->err_code = MY_MATH_BIG_MEM_NOT_ENOUGH;
            return;
        }
        gz[i] = carry;
    }
    if(gz[z->l-1] == 0) z->l--;
}

void my_mul(my_pbig x, my_pbig y, my_pbig z, my_gp *gp){
    
    int i = 0,xl = 0,yl = 0,j = 0,ti = 0;
    my_uint carry = 0,*xg = NULL,*yg = NULL,*w0g = NULL;
    my_uint sz = 0;
    my_pbig w0 = 0;
    union my_dword dble;
    gp->err_code = 0;
    
    if(y->l == 0 || x->l == 0){
        my_zero(z);
        return;
    }
    if(x != gp->p5 && y != gp->p5 && z == gp->p5) w0 = gp->p5;
    else w0 = gp->p0;
    if(my_jint(x) || my_jint(y)){
        gp->err_code = 6;
        return;
    }
    sz = ((x->l & MY_INBITS) ^ (y->l & MY_INBITS));
    xl = (int)(x->l & MY_OBITS);
    yl = (int)(y->l & MY_OBITS);
    my_zero(w0);
    if(gp->ff && ((xl + yl) > 64)){
        gp->err_code = 2;
        return;
    }
    xg = x->d;
    yg = y->d;
    w0g = w0->d;
    if(x == y && xl > 5){
        for(i = 0; i < xl - 1; i++){
            carry = 0;
            for(j = i + 1; j < xl; j++){
                dble.r = (my_ullong)x->d[i] * x->d[j] + carry + w0->d[i+j];
                w0->d[i+j] = dble.f[MY_L];
                carry = dble.f[MY_H];
            }
            w0->d[xl+i] = carry;
        }
        w0->l = xl+xl-1;
        my_add_u(w0,w0,w0,gp);
        carry = 0;
        for(i = 0; i < xl; i++){
            ti = i+i;
            dble.r = (my_ullong)x->d[i] * x->d[i] + carry + w0->d[ti];
            w0->d[ti] = dble.f[MY_L];
            carry = dble.f[MY_H];
            w0->d[ti+1] += carry;
            if(w0->d[ti+1] < carry) carry = 1;
            else carry = 0;
        }
    }else for(i = 0; i < xl; i++){
        carry = 0;
        for(j = 0; j < yl; j++){
            dble.r = (my_ullong)x->d[i] * y->d[j] + carry + w0->d[i+j];
            w0->d[i+j] = dble.f[MY_L];
            carry = dble.f[MY_H];
        }
        w0->d[yl+i] = carry;
    }
    w0->l = (sz | (xl+yl));
    my_lzero(w0);
    my_copy(w0,z);
}

/*
 z=x-y
 注:两个无符号的大数相减,并且要求x必须大于或者等于y
 */
void my_sub_u(my_pbig x, my_pbig y, my_pbig z, my_gp *gp){
    
    int i = 0,lx = 0,ly = 0;
    my_uint borrow = 0,pdiff = 0;
    my_uint *gx = NULL,*gy = NULL,*gz = NULL;
    
    lx = (int)x->l;
    ly = (int)y->l;
    if(ly > lx){
        gp->err_code = MY_MATH_SUB_U_Y_GT_X;
        return;
    }
    if(y != z) my_copy(x,z);
    else ly = lx;
    z->l = lx;
    gx = x->d; gy = y->d; gz = z->d;
    for(i = 0; i < ly || borrow > 0; i++){
        if(i > lx){
            gp->err_code = MY_MATH_SUB_U_Y_GT_X;
            return;
        }
        pdiff = gx[i] - gy[i] - borrow;
        if(pdiff < gx[i]) borrow = 0;
        else if(pdiff > gx[i]) borrow = 1;
        gz[i] = pdiff;
    }
    my_lzero(z);
}

/*
 大数x除以一个无符号的整数d,商赋值给大数z,余数为返回值(非实际的余数)
 除法的逻辑是:
 1. 从大数的高位开始对sn取余,商作为相应高位的值,余数作为次高位的高位(long的高位)
 2. 依次循环运算最后的余数作为余数结果返回
 3. 除法的商为逐位相除的结果
 
 注:
 a. x的实际使用的uint长度不能大于65535
 b. 为返回真正的余数,只是返回无符号数相除的结果,实际的余数在上层函数中做处理(对符号位取反操作)
 */
my_uint my_div_ud(my_pbig x, my_uint d, my_pbig z){
    
    int i = 0,xl = 0;
    my_uint sr = 0;
    union my_dword dble;
    
    xl = (int)(x->l & MY_OBITS);
    if(x != z) my_zero(z);
    for(i = xl-1; i >= 0; i--){
        dble.f[MY_L] = x->d[i];
        dble.f[MY_H] = sr;
        z->d[i] = (my_uint)(dble.r/d);
        sr = (my_uint)(dble.r - (my_ullong)z->d[i] * d);
    }
    z->l = x->l;
    my_lzero(z);
    return sr;
}

void my_div(my_pbig x, my_pbig y, my_pbig z, my_gp *gp){
    
    my_uint carry = 0,attemp = 0,ldy = 0,sdy = 0,ra = 0,r = 0,d = 0,tst = 0,psum = 0;
    my_uint sx = 0,sy = 0,sz = 0;
    my_uint borrow = 0,dig = 0,*w0g = 0,*yg = 0;
    int i = 0,k = 0,m = 0,x0 = 0,y0 = 0,w00 = 0;
    my_pbig w0 = NULL;
    union my_dword dble;
    BOOL check = 0;
    gp->err_code = 0;
    
    w0 = gp->p0;
    if(x == y){
        gp->err_code = MY_MATH_DIV_X_QT_Y;
        return;
    }
    if(my_jint(x) || my_jint(y)){
        gp->err_code = MY_MATH_BIG_NUMBER_TOO_LONG;
        return;
    }
    if(y->l == 0){
        gp->err_code = MY_MATH_DUVUSOR_QT_0;
        return;
    }
    //获取符号位
    sx = (x->l & MY_INBITS);
    sy = (y->l & MY_INBITS);
    sz = (sx ^ sy);
    //获取使用的uint数量
    x->l &= MY_OBITS;
    y->l &= MY_OBITS;
    x0 = (int)x->l;
    y0 = (int)y->l;
    my_copy(x,w0);
    w00 = (int)w0->l;
    //判断大数空间是否够用
    if(gp->ff && (w00-y0 > 64)){
        gp->err_code = MY_MATH_BIG_NUMBER_TOO_LONG;
        return;
    }
    if(x0 == y0){
        if(x0 == 1){
            d = (w0->d[0]) / (y->d[0]);
            w0->d[0] = (w0->d[0] % y->d[0]);
            my_lzero(w0);
        }else if((w0->d[x0-1]) / 4 < y->d[x0-1])//设定循环次数不能大于四次(保障效率)
            while (my_cmp(w0,y) >= 0){
                my_sub_u(w0,y,w0,gp);
                if(gp->err_code) return;
                d++;
            }
    }
    if(my_cmp(w0,y) < 0){
        if(x != z){
            my_copy(w0,x);
            if(x->l != 0) x->l |= sx;
        }
        if(y != z){
            my_zero(z);
            z->d[0] = d;
            if(d>0) z->l = (sz|1);
        }
        y->l |= sy;
        return;
    }
    if(y0 == 1){
        r = my_div_ud(w0,y->d[0],w0);
        if(y != z){
            my_copy(w0,z);
            z->l |= sz;
        }
        if(x != z){
            my_zero(x);
            x->d[0] = r;
            if(r>0) x->l = (sx|1);
        }
        y->l |= sy;
        return;
    }
    if(y != z) my_zero(z);
    d = my_nor(y,y,gp);
    check = gp->ff;
    gp->ff = 0;
    if(d != 1) my_mul_u(w0,d,w0,gp);
    ldy = y->d[y0-1];
    sdy = y->d[y0-2];
    w0g = w0->d; yg=y->d;
    for(k = w00-1; k >= y0-1; k--){
        carry = 0;
        if(w0->d[k+1] == ldy){
            attemp = (my_uint)(-1);
            ra = ldy + w0->d[k];
            if(ra < ldy) carry = 1;
        }else{
            dble.f[MY_L] = w0->d[k];
            dble.f[MY_H] = w0->d[k+1];
            attemp = (my_uint)(dble.r/ldy);
            ra = (my_uint)(dble.r - (my_ullong)attemp * ldy);
        }
        while(carry == 0){
            dble.r = (my_ullong)attemp * sdy;
            r = dble.f[MY_L];
            tst = dble.f[MY_H];
            if(tst < ra || (tst == ra && r <= w0->d[k-1])) break;
            attemp--;
            ra += ldy;
            if(ra < ldy) carry = 1;
        }
        m = k-y0+1;
        if(attemp > 0){
            borrow = 0;
            for(i = 0; i < y0; i++){
                dble.r = (my_ullong)attemp * y->d[i] + borrow;
                dig = dble.f[MY_L];
                borrow = dble.f[MY_H];
                if(w0->d[m+i] < dig) borrow++;
                w0->d[m+i] -= dig;
            }
            if(w0->d[k+1] < borrow){
                w0->d[k+1] = 0;
                carry = 0;
                for(i = 0; i < y0; i++){
                    psum = w0->d[m+i] + y->d[i] + carry;
                    if(psum > y->d[i]) carry = 0;
                    if(psum < y->d[i]) carry = 1;
                    w0->d[m+i] = psum;
                }
                attemp--;
            }else w0->d[k+1]-=borrow;
        }
        if(k == w00-1 && attemp == 0) w00--;
        else if(y!=z) z->d[m] = attemp;
    }
    if(y != z) z->l = ((w00-y0+1) | sz);
    w0->l = y0;
    my_lzero(y);
    my_lzero(z);
    if(x != z){
        my_lzero(w0);
        if(d != 1) my_div_ud(w0,d,x);
        else my_copy(w0,x);
        if(x->l != 0) x->l |= sx;
    }
    if(d != 1) my_div_ud(y,d,y);
    y->l |= sy;
    gp->ff = check;
}

void my_comex(my_pbig x, my_pbig y, my_pbig z, my_pbig w, my_pbig q, my_pbig r, my_gp *gp){
    
    BOOL check = 0;
    if(w == r){
        gp->err_code = 4;
        return;
    }
    check = gp->ff;
    gp->ff = 0;
    my_mul(x,y,gp->p0,gp);
    if(x != z && y != z) my_add(gp->p0,z,gp->p0,gp);
    my_div(gp->p0,w,q,gp);
    if(q != r) my_copy(gp->p0,r);
    gp->ff = check;
}

int my_lb2(my_pbig x){
    
    int xl = 0,lg2 = 0;
    my_uint top = 0;
    
    if(my_size(x) == 0) return 0;
    xl = (int)(x->l & MY_OBITS);
    lg2 = 32 * (xl-1);
    top = x->d[xl-1];
    while(top >= 1){
        lg2++;
        top/=2;
    }
    return lg2;
}

//根据不同的d值,实现相应的计算,如加法运算等等
static void my_select(my_pbig x, int d, my_pbig y, my_pbig z, my_gp *gp){
    
    int sx = 0,sy = 0,sz = 0,jf = 0,xgty = 0;
    gp->err_code = 0;
    
    if(my_jint(x) || my_jint(y)){
        gp->err_code = MY_MATH_BIG_NUMBER_TOO_LONG;
        return;
    }
    sx = my_get_sym(x);
    sy = my_get_sym(y);
    x->l &= MY_OBITS;
    y->l &= MY_OBITS;
    xgty = my_cmp(x,y);
    jf = (1+sx) + (1+d*sy) / 2;
    switch(jf){
        case 0:
            if(xgty >= 0) my_add_u(x,y,z,gp);
            else my_add_u(y,x,z,gp);
            sz = (-1);
            break;
        case 1:
            if(xgty <= 0){
                my_sub_u(y,x,z,gp);
                sz = 1;
            }else{
                my_sub_u(x,y,z,gp);
                sz = (-1);
            }
            break;
        case 2:
            if(xgty >= 0){
                my_sub_u(x,y,z,gp);
                sz = 1;
            }else{
                my_sub_u(y,x,z,gp);
                sz = (-1);
            }
            break;
        case 3:
            if(xgty >= 0) my_add_u(x,y,z,gp);
            else my_add_u(y,x,z,gp);
            sz = 1;
            break;
    }
    if(sz < 0) z->l ^= MY_INBITS;
    if(x != z && sx < 0) x->l ^= MY_INBITS;
    if(y != z && y != x && sy < 0) y->l ^= MY_INBITS;
}

//z=x-n,实现一个大数减去一个有符号的数
void my_sub_d(my_pbig x, int n, my_pbig z, my_gp *gp){
    my_set_d(n,gp->p0);
    my_select(x,(-1),gp->p0,z,gp);
}

int my_tbit(my_pbig x, int n, my_gp *gp){
    
    if((x->d[n/32] & ((my_uint)1<<(n%32))) >0) return 1;
    return 0;
}

void my_ls(my_pbig p, my_pbig r, my_pbig vp, my_pbig v, my_gp *gp){
    
    int i = 0,nb = 0;
    if(my_size(r) == 0){
        my_zero(vp);
        my_set_d(2,v);
        my_pn(v,v,gp);
        return;
    }
    if(my_size(r) == 1 || my_size(r) == (-1)){
        my_set_d(2,vp);
        my_pn(vp,vp,gp);
        my_copy(p,v);
        return;
    }
    my_copy(p,gp->p3);
    my_set_d(2,gp->p4);
    my_pn(gp->p4,gp->p4,gp);
    my_copy(gp->p4,gp->p8);
    my_copy(gp->p3,gp->p9);
    my_copy(r,gp->p1);
    my_set_sym(1,gp->p1);
    my_sub_d(gp->p1,1,gp->p1,gp);
    nb = my_lb2(gp->p1);
    for(i = nb-1; i >= 0; i--){
        if(my_tbit(gp->p1,i,gp)){
            my_mulmodn(gp->p8,gp->p9,gp->p8,gp);
            my_submodn(gp->p8,gp->p3,gp->p8,gp);
            my_mulmodn(gp->p9,gp->p9,gp->p9,gp);
            my_submodn(gp->p9,gp->p4,gp->p9,gp);
        }else{
            my_mulmodn(gp->p9,gp->p8,gp->p9,gp);
            my_submodn(gp->p9,gp->p3,gp->p9,gp);
            my_mulmodn(gp->p8,gp->p8,gp->p8,gp);
            my_submodn(gp->p8,gp->p4,gp->p8,gp);
        }
    }
    my_copy(gp->p9,v);
    if(v != vp) my_copy(gp->p8,vp);
}

//大数x除以一个有符号的整数n,商为z,余数作为返回值(余数为真实的余数)
int my_div_d(my_pbig x, int n, my_pbig z, my_gp *gp){
    
    my_uint sx = 0;
    int r = 0,i = 0,msb = 0;
    my_uint lsb = 0;
    
    //判断大数使用uint数是否大于65535
    if(my_jint(x)) {
        gp->err_code = MY_MATH_BIG_NUMBER_TOO_LONG;
        return 0;
    }
    //判断除数是否为0
    if(n == 0) {
        gp->err_code = MY_MATH_DUVUSOR_QT_0;
        return 0;
    }
    //判断被除数是否为0
    if(x->l == 0){
        my_zero(z);
        return 0;
    }
    //判断除数是否为1
    if(n == 1){
        my_copy(x,z);
        return 0;
    }
    sx = (x->l & MY_INBITS);
    if(n == 2){
        my_copy(x,z);
        msb = (int)(z->l & MY_OBITS) - 1;
        r = (int)z->d[0] & 1;
        //逐位除2取商值
        for(i = 0; ; i++){
            z->d[i] >>= 1;
            if(i == msb){
                if(z->d[i] == 0) my_lzero(z);
                break;
            }
            //高位的最低位如果是1的话,在除以2之后低位的最高位会变成1
            lsb = z->d[i+1] & 1;
            z->d[i] |= (lsb << (31));
        }
        if(sx == 0) return r;
        else return (-r);
    }
    if(n < 0){
        n = (-n);
        r = (int)my_div_ud(x,(my_uint)n,z);
        if(z->l != 0) z->l ^= MY_INBITS;
    }else r = (int)my_div_ud(x,(my_uint)n,z);
    if(sx == 0) return r;
    else return (-r);
}

//计算大数x关于n的余数,余数作为函数返回值
int my_remain(my_pbig x, int n, my_gp *gp){
    
    int r = 0;
    my_uint sx = 0;
    sx = (x->l & MY_INBITS);
    
    /*
     在不知道uint实际占有几个字节的情况下,uint最小占有一个字节也就是8位
     当除数是2(占两位)或者8(占4位)的时候,只需要用大数x的最低位也就是一个uint值对除数取余就是大数x关于n的余数
     */
    if(n == 2){
        if((int)(x->d[0] % 2) == 0) return 0;
        else{
            if(sx == 0) return 1;
            else return (-1);
        }
    }
    if(n == 8){
        r = (int)(x->d[0] % 8);
        if(sx != 0) r = -r;
        return r;
    }
    my_copy(x,gp->p0);
    return my_div_d(gp->p0,n,gp->p0,gp);
}

int my_jack(my_pbig a, my_pbig n, my_gp *gp){
    
    my_pbig w = NULL;
    int nm8 = 0,onm8 = 0,t = 0;
    
    if(my_size(a) == 0 || my_size(n) < 1) return 0;
    t = 1;
    my_copy(n,gp->p2);
    nm8 = my_remain(gp->p2,8,gp);
    if(nm8 % 2 == 0) return 0;
    
    if(my_size(a) < 0){
        if(nm8 % 4 == 3) t = -1;
        my_neg(a,gp->p1);
    }else my_copy(a,gp->p1);
    while(my_size(gp->p1) != 0){
        while(my_remain(gp->p1,2,gp) == 0){
            my_div_d(gp->p1,2,gp->p1,gp);
            if(nm8 == 3 || nm8 == 5) t = -t;
        }
        if(my_cmp(gp->p1,gp->p2) < 0){
            onm8 = nm8;
            w = gp->p1; gp->p1 = gp->p2; gp->p2 = w;
            nm8 = my_remain(gp->p2,8,gp);
            if(onm8 % 4 == 3 && nm8 % 4 == 3) t = -t;
        }
        my_sub_u(gp->p1,gp->p2,gp->p1,gp);
        my_div_d(gp->p1,2,gp->p1,gp);
        if(nm8 == 3 || nm8 == 5) t = -t;
    }
    if(my_size(gp->p2) == 1) return t;
    return 0;
}

//z=x*n,一个大数乘以一个有符号的整数
void my_mul_d(my_pbig x, int n, my_pbig z, my_gp *gp){
    
    if(my_jint(x)){
        gp->err_code = MY_MATH_BIG_NUMBER_TOO_LONG;
        return;
    }
    if(n == 0){
        my_zero(z);
        return;
    }
    if(n == 1){
        my_copy(x,z);
        return;
    }
    if(n < 0){
        n = (-n);
        my_mul_u(x,(my_uint)n,z,gp);
        if(z->l != 0) z->l ^= MY_INBITS;
    }else my_mul_u(x,(my_uint)n,z,gp);
}

//从字符串中读取一个大数,读出来的大数是一个正数,暂定最多支持读取64*4=256长度的字符串
void my_read_bin(int len, const char *ptr, my_pbig x, my_gp *gp){

    int i = 0,j = 0,n = 0,r = 0;
    my_uint wrd = 0;
    gp->err_code = 0;

    my_zero(x);
    if(len <= 0) return;
    if(len > 256){
        gp->err_code = MY_MATH_READ_BIN_TOO_LONG;
        return;
    }
    while(*ptr == 0){
        ptr++; len--;
        if(len == 0) return;
    }
    n = len/4;
    r = len%4;
    if(r != 0){
        n++;
        //存储不足四字节的剩余最高为字节
        for(j = 0; j < r; j++) {wrd <<= 8; wrd |= (unsigned char)(*ptr++);}
    }
    x->l = n;
    if(r != 0){
        n--;
        x->d[n] = wrd;
    }
    for(i = n-1; i >= 0; i--){
        for(j = 0; j < 4; j++) {wrd <<= 8; wrd |= (unsigned char)(*ptr++); }
        x->d[i] = wrd;
    }
    my_lzero(x);
}

int my_getdig(my_pbig x, int i){
    
    int k = 0;
    my_uint n = 0;
    i--;
    n = x->d[i/8];
    k = i % 8;
    for(i = 1; i <= k; i++) n = n / 16;
    return (int)(n % 16);
}

int my_numdig(my_pbig x){
    
    int nd = 0;
    if(x->l == 0) return 0;
    nd = (int)(x->l & (MY_OBITS))*8;
    while(my_getdig(x,nd) == 0) nd--;
    return nd;
}

void my_putdig(int n, my_pbig x, int i, my_gp *gp){
    
    int j = 0,k = 0,lx = 0;
    my_uint m = 0,p = 0;
    my_uint s = 0;
    
    s = (x->l & (MY_INBITS));
    lx = (int)(x->l & (MY_OBITS));
    m = my_getdig(x,i);
    p = n;
    i--;
    j = i / 8;
    k = i % 8;
    for(i = 1; i <= k; i++){
        m *= 16;
        p *= 16;
    }
    if(j >= 64 && (gp->ff || j >= 2 * 64)){
        gp->err_code = 2;
        return;
    }
    x->d[j] = (x->d[j]-m)+p;
    if(j >= lx) x->l = ((j+1)|s);
    my_lzero(x);
}

void my_odn(my_pbig x, my_pbig y, my_gp *gp){
    
    int i = 0,ln = 0,ld = 0;
    my_uint ly = 0;
    if(!my_jint(x)){
        my_set_d(1,y);
        return;
    }
    ly = (x->l & MY_OBITS);
    ln = (int)(ly & 0xFFFF);
    ld = (int)((ly >> 16) & 0xFFFF);
    for(i = 0; i < ld; i++) y->d[i] = x->d[ln+i];
    if(x == y) for(i = 0; i < ln; i++) y->d[ld+i] = 0;
    else for(i = ld; i < my_len(y); i++) y->d[i] = 0;
    y->l = ld;
}

void my_nur(my_pbig x, my_pbig y, my_gp *gp){
    
    int i = 0,ln = 0,ld = 0;
    my_uint s = 0,ly = 0;
    
    if(my_jint(x)){
        s = (x->l & MY_INBITS);
        ly = (x->l & MY_OBITS);
        ln = (int)(ly & 0xFFFF);
        if(ln == 0){
            if(s == MY_INBITS) my_set_d((-1),y);
            else my_set_d(1,y);
            return;
        }
        ld = (int)((ly >> 16) & 0xFFFF);
        if(x != y){
            for(i = 0; i < ln; i++) y->d[i] = x->d[i];
            for(i = ln; i < my_len(y); i++) y->d[i] = 0;
        }else for(i = 0; i < ld; i++) y->d[ln+i] = 0;
        y->l = (ln|s);
    }else my_copy(x,y);
}

int my_to_redix(my_pbig x, char * string, my_gp *gp){
    
    int s = 0,i = 0,n = 0,ch = 0,rp = 0,nd = 0,m = 0;
    BOOL check = 0,done = 0;
    my_uint lx = 0;
    gp->err_code = 0;
    
    s = my_get_sym(x);
    my_set_sym(1,x);
    lx = x->l;
    //长度为零直接返货字符串"0"
    if(lx == 0){
        string[0]='0';
        string[1]='\0';
        return 1;
    }
    //如果是负数添加符号位
    if(s == (-1)){
        string[n] = '-';
        n++;
    }
    my_nur(x,gp->p6,gp);
    while(1){
        nd = my_numdig(gp->p6);
        m = nd;
        if(rp > m) m = rp;
        for(i = m; i > 0; i--){
            if(i == rp){
                string[n] = '.';
                n++;
            }
            if(i > nd) ch = '0';
            else{
                ch = my_getdig(gp->p6,i);
                check = gp->ff;
                gp->ff = 0;
                my_putdig(0,gp->p6,i,gp);
                gp->ff = check;
                ch += 48;
                if(ch >= 58) ch += 7;
                if(ch >= 91) ch += 6;
            }
            if(i < rp && ch == '0' && my_size(gp->p6) == 0) break;
            string[n] = (unsigned char)(ch);
            n++;
        }
        if(done) break;
        my_odn(x,gp->p6,gp);
        if(my_size(gp->p6) == 1) break;
        string[n] = '/';
        n++;
        done = 1;
    }
    string[n] = '\0';
    my_set_sym(s,x);
    return n;
}

int my_moddiv(my_pbig x, my_pbig y, my_pbig w, my_gp *gp){
    
    int gcd = 0;
    if(x == y){
        gp->err_code = 4;
        return 0;
    }
    my_rn(y,gp->p6,gp);
    gcd = my_invmod(gp->p6,gp->N,gp->p6,gp);
    if(gcd != 1) my_zero(w);
    else{
        my_pn(gp->p6,gp->p6,gp);
        my_mulmodn(x,gp->p6,w,gp);
    }
    return gcd;
}

//z=x+n,实现一个大数加上一个有符号的数
void my_add_d(my_pbig x, int n, my_pbig z, my_gp *gp){
    my_set_d(n,gp->p0);
    my_select(x,1,gp->p0,z,gp);
}

BOOL my_sls(my_pbig x, my_pbig w, my_gp *gp){
    
    int t = 0,js = 0;
    my_copy(x,w);
    if(my_size(w) == 0) return 1;
    my_rn(w,w,gp);
    
    if(my_size(w) == 1){
        my_pn(w,w,gp);
        return 1;
    }
    if(my_size(w) == 4){
        my_set_d(2,w);
        my_pn(w,w,gp);
        return 1;
    }
    if(my_jack(w,gp->N,gp) != 1){
        my_zero(w);
        return 0;
    }
    js = gp->MNE % 4 - 2;
    my_add_d(gp->N,js,gp->p10,gp);
    my_div_d(gp->p10,4,gp->p10,gp);
    if(js == 1){
        my_pn(w,gp->p2,gp);
        my_copy(gp->tmp,w);
        while(1){
            if(my_div_d(gp->p10,2,gp->p10,gp) != 0) my_mulmodn(w,gp->p2,w,gp);
            if(my_size(gp->p10) == 0) break;
            my_mulmodn(gp->p2,gp->p2,gp->p2,gp);
        }
    }else{
        for(t = 1; ; t++){
            if(t == 1) my_copy(w,gp->p4);
            else{
                my_mul_d(w,t,gp->p4,gp);
                my_div(gp->p4,gp->N,gp->N,gp);
                my_mul_d(gp->p4,t,gp->p4,gp);
                my_div(gp->p4,gp->N,gp->N,gp);
            }
            my_sub_d(gp->p4,4,gp->p1,gp);
            if(my_jack(gp->p1,gp->N,gp) == js) break;
        }
        my_sub_d(gp->p4,2,gp->p3,gp);
        my_pn(gp->p3,gp->p3,gp);
        my_ls(gp->p3,gp->p10,w,w,gp);
        if(t != 1){
            my_set_d(t,gp->p11);
            my_pn(gp->p11,gp->p11,gp);
            my_moddiv(w,gp->p11,w,gp);
        }
    }
    return 1;
}

//开辟num块,每块大小为size的内存空间
void * my_alloc(int num, int size, my_gp *gp){
    
    char * p = NULL;
    if(gp == NULL){//无错误记录
        p = (char *)calloc(num,size);
        return(void *)p;
    }
    p = (char *)calloc(num,size);//有错误记录
    if(p == NULL) gp->err_code = MY_MATH_CALLOC_ERROR;
    return (void *)p;
}

//释放addr指向的内存空间
void my_free(void * addr){
    if(addr != NULL) free(addr); addr = NULL;
}

//z=x+y,实现两个大数的相加
void my_add(my_pbig x, my_pbig y, my_pbig z, my_gp *gp){
    my_select(x,1,y,z,gp);
}
//z=x-y,实现两个大数的相减
void my_sub(my_pbig x, my_pbig y, my_pbig z, my_gp *gp){
    my_select(x,(-1),y,z,gp);
}

//u除以v,如果商大于uint能表示的最大数,就返回0
static my_uint my_qdiv(my_ullong u, my_ullong v){
    
    my_ullong lq = u/v;
    if(lq >= MY_UMAX) return 0;
    return (my_uint)lq;
}

my_uint my_lmuldv(my_uint a, my_uint c, my_uint m, my_uint *rp){
    
    my_uint q = 0;
    union my_dword dble;
    dble.f[MY_L] = c;
    dble.f[MY_H] = a;
    q = (my_uint)(dble.r / m);
    *rp = (my_uint)(dble.r - (my_ullong)q * m);
    return q;
}

int my_gcd(my_pbig x, my_pbig y, my_pbig xd, my_pbig yd, my_pbig z, my_gp *gp){
    
    int s = 0,n = 0,iter = 0;
    my_uint r = 0,a = 0,b = 0,c = 0,d = 0;
    my_uint q = 0,m = 0,sr = 0;
    union my_dword uu,vv;
    my_ullong u = 0,v = 0,lr = 0;
    BOOL last = 0,dplus = 1;
    my_pbig t = NULL;
    gp->err_code = 0;
    
    my_copy(x,gp->p1);
    my_copy(y,gp->p2);
    s = my_get_sym(gp->p1);
    my_set_sym(1,gp->p1);
    my_set_sym(1,gp->p2);
    my_set_d(1,gp->p3);
    my_zero(gp->p4);
    
    while(my_size(gp->p2) != 0){
        if(b == 0){
            my_div(gp->p1,gp->p2,gp->p5,gp);
            t = gp->p1;
            gp->p1 = gp->p2;
            gp->p2 = t;
            my_mul(gp->p4,gp->p5,gp->p0,gp);
            my_add(gp->p3,gp->p0,gp->p3,gp);
            t = gp->p3;
            gp->p3 = gp->p4;
            gp->p4 = t;
            iter++;
        }else{
            my_mul_u(gp->p1,c,gp->p5,gp);
            my_mul_u(gp->p1,a,gp->p1,gp);
            my_mul_u(gp->p2,b,gp->p0,gp);
            my_mul_u(gp->p2,d,gp->p2,gp);
            if(!dplus){
                my_sub_u(gp->p0,gp->p1,gp->p1,gp);
                my_sub_u(gp->p5,gp->p2,gp->p2,gp);
            }else{
                my_sub_u(gp->p1,gp->p0,gp->p1,gp);
                my_sub_u(gp->p2,gp->p5,gp->p2,gp);
            }
            my_mul_u(gp->p3,c,gp->p5,gp);
            my_mul_u(gp->p3,a,gp->p3,gp);
            my_mul_u(gp->p4,b,gp->p0,gp);
            my_mul_u(gp->p4,d,gp->p4,gp);
            if(a == 0) my_copy(gp->p0,gp->p3);
            else my_add_u(gp->p3,gp->p0,gp->p3,gp);
            my_add_u(gp->p4,gp->p5,gp->p4,gp);
        }
        if(my_size(gp->p2) == 0) break;
        n = (int)gp->p1->l;
        if(n == 1){
            last = 1;
            u = gp->p1->d[0];
            v = gp->p2->d[0];
        }else{
            m = gp->p1->d[n-1] + 1;
            if(n > 2 && m != 0){
                uu.f[MY_H] = my_lmuldv(gp->p1->d[n-1],gp->p1->d[n-2],m,&sr);
                uu.f[MY_L] = my_lmuldv(sr,gp->p1->d[n-3],m,&sr);
                vv.f[MY_H] = my_lmuldv(gp->p2->d[n-1],gp->p2->d[n-2],m,&sr);
                vv.f[MY_L] = my_lmuldv(sr,gp->p2->d[n-3],m,&sr);
            }else{
                uu.f[MY_H] = gp->p1->d[n-1];
                uu.f[MY_L] = gp->p1->d[n-2];
                vv.f[MY_H] = gp->p2->d[n-1];
                vv.f[MY_L] = gp->p2->d[n-2];
                if(n == 2) last = 1;
            }
            u = uu.r;
            v = vv.r;
        }
        dplus = 1;
        a = 1; b = 0; c = 0; d = 1;
        while(1){
            if(last){
                if(v == 0) break;
                q = my_qdiv(u,v);
                if(q == 0) break;
            }else{
                if(dplus){
                    if((my_uint)(v-c) == 0 || (my_uint)(v+d) == 0) break;
                    q = my_qdiv(u+a,v-c);
                    if(q == 0) break;
                    if(q != my_qdiv(u-b,v+d)) break;
                }else{
                    if((my_uint)(v+c) == 0 || (my_uint)(v-d) == 0) break;
                    q = my_qdiv(u-a,v+c);
                    if(q == 0) break;
                    if(q != my_qdiv(u+b,v-d)) break;
                }
            }
            if(q == 1){
                if((my_uint)(b+d) >= MY_UMAX) break;
                r = a + c;  a = c; c = r;
                r = b + d;  b = d; d = r;
                lr = u - v; u = v; v = lr;
            }else{
                if(q >= ((MY_UMAX-b) / d)) break;
                r = a+q*c;  a = c; c = r;
                r = b+q*d;  b = d; d = r;
                lr = u-q*v; u = v; v = lr;
            }
            iter++;
            dplus = !dplus;
        }
        iter %= 2;
    }
    if(s == (-1)) iter++;
    if(iter%2 == 1) my_sub_u(y,gp->p3,gp->p3,gp);
    if(xd != yd){
        my_neg(x,gp->p2);
        my_comex(gp->p2,gp->p3,gp->p1,y,gp->p4,gp->p4,gp);
        my_copy(gp->p4,yd);
    }
    my_copy(gp->p3,xd);
    if(z != xd && z != yd) my_copy(gp->p1,z);
    return (my_size(gp->p1));
}

int my_invmod(my_pbig x, my_pbig y, my_pbig z, my_gp *gp){
    return my_gcd(x,y,z,z,z,gp);
}

//对x左移n位,n为负数时,x右移|n|位
my_uint my_leftbits(my_uint x, int n){
    
    if(n == 0) return x;
    if(n > 0) x <<= n;
    else x >>= (-n);
    return x;
}

//将x赋值为0
void my_zero(my_pbig x){
    
    int i = 0;
    if(x == NULL) return;
    for(i = 0; i < my_len(x); i++) x->d[i] = 0;
    x->l = 0;
}

//将一个无符号的数n赋值给x
void my_set_ud(unsigned int n, my_pbig x){
    
    my_zero(x);
    if(n == 0) return;
    x->d[0] = (my_uint)n;
    x->l = 1;
}

//将一个有符号的数n赋值给x
void my_set_d(int n, my_pbig x){
    
    my_uint s = 0;
    if(n == 0) {my_zero(x); return;}
    if(n < 0){
        s = MY_INBITS;
        n = (-n);
    }
    my_set_ud((unsigned int)n,x);
    x->l |= s;
}

//初始化一个大数,并进行内存对齐,x->d指向的地址值是sizeof(my_uint)的整数倍,很奇怪？！！
my_pbig my_init(int iv, my_gp *gp){
        
    my_pbig x = NULL;
    int align = 0;
    char * ptr = NULL;
    
    x = (my_pbig)my_alloc(MY_BIG_SIZE(MY_BIG_N),1,gp);//开辟一个能容纳66个my_uint的大数空间
    if(x == NULL) return x;
    ptr = (char *)&x->d;
    align = (int)(ptr + sizeof(my_uint *)) % sizeof(my_uint);
    x->d = (my_uint *)(ptr + sizeof(my_uint *) + sizeof(my_uint) - align);
    if(iv != 0) my_set_d(iv,x);
    return x;
}

//组内变量内存对齐
my_pbig my_av_mem(char *mem, int index, int sz){
    
    my_pbig x = NULL;
    int align = 0;
    char * ptr = NULL;
    int offset = 0,r = 0;
    
    r = (unsigned long)mem % MY_LSIZE;
    if(r > 0) offset = MY_LSIZE - r;
    x = (my_pbig)&mem[offset + MY_BIG_SIZE(sz) * index];
    ptr = (char *)&x->d;
    align = (int)(ptr + sizeof(my_uint *)) % sizeof(my_uint);
    x->d = (my_uint *)(ptr + sizeof(my_uint *) + sizeof(my_uint) - align);
    return x;
}

//组内变量内存对齐
my_pbig my_lmem(char *mem, int index){
    
    return my_av_mem(mem,index,MY_BIG_N);
}

/*
 开辟过程变量空间,将所有中间变量放到同一空间内部,这样的好处是不用开辟多个空间,不用维护多个指针
 释放空间的时候只需要释放组空间即可
 */
void * my_calloc_gp(int num, my_gp *gp){
    
    return my_alloc(MY_GROW_BIG_SIZE(num,MY_BIG_N),1,gp);
}

//设置过程变量值
my_gp * my_gpb(my_gp *gp){
        
    if(gp == NULL) return NULL;
    //必须保证unsigned int的字节数是4,unsigned long long的字节数大于等于8
    if(sizeof(my_ullong) < 2*sizeof(my_uint)){
        gp->err_code = MY_MATH_2UINT_SIZE_LT_ULONG_SIZE;
        return gp;
    }
    if(sizeof(my_uint) != 4){
        gp->err_code = MY_MATH_UINT_SIZE_NOT_QT_4;
        return gp;
    }
    gp->ff = 1;
    gp->MNE = 0;
    gp->MNN = 0;
    gp->room = (char *)my_calloc_gp(20,gp);
    gp->p0 = my_lmem(gp->room,0);
    gp->p1 = my_lmem(gp->room,1);
    gp->p2 = my_lmem(gp->room,2);
    gp->p3 = my_lmem(gp->room,3);
    gp->p4 = my_lmem(gp->room,4);
    gp->p5 = my_lmem(gp->room,5);
    gp->p6 = my_lmem(gp->room,6);
    gp->p7 = my_lmem(gp->room,7);
    gp->p8 = my_lmem(gp->room,8);
    gp->p9 = my_lmem(gp->room,9);
    gp->p10 = my_lmem(gp->room,10);
    gp->p11 = my_lmem(gp->room,11);
    gp->p12 = my_lmem(gp->room,12);
    gp->p13 = my_lmem(gp->room,13);
    gp->p14 = my_lmem(gp->room,14);
    gp->p15 = my_lmem(gp->room,15);
    gp->N = my_lmem(gp->room,16);
    gp->P1 = my_lmem(gp->room,17);
    gp->P2 = my_lmem(gp->room,18);
    gp->tmp = my_lmem(gp->room,19);
    return gp;
}

//创建过程变量,并初始化
my_gp * my_init_gp(void){
        
    my_gp * temp_gp = (my_gp *)calloc(1,sizeof(my_gp));
    return my_gpb(temp_gp);
}

//释放组空间
void my_free_gp(char *mem, int len, my_gp *gp){
    
    if(mem == NULL) return;
    memset(mem,0,MY_GROW_BIG_SIZE(len,MY_BIG_N));
    my_free(mem);
}

//释放一个大数
void my_clear(my_pbig x){
    
    if(x == NULL) return;
    my_zero(x);
    my_free(x);
}

//释放过程变量
void my_gp_clear(my_gp *gp){
    
    if(gp == NULL) return;
    my_free_gp(gp->room,20,gp);
    my_free(gp);
    gp = NULL;
}

//将x的值赋值给y
void my_copy(my_pbig x, my_pbig y){
    
    int i = 0;
    if(x == y || y == NULL) return;
    if(x == NULL){
        my_zero(y);
        return;
    }
    for(i = my_len(x); i < my_len(y); i++) y->d[i] = 0;
    for(i = 0; i < my_len(x); i++) y->d[i] = x->d[i];
    y->l = x->l;
}

//一个大数的符号位取反
void my_neg(my_pbig x, my_pbig y){
    
    my_copy(x,y);
    if(y->l != 0) y->l ^= MY_INBITS;
}

//比较两个大数,如果x>y返回1,如果x<y返回-1,如果相等返回0
int my_cmp(my_pbig x, my_pbig y){
    
    int m = 0,n = 0,sig = 0;
    my_uint sx = 0,sy = 0;
    if(x == y) return 0;
    sx = (x->l & MY_INBITS);
    sy = (y->l & MY_INBITS);
    if(sx == 0) sig = 1;
    else sig = (-1);
    if(sx != sy) return sig;
    m = (int)(x->l & MY_OBITS);
    n = (int)(y->l & MY_OBITS);
    if(m > n) return sig;
    if(m < n) return -sig;
    while(m > 0){
        m--;
        if(x->d[m] > y->d[m]) return sig;
        if(x->d[m] < y->d[m]) return -sig;
    }
    return 0;
}

int my_mov_win(my_pbig x, my_pbig x3, int i, int *nbs, int * nzs, int store, my_gp *gp){
    
    int nb = 0,j = 0,r = 0,biggest = 0;
    nb = my_tbit(x3,i,gp) - my_tbit(x,i,gp);
    *nbs = 1;
    *nzs = 0;
    if(nb == 0) return 0;
    if(i == 0) return nb;
    biggest = 2 * store - 1;
    if(nb > 0) r = 1;
    else r = (-1);
    for(j = i-1; j > 0; j--){
        (*nbs)++;
        r *= 2;
        nb = my_tbit(x3,j,gp) - my_tbit(x,j,gp);
        if(nb > 0) r += 1;
        if(nb < 0) r -= 1;
        if(abs(r) > biggest) break;
    }
    if(r%2 != 0 && j != 0){
        if(nb > 0) r = (r-1)/2;
        if(nb < 0) r = (r+1)/2;
        (*nbs)--;
    }
    while(r % 2 == 0){
        r /= 2;
        (*nzs)++;
        (*nbs)--;
    }
    return r;
}

my_point * my_point_init(my_gp *gp){
    
    my_point * p = NULL;
    char * ptr = NULL;
    
    p = (my_point *)my_alloc(MY_PSIZE(64-1),1,gp);
    ptr = (char *)p + sizeof(my_point);
    p->X = my_lmem(ptr,0);
    p->Y = my_lmem(ptr,1);
    p->Z = my_lmem(ptr,2);
    p->flag = 2;
    return p;
}

my_point * my_point_av_mem(char *mem, int index, int sz, my_gp *gp){
    
    my_point * p = NULL;
    char * ptr = NULL;
    int offset = 0,r = 0;
    
    offset = 0;
    r = (unsigned long)mem % MY_LSIZE;
    if(r > 0) offset = MY_LSIZE - r;
    p = (my_point *)&mem[offset + index * MY_PSIZE(sz)];
    ptr = (char *)p + sizeof(my_point);
    p->X = my_av_mem(ptr,0,sz);
    p->Y = my_av_mem(ptr,1,sz);
    p->Z = my_av_mem(ptr,2,sz);
    p->flag = 2;
    return p;
}

my_point * my_point_mem(char *mem, int index, my_gp *gp){
    
    return my_point_av_mem(mem,index,MY_BIG_N,gp);
}

void * my_point_alloc(int num, my_gp *gp){
    
    return my_alloc(MY_GROW_PSIZE(num,MY_BIG_N),1,gp);
}

void my_memfree(char *mem, int num, my_gp *gp){
    
    if(mem == NULL) return;
    memset(mem,0,MY_GROW_PSIZE(num,MY_BIG_N));
    my_free(mem);
}

void my_point_clear(my_point *p){
    
    if(p == NULL) return;
    my_zero(p->X);
    my_zero(p->Y);
    if(p->flag == 0) my_zero(p->Z);
    my_free(p);
}

my_uint my_set_mod(my_pbig n, my_gp *gp){
    
    if(my_size(gp->N) != 0)
        if(my_cmp(n,gp->N) == 0) return gp->LN;
    if(my_size(n) <= 2){
        gp->err_code = 8;
        return (my_uint)0;
    }
    my_zero(gp->p6);
    my_zero(gp->p15);
    gp->MNE = my_remain(n,8,gp);
    gp->MNN = my_remain(n,9,gp);
    my_set_d(1,gp->tmp);
    gp->p6->l = 2;
    gp->p6->d[0] = 0;
    gp->p6->d[1] = 1;
    gp->p15->l = 1;
    gp->p15->d[0] = n->d[0];
    if(my_invmod(gp->p15,gp->p6,gp->p14,gp) != 1){
        gp->err_code = 8;
        return (my_uint)0;
    }
    gp->LN = 0 - gp->p14->d[0];
    my_copy(n,gp->N);
    my_pn(gp->tmp,gp->tmp,gp);
    return gp->LN;
}

void my_left(my_pbig x, int n, my_pbig w, my_gp *gp){
    
    my_uint s = 0;
    int i = 0,bl = 0;
    my_uint * gw = w->d;
    my_copy(x,w);
    if(w->l == 0 || n == 0) return;
    if(my_jint(w)) gp->err_code = 6;
    s = (w->l & (MY_INBITS));
    bl = (int)(w->l & (MY_OBITS)) + n;
    if(bl <= 0){
        my_zero(w);
        return;
    }
    if(bl > 64 && gp->ff) gp->err_code = 2;
    if(n > 0){
        for(i = bl - 1; i >= n; i--) gw[i] = gw[i-n];
        for(i = 0; i < n; i++) gw[i] = 0;
    }else{
        n = (-n);
        for(i = 0; i < bl; i++) gw[i] = gw[i+n];
        for(i = 0; i < n; i++) gw[bl+i] = 0;
    }
    w->l = (bl|s);
}

void my_pn(my_pbig x, my_pbig y, my_gp *gp){
    
    if(my_size(gp->N) == 0){
        gp->err_code = 9;
        return;
    }
    my_copy(x,y);
    my_div(y,gp->N,gp->N,gp);
    if(my_size(y) < 0) my_add(y,gp->N,y,gp);
    gp->ff = 0;
    my_left(y,(int)gp->N->l,gp->p0,gp);
    my_div(gp->p0,gp->N,gp->N,gp);
    gp->ff = 1;
    my_copy(gp->p0,y);
}

void my_rn(my_pbig x, my_pbig y, my_gp *gp){
    
    my_uint carry = 0,delay_carry = 0,m = 0,LN = 0,*w0g = NULL,*mg = NULL;
    int i = 0,j = 0,rn = 0,rn2 = 0;
    my_pbig w0 = NULL,modulus = NULL;
    union my_dword dble;
    
    w0 = gp->p0;
    modulus = gp->N;
    LN = gp->LN;
    my_copy(x,w0);
    delay_carry = 0;
    rn = (int)modulus->l;
    rn2 = rn+rn;
    mg = modulus->d;
    w0g = w0->d;
    for(i = 0; i < rn; i++){
        m = LN * w0->d[i];
        carry = 0;
        for(j = 0; j < rn; j++){
            dble.r = (my_ullong)m * modulus->d[j] + carry + w0->d[i+j];
            w0->d[i+j] = dble.f[MY_L];
            carry = dble.f[MY_H];
        }
        w0->d[rn+i] += delay_carry;
        if(w0->d[rn+i] < delay_carry) delay_carry = 1;
        else delay_carry = 0;
        w0->d[rn+i] += carry;
        if(w0->d[rn+i] < carry) delay_carry = 1;
    }
    w0->d[rn2] = delay_carry;
    w0->l = rn2 + 1;
    my_left(w0,(-rn),w0,gp);
    my_lzero(w0);
    if(my_cmp(w0,modulus) >= 0) my_sub_u(w0,modulus,w0,gp);
    my_copy(w0,y);
}

void my_negn(my_pbig x, my_pbig w, my_gp *gp){
    
    if(my_size(x) == 0){
        my_zero(w);
        return;
    }
    my_sub_u(gp->N,x,w,gp);
}

void my_pow_div(my_pbig x, my_pbig w, my_gp *gp){
    
    my_copy(x,gp->p1);
    if(my_remain(gp->p1,2,gp) != 0) my_add(gp->p1,gp->N,gp->p1,gp);
    my_div_d(gp->p1,2,gp->p1,gp);
    my_copy(gp->p1,w);
}

void my_addmodn(my_pbig x, my_pbig y, my_pbig w, my_gp *gp){
    
    my_add_u(x,y,w,gp);
    if(my_cmp(w,gp->N) >= 0) my_sub_u(w,gp->N,w,gp);
}

void my_submodn(my_pbig x, my_pbig y, my_pbig w, my_gp *gp){
    
    if(my_cmp(x,y) >= 0) my_sub_u(x,y,w,gp);
    else{
        my_sub_u(y,x,w,gp);
        my_sub_u(gp->N,w,w,gp);
    }
}

void my_lpmul(my_pbig x, int k, my_pbig w, my_gp *gp){
    
    int sign = 0;
    if(k == 0){
        my_zero(w);
        return;
    }
    if(k < 0){
        k = -k;
        sign = 1;
    }
    if(k <= 6){
        switch(k){
            case 1: my_copy(x,w);
                break;
            case 2: my_addmodn(x,x,w,gp);
                break;
            case 3:
                my_addmodn(x,x,gp->p0,gp);
                my_addmodn(x,gp->p0,w,gp);
                break;
            case 4:
                my_addmodn(x,x,w,gp);
                my_addmodn(w,w,w,gp);
                break;
            case 5:
                my_addmodn(x,x,gp->p0,gp);
                my_addmodn(gp->p0,gp->p0,gp->p0,gp);
                my_addmodn(x,gp->p0,w,gp);
                break;
            case 6:
                my_addmodn(x,x,w,gp);
                my_addmodn(w,w,gp->p0,gp);
                my_addmodn(w,gp->p0,w,gp);
                break;
        }
        if(sign == 1) my_negn(w,w,gp);
        return;
    }
    my_mul_u(x,(my_uint)k,gp->p0,gp);
    my_div(gp->p0,gp->N,gp->N,gp);
    my_copy(gp->p0,w);
    if(sign == 1) my_negn(w,w,gp);
}

void my_mulmodn(my_pbig x, my_pbig y, my_pbig w, my_gp *gp){
    
    if((x == NULL || x->l == 0) && x == w) return;
    if((y == NULL || y->l == 0) && y == w) return;
    if(y == NULL || x == NULL || x->l == 0 || y->l == 0){
        my_zero(w);
        return;
    }
    gp->ff = 0;
    my_mul(x,y,gp->p0,gp);
    my_rn(gp->p0,w,gp);
    gp->ff = 1;
}

BOOL my_grew_mul(int m, my_pbig *x, my_pbig *w, my_gp *gp){
    
    int i = 0;
    if(m == 0) return 1;
    if(m < 0) return 0;
    if(x == w){
        gp->err_code = 4;
        return 0;
    }
    if(m == 1){
        my_copy(gp->tmp,w[0]);
        my_moddiv(w[0],x[0],w[0],gp);
        return 1;
    }
    my_set_d(1,w[0]);
    my_copy(x[0],w[1]);
    for(i = 2; i < m; i++) my_mulmodn(w[i-1],x[i-1],w[i],gp);
    my_mulmodn(w[m-1],x[m-1],gp->p6,gp);
    if(my_size(gp->p6) == 0){
        gp->err_code = 1;
        return 0;
    }
    my_rn(gp->p6,gp->p6,gp);
    my_rn(gp->p6,gp->p6,gp);
    my_invmod(gp->p6,gp->N,gp->p6,gp);
    my_copy(x[m-1],gp->p5);
    my_mulmodn(w[m-1],gp->p6,w[m-1],gp);
    for(i = m-2; ; i--){
        if(i == 0){
            my_mulmodn(gp->p5,gp->p6,w[0],gp);
            break;
        }
        my_mulmodn(w[i],gp->p5,w[i],gp);
        my_mulmodn(w[i],gp->p6,w[i],gp);
        my_mulmodn(gp->p5,x[i],gp->p5,gp);
    }
    return 1;
}

void my_ecc_init(my_pbig a, my_pbig b, my_pbig p, my_gp *gp){
    
    int as = 0;
    gp->err_code = 0;
    my_set_mod(p,gp);
    gp->PL1 = my_size(a);
    if(MY_PV(gp->PL1) == MY_OVER){
        if(gp->PL1 >= 0){
            my_copy(a,gp->p1);
            my_div(gp->p1,p,p,gp);
            my_sub_u(p,gp->p1,gp->p1,gp);
            as = my_size(gp->p1);
            if(as < MY_OVER) gp->PL1 = -as;
        }
    }
    my_pn(a,gp->P1,gp);
    gp->PL2 = my_size(b);
    if(MY_PV(gp->PL2) == MY_OVER){
        if(gp->PL2 >= 0){
            my_copy(b,gp->p1);
            my_div(gp->p1,p,p,gp);
            my_sub_u(p,gp->p1,gp->p1,gp);
            as = my_size(gp->p1);
            if(as < MY_OVER) gp->PL2 = -as;
        }
    }
    my_pn(b,gp->P2,gp);
    return;
}

static void my_epoint_getrhs(my_pbig x, my_pbig y, my_gp *gp){
    
    my_mulmodn(x,x,y,gp);
    my_mulmodn(y,x,y,gp);
    if(MY_PV(gp->PL1) == MY_OVER) my_mulmodn( x,gp->P1,gp->p1,gp);
    else my_lpmul(x,gp->PL1,gp->p1,gp);
    my_addmodn(y,gp->p1,y,gp);
    if(MY_PV(gp->PL2) == MY_OVER) my_addmodn( y,gp->P2,y,gp);
    else{
        my_set_d(gp->PL2,gp->p1);
        my_pn(gp->p1,gp->p1,gp);
        my_addmodn( y,gp->p1,y,gp);
    }
}

BOOL my_set_point(my_pbig x, my_pbig y, my_point *p, my_gp *gp){
    
    BOOL valid = 0;
    gp->err_code = 0;
    if(x == NULL || y == NULL){
        my_copy(gp->tmp,p->X);
        my_copy(gp->tmp,p->Y);
        p->flag = 2;
        return 1;
    }
    my_pn(x,p->X,gp);
    my_epoint_getrhs(p->X,gp->p3,gp);
    valid = 0;
    if(x != y){
        my_pn(y,p->Y,gp);
        my_mulmodn(p->Y,p->Y,gp->p1,gp);
        if(my_cmp(gp->p1,gp->p3) == 0) valid = 1;
    }else{
        valid = my_sls(gp->p3,p->Y,gp);
        my_rn(p->Y,gp->p1,gp);
        if(my_remain(gp->p1,2,gp) != 0) my_sub_u(gp->N,p->Y,p->Y,gp);
    }
    if(valid){
        p->flag = 1;
        return 1;
    }
    return 0;
}

BOOL my_point_right(my_point *p, my_gp *gp){
    
    if(p->flag != 0) return 1;
    my_copy(gp->tmp,gp->p8);
    if(my_moddiv(gp->p8,p->Z,gp->p8,gp) > 1){
        my_set_point(NULL,NULL,p,gp);
        gp->err_code = 11;
        return 0;
    }
    my_mulmodn(gp->p8,gp->p8,gp->p1,gp);
    my_mulmodn(p->X,gp->p1,p->X,gp);
    my_mulmodn(gp->p1,gp->p8,gp->p1,gp);
    my_mulmodn(p->Y,gp->p1,p->Y,gp);
    my_copy(gp->tmp,p->Z);
    p->flag = 1;
    return 1;
}

int my_get_point(my_point *p, my_pbig x, my_pbig y, my_gp *gp){
    
    int lsb = 0;
    gp->err_code = 0;
    if(p->flag == 2){
        my_zero(x);
        my_zero(y);
        return 0;
    }
    if(!my_point_right(p,gp)){
        return (-1);
    }
    my_rn(p->X,x,gp);
    my_rn(p->Y,gp->p1,gp);
    if(x != y) my_copy(gp->p1,y);
    lsb = my_remain(gp->p1,2,gp);
    return lsb;
}

BOOL my_point_lmul(int m, my_pbig *work, my_point **p, my_gp *gp){
    
    int i = 0;
    BOOL inf = 0;
    my_pbig w[64];
    if(m > 64) return 0;
    for(i = 0; i < m; i++){
        if(p[i]->flag == 1) w[i] = gp->tmp;
        else w[i] = p[i]->Z;
        if(p[i]->flag == 2) {inf = 1; break;}
    }
    if(inf){
        for(i = 0; i < m; i++) my_point_right(p[i],gp);
        return 1;
    }
    if(!my_grew_mul(m,w,work,gp)){
        return 0;
    }
    for(i = 0; i < m; i++){
        my_copy(gp->tmp,p[i]->Z);
        p[i]->flag = 1;
        my_mulmodn(work[i],work[i],gp->p1,gp);
        my_mulmodn(p[i]->X,gp->p1,p[i]->X,gp);
        my_mulmodn(gp->p1,work[i],gp->p1,gp);
        my_mulmodn(p[i]->Y,gp->p1,p[i]->Y,gp);
    }
    return 1;
}

void my_ecc_ld(my_point *p, my_gp *gp){
    
    if(p->flag == 2) return;
    if(my_size(p->Y) == 0){
        my_set_point(NULL,NULL,p,gp);
        return;
    }
    my_set_d(1,gp->p1);
    if(MY_PV(gp->PL1) < MY_OVER){
        if(gp->PL1 != 0){
            if(p->flag == 1) my_pn(gp->p1,gp->p6,gp);
            else my_mulmodn(p->Z,p->Z,gp->p6,gp);
        }
        if(gp->PL1 == (-3)){
            my_submodn(p->X,gp->p6,gp->p3,gp);
            my_addmodn(p->X,gp->p6,gp->p8,gp);
            my_mulmodn(gp->p3,gp->p8,gp->p3,gp);
            my_addmodn(gp->p3,gp->p3,gp->p8,gp);
            my_addmodn(gp->p8,gp->p3,gp->p8,gp);
        }else{
            if(gp->PL1 != 0){
                my_mulmodn(gp->p6,gp->p6,gp->p3,gp);
                my_lpmul(gp->p3,gp->PL1,gp->p3,gp);
            }
            my_mulmodn(p->X,p->X,gp->p1,gp);
            my_addmodn(gp->p1,gp->p1,gp->p8,gp);
            my_addmodn(gp->p8,gp->p1,gp->p8,gp);
            if(gp->PL1 != 0) my_addmodn(gp->p8,gp->p3,gp->p8,gp);
        }
    }else{
        if(p->flag == 1) my_pn(gp->p1,gp->p6,gp);
        else my_mulmodn(p->Z,p->Z,gp->p6,gp);
        my_mulmodn(gp->p6,gp->p6,gp->p3,gp);
        my_mulmodn(gp->p3,gp->P1,gp->p3,gp);
        my_mulmodn(p->X,p->X,gp->p1,gp);
        my_addmodn(gp->p1,gp->p1,gp->p8,gp);
        my_addmodn(gp->p8,gp->p1,gp->p8,gp);
        my_addmodn(gp->p8,gp->p3,gp->p8,gp);
    }
    my_mulmodn(p->Y,p->Y,gp->p2,gp);
    my_mulmodn(p->X,gp->p2,gp->p3,gp);
    my_addmodn(gp->p3,gp->p3,gp->p3,gp);
    my_addmodn(gp->p3,gp->p3,gp->p3,gp);
    my_mulmodn(gp->p8,gp->p8,p->X,gp);
    my_submodn(p->X,gp->p3,p->X,gp);
    my_submodn(p->X,gp->p3,p->X,gp);
    if(p->flag == 1) my_copy(p->Y,p->Z);
    else my_mulmodn(p->Z,p->Y,p->Z,gp);
    my_addmodn(p->Z,p->Z,p->Z,gp);
    my_addmodn(gp->p2,gp->p2,gp->p7,gp);
    my_mulmodn(gp->p7,gp->p7,gp->p2,gp);
    my_addmodn(gp->p2,gp->p2,gp->p2,gp);
    my_submodn(gp->p3,p->X,gp->p3,gp);
    my_mulmodn(gp->p8,gp->p3,p->Y,gp);
    my_submodn(p->Y,gp->p2,p->Y,gp);
    p->flag = 0;
    return;
}

static BOOL my_ecurve_padd(my_point *p, my_point *pa, my_gp *gp){
    
    if(p->flag != 1){
        my_mulmodn(p->Z,p->Z,gp->p6,gp);
        my_mulmodn(pa->X,gp->p6,gp->p1,gp);
        my_mulmodn(gp->p6,p->Z,gp->p6,gp);
        my_mulmodn(pa->Y,gp->p6,gp->p8,gp);
    }else{
        my_copy(pa->X,gp->p1);
        my_copy(pa->Y,gp->p8);
    }
    if(pa->flag == 1) my_copy(gp->tmp,gp->p6);
    else my_mulmodn(pa->Z,pa->Z,gp->p6,gp);
    my_mulmodn(p->X,gp->p6,gp->p4,gp);
    if(pa->flag != 1) my_mulmodn(gp->p6,pa->Z,gp->p6,gp);
    my_mulmodn(p->Y,gp->p6,gp->p5,gp);
    my_submodn(gp->p1,gp->p4,gp->p1,gp);
    my_submodn(gp->p8,gp->p5,gp->p8,gp);
    if(my_size(gp->p1) == 0){
        if(my_size(gp->p8) == 0){
            return 0;
        }else{
            my_set_point(NULL,NULL,pa,gp);
            return 1;
        }
    }
    my_addmodn(gp->p4,gp->p4,gp->p6,gp);
    my_addmodn(gp->p1,gp->p6,gp->p4,gp);
    my_addmodn(gp->p5,gp->p5,gp->p6,gp);
    my_addmodn(gp->p8,gp->p6,gp->p5,gp);
    if(p->flag != 1){
        if(pa->flag != 1) my_mulmodn(pa->Z,p->Z,gp->p3,gp);
        else my_copy(p->Z,gp->p3);
        my_mulmodn(gp->p3,gp->p1,pa->Z,gp);
    }else{
        if(pa->flag != 1) my_mulmodn(pa->Z,gp->p1,pa->Z,gp);
        else my_copy(gp->p1,pa->Z);
    }
    my_mulmodn(gp->p1,gp->p1,gp->p6,gp);
    my_mulmodn(gp->p1,gp->p6,gp->p1,gp);
    my_mulmodn(gp->p6,gp->p4,gp->p6,gp);
    my_mulmodn(gp->p8,gp->p8,gp->p4,gp);
    my_submodn(gp->p4,gp->p6,pa->X,gp);
    my_submodn(gp->p6,pa->X,gp->p6,gp);
    my_submodn(gp->p6,pa->X,gp->p6,gp);
    my_mulmodn(gp->p8,gp->p6,gp->p2,gp);
    my_mulmodn(gp->p1,gp->p5,gp->p1,gp);
    my_submodn(gp->p2,gp->p1,gp->p5,gp);
    my_pow_div(gp->p5,pa->Y,gp);
    pa->flag = 0;
    return 1;
}

void my_point_copy(my_point *a, my_point *b){
    
    if(a == b || b == NULL) return;
    my_copy(a->X,b->X);
    my_copy(a->Y,b->Y);
    if(a->flag == 0) my_copy(a->Z,b->Z);
    b->flag = a->flag;
    return;
}

int my_point_add(my_point *p, my_point *pa, my_gp *gp){
    
    if(p == pa){
        my_ecc_ld(pa,gp);
        if(pa->flag == 2) return 0;
        return 2;
    }
    if(pa->flag == 2){
        my_point_copy(p,pa);
        return 1;
    }
    if(p->flag == 2){
        return 1;
    }
    if(!my_ecurve_padd(p,pa,gp)){
        my_ecc_ld(pa,gp);
        return 2;
    }
    if(pa->flag == 2) return 0;
    return 1;
}

void my_point_neg(my_point *p, my_gp *gp){
    
    if(p->flag == 2) return;
    if(my_size(p->Y) != 0) my_sub_u(gp->N,p->Y,p->Y,gp);
}

int my_point_lsub(my_point *p, my_point *pa, my_gp *gp){
    
    int r = 0;
    if(p == pa){
        my_set_point(NULL,NULL,pa,gp);
        return 0;
    }
    if(p->flag == 2){
        return 1;
    }
    my_point_neg(p,gp);
    r = my_point_add(p,pa,gp);
    my_point_neg(p,gp);
    return r;
}

int my_point_mul(my_pbig e, my_point *pa, my_point *pt, my_gp *gp){
    
    int i = 0,j = 0,n = 0,nb = 0,nbs = 0,nzs = 0,nadds = 0;
    my_point * table[8] = {0};
    my_pbig work[8] = {0};
    char * mem = NULL;
    char * mem1 = NULL;
    gp->err_code = 0;
    
    if(my_size(e) == 0){
        my_set_point(NULL,NULL,pt,gp);
        return 0;
    }
    my_copy(e,gp->p9);
    my_point_copy(pa,pt);
    if(my_size(gp->p9) < 0){
        my_neg(gp->p9,gp->p9);
        my_point_neg(pt,gp);
    }
    if(my_size(gp->p9) == 1) return 0;
    
    my_mul_d(gp->p9,3,gp->p10,gp);
    mem = (char *)my_point_alloc(8,gp);
    mem1 = (char *)my_calloc_gp(8,gp);
    for(i = 0; i <= 7; i++){
        table[i] = my_point_mem(mem,i,gp);
        work[i] = my_lmem(mem1,i);
    }
    my_point_copy(pt,table[0]);
    my_point_copy(table[0],table[7]);
    my_ecc_ld(table[7],gp);
    for(i = 1; i < 7; i++){
        my_point_copy(table[i-1],table[i]);
        my_point_add(table[7],table[i],gp);
    }
    my_point_add(table[6],table[7],gp);
    my_point_lmul(8,work,table,gp);
    nb = my_lb2(gp->p10);
    nadds = 0;
    my_set_point(NULL,NULL,pt,gp);
    for(i = nb-1; i >= 1;){
        n = my_mov_win(gp->p9,gp->p10,i,&nbs,&nzs,8,gp);
        for(j = 0; j < nbs; j++)
            my_ecc_ld(pt,gp);
        if(n>0){my_point_add(table[n/2],pt,gp); nadds++;}
        if(n<0){my_point_lsub(table[(-n)/2],pt,gp); nadds++;}
        i -= nbs;
        if(nzs){
            for(j = 0; j < nzs; j++) my_ecc_ld(pt,gp);
            i -= nzs;
        }
    }
    my_memfree(mem,8,gp);
    my_free_gp(mem1,8,gp);
    return nadds;
}

//----------------add by xiao yun song-------------------
const unsigned long ltm_prime_tab[] = {
  0x0002, 0x0003, 0x0005, 0x0007, 0x000B, 0x000D, 0x0011, 0x0013,
  0x0017, 0x001D, 0x001F, 0x0025, 0x0029, 0x002B, 0x002F, 0x0035,
  0x003B, 0x003D, 0x0043, 0x0047, 0x0049, 0x004F, 0x0053, 0x0059,
  0x0061, 0x0065, 0x0067, 0x006B, 0x006D, 0x0071, 0x007F, 0x0083,
  0x0089, 0x008B, 0x0095, 0x0097, 0x009D, 0x00A3, 0x00A7, 0x00AD,
  0x00B3, 0x00B5, 0x00BF, 0x00C1, 0x00C5, 0x00C7, 0x00D3, 0x00DF,
  0x00E3, 0x00E5, 0x00E9, 0x00EF, 0x00F1, 0x00FB, 0x0101, 0x0107,
  0x010D, 0x010F, 0x0115, 0x0119, 0x011B, 0x0125, 0x0133, 0x0137,
  0x0139, 0x013D, 0x014B, 0x0151, 0x015B, 0x015D, 0x0161, 0x0167,
  0x016F, 0x0175, 0x017B, 0x017F, 0x0185, 0x018D, 0x0191, 0x0199,
  0x01A3, 0x01A5, 0x01AF, 0x01B1, 0x01B7, 0x01BB, 0x01C1, 0x01C9,
  0x01CD, 0x01CF, 0x01D3, 0x01DF, 0x01E7, 0x01EB, 0x01F3, 0x01F7,
  0x01FD, 0x0209, 0x020B, 0x021D, 0x0223, 0x022D, 0x0233, 0x0239,
  0x023B, 0x0241, 0x024B, 0x0251, 0x0257, 0x0259, 0x025F, 0x0265,
  0x0269, 0x026B, 0x0277, 0x0281, 0x0283, 0x0287, 0x028D, 0x0293,
  0x0295, 0x02A1, 0x02A5, 0x02AB, 0x02B3, 0x02BD, 0x02C5, 0x02CF,
  0x02D7, 0x02DD, 0x02E3, 0x02E7, 0x02EF, 0x02F5, 0x02F9, 0x0301,
  0x0305, 0x0313, 0x031D, 0x0329, 0x032B, 0x0335, 0x0337, 0x033B,
  0x033D, 0x0347, 0x0355, 0x0359, 0x035B, 0x035F, 0x036D, 0x0371,
  0x0373, 0x0377, 0x038B, 0x038F, 0x0397, 0x03A1, 0x03A9, 0x03AD,
  0x03B3, 0x03B9, 0x03C7, 0x03CB, 0x03D1, 0x03D7, 0x03DF, 0x03E5,
  0x03F1, 0x03F5, 0x03FB, 0x03FD, 0x0407, 0x0409, 0x040F, 0x0419,
  0x041B, 0x0425, 0x0427, 0x042D, 0x043F, 0x0443, 0x0445, 0x0449,
  0x044F, 0x0455, 0x045D, 0x0463, 0x0469, 0x047F, 0x0481, 0x048B,
  0x0493, 0x049D, 0x04A3, 0x04A9, 0x04B1, 0x04BD, 0x04C1, 0x04C7,
  0x04CD, 0x04CF, 0x04D5, 0x04E1, 0x04EB, 0x04FD, 0x04FF, 0x0503,
  0x0509, 0x050B, 0x0511, 0x0515, 0x0517, 0x051B, 0x0527, 0x0529,
  0x052F, 0x0551, 0x0557, 0x055D, 0x0565, 0x0577, 0x0581, 0x058F,
  0x0593, 0x0595, 0x0599, 0x059F, 0x05A7, 0x05AB, 0x05AD, 0x05B3,
  0x05BF, 0x05C9, 0x05CB, 0x05CF, 0x05D1, 0x05D5, 0x05DB, 0x05E7,
  0x05F3, 0x05FB, 0x0607, 0x060D, 0x0611, 0x0617, 0x061F, 0x0623,
  0x062B, 0x062F, 0x063D, 0x0641, 0x0647, 0x0649, 0x064D, 0x0653};

//int mp_prime_is_divisible(my_pbig a, int *result)
//{
//  int     err, ix;
//  mp_digit res;
//
//  for(ix = 0; ix < 256; ix++){
//    my_div(<#my_pbig x#>, <#my_pbig y#>, <#my_pbig z#>, <#my_gp *gp#>)
//      
//    if ((err = mp_mod_d (a, ltm_prime_tab[ix], &res)) != MP_OKAY) {
//      return err;
//    }
//
//    /* is the residue zero? */
//    if (res == 0) {
//      *result = 1;
//      return 0;
//    }
//  }
//
//  return 0;
//}

//void my_judge_prime(my_pbig a, int t, my_gp *gp){
//
//    int ix, err, res;
//
//    if(t <= 0 || t > 256) gp->err_code = -1;
//    for(ix = 0; ix < 256; ix++){
//        my_set_d((int)ltm_prime_tab[ix], gp->p0);
//        if(my_cmp(a, gp->p0) == 0){
//            gp->err_code = 0;
//            return;
//        }
//    }
//
//    /* first perform trial division */
//    if ((err = mp_prime_is_divisible (a, &res)) != MP_OKAY) {
//      return err;
//    }
//}
