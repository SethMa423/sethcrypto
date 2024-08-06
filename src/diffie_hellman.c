#include "diffie_hellman.h"

int prime_generation(unsigned int L, unsigned int m, 
                     unsigned char* p, unsigned int* p_len,
                     unsigned char* q, unsigned int* q_len, 
                     unsigned char* seed, unsigned int* seed_len, 
                     unsigned int* pgenCounter)
{
    if (L < 1024 || m < 160) {
        printf("parameters is too small\n");
        return ERR_PARM_SMALL;
    }

    if (p == NULL || q == NULL || seed == NULL || pgenCounter == NULL ||
        p_len == NULL || q_len == NULL || seed_len == NULL) {
        printf("parameters is NULL\n");
        return ERR_PARM_NULL;
    }

    int i, j, ret;
    bool is_prime = false;
    unsigned int int_tmp;
    unsigned int tmp_pgenCounter = 0;
    size_t str_tmp_len = 1024;
    size_t tmp_p_len = (size_t)*p_len, tmp_q_len = (size_t)*q_len;
    unsigned int hash1_len = 32, hash2_len = 32;
    unsigned int m_1 = (unsigned int)ceil((double)m / 160.0);
    unsigned int L_1 = (unsigned int)ceil((double)L / 160.0);
    unsigned int N = (unsigned int)ceil((double)L / 1024.0);
    unsigned char hash1[33] = {0}, hash2[33] = {0};
    unsigned char str_tmp[1025] = {0};

    mp_int mp_p, mp_q, mp_seed, mp_tmp, mp_R, mp_2_expt_L_sub_1;
    
    ret = mp_init_multi(&mp_p, &mp_q, &mp_seed, &mp_tmp, &mp_R, 
                        &mp_2_expt_L_sub_1, NULL);CHECK(ret);

    do {
        // generate seed with bit length of m
        ret = my_random(seed, m / 8);CHECK(ret);
        *seed_len = m / 8;
        ret = mp_from_ubin(&mp_seed, seed, m / 8);CHECK(ret);
        mp_zero(&mp_q);

        // q += (sha1(seed + i) xor sha1(seed + m_tmp + i)) * 2^(160*i);
        for (i = 0; i < m_1; i++) {
            ret = mp_add_d(&mp_seed, i, &mp_tmp);CHECK(ret);
            ret = mp_to_ubin(&mp_tmp, str_tmp, 1024, &str_tmp_len);CHECK(ret);
            ret = hash(SHA1, str_tmp, str_tmp_len, hash1, &hash1_len);CHECK(ret);

            ret = mp_add_d(&mp_seed, i, &mp_tmp);CHECK(ret);
            ret = mp_add_d(&mp_tmp, m_1, &mp_tmp);CHECK(ret);
            ret = mp_to_ubin(&mp_tmp, str_tmp, 1024, &str_tmp_len);CHECK(ret);
            ret = hash(SHA1, str_tmp, str_tmp_len, hash2, &hash2_len);CHECK(ret);
            
            for (j = 0; j < hash1_len; j++)
                str_tmp[j] = hash1[j] ^ hash2[j];

            ret = mp_from_ubin(&mp_tmp, str_tmp, 20);CHECK(ret);
            ret = mp_mul_2d(&mp_tmp, 160 * i, &mp_tmp);CHECK(ret);
            ret = mp_add(&mp_q, &mp_tmp, &mp_q);CHECK(ret);
        }

        // q = q(mod 2^m)
        ret = mp_mod_2d(&mp_q, m, &mp_q);CHECK(ret);

        // perform 50 rounds of Miller-Rabin test on q
        ret = mp_prime_is_prime(&mp_q, 50, &is_prime);CHECK(ret);

    } while (!is_prime);

    do {
        // set R = seed + 2m' + (L*pgenCounter)
        int_tmp = 2 * m_1 + tmp_pgenCounter * L_1;
        ret = mp_add_d(&mp_R, int_tmp, &mp_R);CHECK(ret);
        ret = mp_add(&mp_R, &mp_seed, &mp_R);CHECK(ret);

        mp_zero(&mp_p);

        // p += sha1(R + i) * 2^(160*i)
        for (i = 0; i < L_1; i++) {
            ret = mp_add_d(&mp_R, i, &mp_tmp);CHECK(ret);
            ret = mp_to_ubin(&mp_tmp, str_tmp, 1024, &str_tmp_len);CHECK(ret);
            ret = hash(SHA1, str_tmp, str_tmp_len, hash1, &hash1_len);CHECK(ret);
            ret = mp_from_ubin(&mp_tmp, hash1, hash1_len);CHECK(ret);
            ret = mp_mul_2d(&mp_tmp, 160*i, &mp_tmp);CHECK(ret);
            ret = mp_add(&mp_p, &mp_tmp, &mp_p);CHECK(ret);
        }

        // p = p(mod 2^L)
        ret = mp_mod_2d(&mp_p, L, &mp_p);CHECK(ret);

        // p = p - (p mod 2q) + 1
        ret = mp_mul_2(&mp_q, &mp_tmp);CHECK(ret);
        ret = mp_mod(&mp_p, &mp_tmp, &mp_tmp);CHECK(ret);
        ret = mp_sub(&mp_p, &mp_tmp, &mp_p);CHECK(ret);
        ret = mp_add_d(&mp_p, 1, &mp_p);CHECK(ret);

        // test if p > 2^(L-1)
        ret = mp_2expt(&mp_2_expt_L_sub_1, L-1);CHECK(ret);

        if (MP_GT == mp_cmp(&mp_p, &mp_2_expt_L_sub_1)) {
            ret = mp_prime_is_prime(&mp_p, 50, &is_prime);CHECK(ret);

            if (is_prime) {
                ret = mp_to_ubin(&mp_p, p, tmp_p_len, &tmp_p_len);CHECK(ret);
                ret = mp_to_ubin(&mp_q, q, tmp_q_len, &tmp_q_len);CHECK(ret);

                *p_len = (unsigned int)(tmp_p_len & 0xFFFFFFFF);
                *q_len = (unsigned int)(tmp_q_len & 0xFFFFFFFF);
                *pgenCounter = tmp_pgenCounter;

                ret = DH_SUCCESS;
                goto END;
            }
        }

    } while (++tmp_pgenCounter < 4096 * N);

    printf("tmp_pgenCounter: %d\n", tmp_pgenCounter);
    ret = ERR_FAILED_GEN_PRIME;

END:
    mp_clear_multi(&mp_p, &mp_q, &mp_seed, &mp_tmp, &mp_R, &mp_2_expt_L_sub_1, NULL);

    return ret;
}

int prime_validation(unsigned char* p, unsigned int p_len, 
                      unsigned char* q, unsigned int q_len, 
                      unsigned char* seed, unsigned int seed_len,
                      unsigned int L, unsigned int m,
                      unsigned int pgenCounter)
{
    if (L < 1024 || L % 256 || m < 160 || pgenCounter >= 4096) {
        printf("Invalid parameters.\n");
        return ERR_PARM_INVALID;
    }

    if (p == NULL || q == NULL || seed == NULL) {
        printf("parameters NULL error\n");
        return ERR_PARM_NULL;
    }

    int i, j, ret;
    bool is_prime = false;
    size_t str_tmp_len = 1024;
    unsigned int tmp_int = 0;
    unsigned int m_1 = (unsigned int)ceil((double)m / 160.0);
    unsigned int L_1 = (unsigned int)ceil((double)L / 160.0);
    unsigned int N = (unsigned int)ceil((double)L / 1024.0);
    unsigned int pgenCounter_1 = 0;
    unsigned int hash1_len = 32, hash2_len = 32;
    unsigned char hash1[33] = {0}, hash2[33] = {0};
    unsigned char str_tmp[1025] = {0};

    mp_int mp_p, mp_p_1, mp_q, mp_q_1, mp_seed, mp_tmp, mp_R, mp_2_expt_L_sub_1;

    ret = mp_init_multi(&mp_p, &mp_p_1, &mp_q, &mp_q_1, &mp_seed, &mp_tmp, &mp_R, 
                        &mp_2_expt_L_sub_1, NULL);CHECK(ret);

    ret = mp_from_ubin(&mp_q, q, (size_t)q_len);CHECK(ret);
    ret = mp_from_ubin(&mp_p, p, (size_t)p_len);CHECK(ret);
    ret = mp_from_ubin(&mp_seed, seed, (size_t)seed_len);CHECK(ret);
    
    mp_zero(&mp_q_1);

    // q' += (sha1(seed + i) xor sha1(seed + m' + i)) * 2^(160*i);
    for (i = 0; i < m_1; i++) {
        ret = mp_add_d(&mp_seed, i, &mp_tmp);CHECK(ret);
        ret = mp_to_ubin(&mp_tmp, str_tmp, 1024, &str_tmp_len);CHECK(ret);
        ret = hash(SHA1, str_tmp, str_tmp_len, hash1, &hash1_len);CHECK(ret);

        ret = mp_add_d(&mp_seed, i, &mp_tmp);CHECK(ret);
        ret = mp_add_d(&mp_tmp, m_1, &mp_tmp);CHECK(ret);
        ret = mp_to_ubin(&mp_tmp, str_tmp, 1024, &str_tmp_len);CHECK(ret);
        ret = hash(SHA1, str_tmp, str_tmp_len, hash2, &hash2_len);CHECK(ret);
        
        for (j = 0; j < hash1_len; j++)
            str_tmp[j] = hash1[j] ^ hash2[j];

        ret = mp_from_ubin(&mp_tmp, str_tmp, 20);CHECK(ret);
        ret = mp_mul_2d(&mp_tmp, 160 * i, &mp_tmp);CHECK(ret);
        ret = mp_add(&mp_q_1, &mp_tmp, &mp_q_1);CHECK(ret);
    }

    // q' = q'(mod 2^m)
    ret = mp_mod_2d(&mp_q_1, m, &mp_q_1);CHECK(ret);

    // if q' is composite or q' != q, return failed
    if (MP_EQ != mp_cmp(&mp_q, &mp_q_1)) {
        ret = ERR_Q_INVALID;
        goto END;
    }

    // perform 50 rounds of Miller-Rabin test on q'
    ret = mp_prime_is_prime(&mp_q_1, 50, &is_prime);CHECK(ret);
    if (!is_prime) {
        ret = ERR_Q_INVALID;
        goto END;
    }

    do {
        // R = seed + 2m' + (L'*pgenCounter')
        tmp_int = 2 * m_1 + L_1 * pgenCounter_1;
        ret = mp_add_d(&mp_R, tmp_int, &mp_R);CHECK(ret);
        ret = mp_add(&mp_R, &mp_seed, &mp_R);CHECK(ret);

        mp_zero(&mp_p_1);

        // p' = p' + sha1(R + i)*2^(160*i)
        for (i = 0; i < L_1; i++) {
            ret = mp_add_d(&mp_R, i, &mp_tmp);CHECK(ret);
            ret = mp_to_ubin(&mp_tmp, str_tmp, 1024, &str_tmp_len);CHECK(ret);
            ret = hash(SHA1, str_tmp, str_tmp_len, hash1, &hash1_len);CHECK(ret);
            ret = mp_from_ubin(&mp_tmp, hash1, (size_t)hash1_len);CHECK(ret);
            ret = mp_mul_2d(&mp_tmp, 160*i, &mp_tmp);CHECK(ret);
            ret = mp_add(&mp_p_1, &mp_tmp, &mp_p_1);CHECK(ret);
        }

        // p' = p'(mod 2^L)
        ret = mp_mod_2d(&mp_p_1, L, &mp_p_1);CHECK(ret);

        // p' = p' - (p' mod 2q') + 1
        ret = mp_mul_2(&mp_q_1, &mp_tmp);CHECK(ret);
        ret = mp_mod(&mp_p_1, &mp_tmp, &mp_tmp);CHECK(ret);
        ret = mp_sub(&mp_p_1, &mp_tmp, &mp_tmp);CHECK(ret);
        ret = mp_add_d(&mp_tmp, 1, &mp_p_1);CHECK(ret);

        // test if p' > 2^(L-1) and if p' is prime
        ret = mp_2expt(&mp_2_expt_L_sub_1, L-1);CHECK(ret);

        if ((MP_GT == mp_cmp(&mp_p_1, &mp_2_expt_L_sub_1))) {

            // test if p' is prime
            ret = mp_prime_is_prime(&mp_p_1, 50, &is_prime);CHECK(ret);

            if (is_prime) {

                // test if p is prime
                ret = mp_prime_is_prime(&mp_p, 50, &is_prime);CHECK(ret);
                if (is_prime)
                    break;
            }
        }

    } while (++pgenCounter_1 <= pgenCounter);

END:
    if ((pgenCounter == pgenCounter_1) && (MP_EQ == mp_cmp(&mp_p, &mp_p_1)))
        ret = DH_SUCCESS;
    else
        ret = ERR_VALIDATION_FAILED;

    mp_clear_multi(&mp_p, &mp_p_1, &mp_q, &mp_q_1, &mp_seed, &mp_tmp, &mp_R, 
                   &mp_2_expt_L_sub_1, NULL);

    return ret;
}

int select_generator(unsigned char* p, unsigned int p_len, 
                     unsigned char* q, unsigned int q_len,
                     unsigned char* g, unsigned int* g_len)
{
    if (p == NULL || q == NULL || g == NULL || g_len == NULL) {
        printf("parameters is NULL\n");
        return ERR_PARM_NULL;
    }

    int ret;
    unsigned int size_p_minus_1 = 0;
    size_t tmp_g_len = (size_t)*g_len;

    mp_int mp_j, mp_p, mp_q, mp_g, mp_tmp, mp_mod;
    ret = mp_init_multi(&mp_j, &mp_p, &mp_q, &mp_g, &mp_tmp, &mp_mod, NULL);CHECK(ret);

    // set p, q
    ret = mp_from_ubin(&mp_p, p, (size_t)p_len);CHECK(ret);
    ret = mp_from_ubin(&mp_q, q, (size_t)q_len);CHECK(ret);

    // j = (p - 1) / q
    ret = mp_sub_d(&mp_p, 1, &mp_tmp);CHECK(ret);
    ret = mp_div(&mp_tmp, &mp_q, &mp_j, &mp_mod);CHECK(ret);

    do {
        // generate random g
        ret = mp_sub_d(&mp_p, 1, &mp_tmp);CHECK(ret);
        size_p_minus_1 = mp_ubin_size(&mp_tmp);CHECK(ret);
        size_p_minus_1 = size_p_minus_1 / sizeof(mp_digit);     // get mp_digit size
        ret = mp_rand(&mp_g, size_p_minus_1);CHECK(ret);

        // g = g^j
        ret = mp_exptmod(&mp_g, &mp_j, &mp_p, &mp_g);CHECK(ret);

        // if g = 1, try again
    } while (MP_EQ == mp_cmp_d(&mp_g, 1));

    ret = mp_to_ubin(&mp_g, g, *g_len, &tmp_g_len);CHECK(ret);
    *g_len = (unsigned int)(tmp_g_len & 0xFFFFFFFF);

END:
    mp_clear_multi(&mp_j, &mp_p, &mp_q, &mp_g, &mp_tmp, &mp_mod, NULL);

    return ret;
}

int generate_key_pair(unsigned char* p, unsigned int p_len,
                      unsigned char* q, unsigned int q_len,
                      unsigned char* g, unsigned int g_len,
                      unsigned char* pubkey, unsigned int* pubkey_len,
                      unsigned char* prikey, unsigned int* prikey_len)
{
    if (p == NULL || q == NULL || g == NULL || p_len < 0 || q_len < 0 || g_len < 0) {
        printf("input parameters invalid\n");
        return ERR_PARM_INVALID;
    }

    if (pubkey == NULL || prikey == NULL || pubkey_len == NULL || prikey_len == NULL || 
        *pubkey_len < 0 || *prikey_len < 0) {
        printf("output buffer invalid\n");
        return ERR_BUFFER_NOT_ENOUGH;
    }

    mp_int mp_x, mp_y, mp_p, mp_q, mp_q_minus_1, mp_g;

    int ret, i = 0;
    size_t size_q, tmp_pubkey_len, tmp_prikey_len;
    ret = mp_init_multi(&mp_x, &mp_y, &mp_p, &mp_q, &mp_q_minus_1, &mp_g, NULL);CHECK(ret);

    tmp_pubkey_len = (size_t)pubkey_len;
    tmp_prikey_len = (size_t)prikey_len;
    ret = mp_from_ubin(&mp_p, p, (size_t)p_len);CHECK(ret);
    ret = mp_from_ubin(&mp_q, q, (size_t)q_len);CHECK(ret);
    ret = mp_from_ubin(&mp_g, g, (size_t)g_len);CHECK(ret);

    // get the size of integer q
    size_q = mp_ubin_size(&mp_q);CHECK(ret);
    ret = mp_sub_d(&mp_q, 1, &mp_q_minus_1);CHECK(ret);

    // generate x, so that 1 < x <= q-1
    ret = mp_rand(&mp_x, size_q);CHECK(ret);
    ret = mp_mod(&mp_x, &mp_q_minus_1, &mp_x);CHECK(ret);

    // compute y = g^x(mod p)
    ret = mp_exptmod(&mp_g, &mp_x, &mp_p, &mp_y);CHECK(ret);

    ret = mp_to_ubin(&mp_x, prikey, tmp_pubkey_len, &tmp_prikey_len);CHECK(ret);
    ret = mp_to_ubin(&mp_y, pubkey, tmp_pubkey_len, &tmp_pubkey_len);CHECK(ret);
    *pubkey_len = (unsigned int)(tmp_pubkey_len & 0xFFFFFFFF);
    *prikey_len = (unsigned int)(tmp_prikey_len & 0xFFFFFFFF);

END:
    mp_clear_multi(&mp_x, &mp_y, &mp_p, &mp_q, &mp_q_minus_1, &mp_g, NULL);

    return ret;
}

int public_key_validation(unsigned char* p, unsigned int p_len,
                          unsigned char* q, unsigned int q_len,
                          unsigned char* g, unsigned int g_len,
                          unsigned char* seed, unsigned int seed_len,
                          unsigned char* pubkey, unsigned int pubkey_len)
{
    if (p == NULL || q == NULL || g == NULL || seed == NULL || pubkey == NULL ||
        p_len < 0 || q_len < 0 || g_len < 0 || seed_len < 0 || pubkey_len < 0) {
        printf("input parameters invalid\n");
        return ERR_PARM_INVALID;
    }

    int ret;
    mp_int mp_p, mp_p_minus_2, mp_q, mp_g, mp_seed, mp_y, mp_tmp;

    ret = mp_init_multi(&mp_p, &mp_p_minus_2, &mp_q, &mp_g, &mp_seed, &mp_y, 
                        &mp_tmp, NULL);CHECK(ret);

    ret = mp_from_ubin(&mp_p, p, (size_t)p_len);CHECK(ret);
    ret = mp_from_ubin(&mp_q, q, (size_t)q_len);CHECK(ret);
    ret = mp_from_ubin(&mp_g, g, (size_t)g_len);CHECK(ret);
    ret = mp_from_ubin(&mp_seed, seed, (size_t)seed_len);CHECK(ret);
    ret = mp_from_ubin(&mp_y, pubkey, (size_t)pubkey_len);CHECK(ret);

    // check if y < 2, return invalid if true
    if (MP_LT == mp_cmp_d(&mp_y, 2)) {
        ret = ERR_PUBKEY_LESS_THAN_2;
        goto END;
    }

    // check if y > p-2, return invalid if true
    ret = mp_sub_d(&mp_p, 2, &mp_p_minus_2);CHECK(ret);
    if (MP_GT == mp_cmp(&mp_y, &mp_p_minus_2)) {
        ret = ERR_PUBKEY_GREATER_THAN_P_MINUS_2;
        goto END;
    }

    // check if y^q = 1 (mod p), return invalid if false
    ret = mp_exptmod(&mp_y, &mp_q, &mp_p, &mp_tmp);CHECK(ret);
    if (MP_EQ != mp_cmp_d(&mp_tmp, 1)) {
        ret = ERR_PUBKEY_NOT_EQ_1_MOD_P;
        goto END;
    }

END:
    mp_clear_multi(&mp_p, &mp_p_minus_2, &mp_q, &mp_g, &mp_seed, &mp_y, 
                   &mp_tmp, NULL);

    return ret;
}

int calculate_zz(unsigned char* p, unsigned int p_len,
                 unsigned char* q, unsigned int q_len,
                 unsigned char* g, unsigned int g_len,
                 unsigned char* v_pubkey, unsigned int v_pubkey_len,
                 unsigned char* u_prikey, unsigned int u_prikey_len,
                 unsigned char* z, unsigned int* z_len)
{
    if (p == NULL || q == NULL || g == NULL || p_len < 0 || 
        q_len < 0 || g_len < 0 || v_pubkey == NULL || u_prikey == NULL || 
        v_pubkey_len < 0 || u_prikey_len < 0) {
        printf("input parameters invalid\n");
        return ERR_PARM_INVALID;
    }

    if (z == NULL || z_len == NULL || *z_len < 0) {
        printf("output buffer invalid\n");
        return ERR_BUFFER_NOT_ENOUGH;
    }

    int ret;
    size_t tmp_z_len = (size_t)z_len;
    mp_int mp_p, mp_q, mp_g, mp_xu, mp_yv, mp_z, mp_tmp;

    ret = mp_init_multi(&mp_p, &mp_q, &mp_g, &mp_xu, &mp_yv, &mp_z, 
                        &mp_tmp, NULL);CHECK(ret);

    ret = mp_from_ubin(&mp_p, p, (size_t)p_len);CHECK(ret);
    ret = mp_from_ubin(&mp_q, q, (size_t)q_len);CHECK(ret);
    ret = mp_from_ubin(&mp_g, g, (size_t)g_len);CHECK(ret);
    ret = mp_from_ubin(&mp_xu, u_prikey, (size_t)u_prikey_len);CHECK(ret);
    ret = mp_from_ubin(&mp_yv, v_pubkey, (size_t)v_pubkey_len);CHECK(ret);

    // zz = Yv^Xu (mdd p)
    ret = mp_exptmod(&mp_yv, &mp_xu, &mp_p, &mp_z);CHECK(ret);

    if (MP_EQ == mp_cmp_d(&mp_z, 1))
        ret = ERR_ZZ_EQ_1;
    else {
        ret = mp_to_ubin(&mp_z, z, tmp_z_len, &tmp_z_len);CHECK(ret);
        *z_len = (unsigned int)(tmp_z_len & 0xFFFFFFFF);
    }

END:
    mp_clear_multi(&mp_p, &mp_q, &mp_g, &mp_xu, &mp_yv, &mp_z, &mp_tmp, NULL);

    return ret;
}
