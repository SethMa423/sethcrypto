#include <time.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <ctype.h>

#include "sm2.h"
#include "hash.h"
#include "tool.h"
#include "base64.h"
#include "symmetric.h"
#include "diffie_hellman.h"

int hex_to_byte(char *in, unsigned char *out, unsigned int *outLen)
{
    if (NULL == in || NULL == out) {
        return 1;
    }

    int i = 0, isFree = 0;
    unsigned char tmpchar = 0;
    char *tmp = in;
    *outLen = 0;
    int len = (int)strlen(tmp);
    int flag = 0;
    for (i = 0; i < len; tmp++, i++) {
        for (; isspace(*tmp); tmp++, i++)
            ;
        if ((*tmp <= 0x39) && (*tmp >= 0x30)) {    // 0~9
            tmpchar = *tmp - 48;
            ++flag;
        }
        else if ((*tmp <= 0x46) && (*tmp >= 0x41))    // A~F
        {
            tmpchar = *tmp - 55;
            ++flag;
        }
        else if ((*tmp <= 0x66) && (*tmp >= 0x61))    // a~f
        {
            tmpchar = *tmp - 87;
            ++flag;
        }
        else {
            return 1;
        }

        if (flag % 2) {
            out[*outLen] = tmpchar << 4;
        }
        else {
            out[*outLen] |= tmpchar;
            (*outLen)++;
        }
    }

    return 0;
}

#ifdef SM2VERIFY
void printf_instruction()
{
    printf(
        "\n-------------------- HELP --------------------\n"
        "INSTRUCTION:\n"
        "    This program is created for SM2 verification.\n");
    printf(
        "SYNOPSIS:\n"
        "    ECC_verify [-p public key] [-d data] [-s sinature] [-h]\n");
    printf(
        "USE:\n"
        "    -p specify public key, should be base64 encoding.\n"
        "    -d previous data, could be either pre-processed data or \n"
        "       not processed data, this could be specified via '-h' option\n"
        "    -s signature to be verified, should be in base64 encoding.\n"
        "    -h hash flag. If input data is pre-processed, then this could\n"
        "       be omitted, else this flag should be carried to tell the\n"
        "       program to de pre-processiong for input data.\n"
        "-------------------- HELP --------------------\n");
    return;
}

/*
原文要不然就传做了base的原文，要不就传做过预处理的结果。
 */
// temp sign & verify, enc & dec
void main(int argc, char *argv[])
{
    int i, ret, ch;
    opterr = 0;

    if (argc < 4) {
        printf("input parameters not enough...\n");
        printf_instruction();
        return;
    }

    unsigned char bpubkey[89] = {0};
    unsigned int bpubkeylen = 89;
    unsigned char pubkey[66] = {0};
    unsigned int pubkeylen = 66;

    unsigned char *bsrc = NULL;
    unsigned int bsrclen = 0;
    unsigned char *src = NULL;
    unsigned int srclen = 0;

    unsigned char bsign[89] = {0};
    unsigned int bsignlen = 89;
    unsigned char sign[66] = {0};
    unsigned int signlen = 66;
    int flag = NO_HASH;    // default WITH_HASH

    while ((ch = getopt(argc, argv, "p:P:d:D:s:S:h")) != -1) {
        switch (ch) {
            case 'p':
            case 'P':
                bpubkeylen = strlen(optarg);
                if (bpubkeylen > 88) {
                    printf("pubkey too long, what is this?\n");
                    return;
                }
                memcpy(bpubkey, optarg, bpubkeylen);
                break;
            case 'd':
            case 'D':
                bsrclen = strlen(optarg);
                bsrc = (unsigned char *)calloc(bsrclen + 1, 1);
                memcpy(bsrc, optarg, bsrclen);
                break;
            case 's':
            case 'S':
                bsignlen = strlen(optarg);
                if (bsignlen > 88) {
                    printf("signature too long, you sure?\n");
                    return;
                }
                memcpy(bsign, optarg, bsignlen);
                break;
            case 'h':
                flag = WITH_HASH;
                break;
            default:
                printf("Unknown option, programme exit...\n");
                printf_instruction();
                return;
        }
    }

    unsigned char ID[17] = "1234567812345678";
    ret = base64_decode(bsign, bsignlen, sign, &signlen);
    if (ret) {
        printf("Base64 failed, ret: %d\n", ret);
        return;
    }
    if (signlen > 64) {
        printf("signature length seems not alright\n");
        return;
    }

    ret = base64_decode(bpubkey, bpubkeylen, pubkey, &pubkeylen);
    if (ret) {
        printf("Base64 failed, ret: %d\n", ret);
        return;
    }
    if (pubkeylen != 65 && pubkeylen != 64) {
        printf("pubkey length seems not alright\n");
        return;
    }
    if (pubkeylen == 65) {
        for (i = 0; i < 63; i++) {
            pubkey[i] = pubkey[i + 1];
        }
        pubkeylen = 64;
    }

    srclen = bsrclen;
    src = (unsigned char *)calloc(srclen, 1);
    ret = base64_decode(bsrc, bsrclen, src, &srclen);
    if (ret) {
        printf("Base64 failed, ret: %d\n", ret);
        return;
    }

    ret = sm2_verify(sign, signlen, src, srclen, ID, 16, pubkey, pubkeylen, flag);
    if (ret) {
        printf("verify ret: %d\n", ret);
        return;
    }
    printf("Verify successful\n");

    if (bsrc)
        free(bsrc);
    bsrc = NULL;
    if (src)
        free(src);
    src = NULL;
    return;
}
#endif

#ifdef ECCCHECKKEY
// check if ecc keypair is matched, compailed as ECC_checkkey
void main(int argc, char *argv[])
{
    // input parameters should have pubkey and prikey, another arg is name
    // of programe
    if (argc < 3) {
        printf("Warning: In order to check if matches, both private key and ",
               "public key should be input.\n");
        return;
    }

    unsigned int tmp3, ret = 0, i;
    unsigned int bpubkeylen = strlen(argv[1]);
    unsigned int bprikeylen = strlen(argv[2]);
    unsigned int pubkeylen = 100;
    unsigned int prikeylen = 100;
    unsigned char pubkey[100] = {0};
    unsigned char prikey[100] = {0};

    // input order could either be "1)prikey 2)pubkey" or "1)pubkey 2)prikey"
    // identify it according to their length
    if (bpubkeylen < bprikeylen) {
        tmp3 = bpubkeylen;
        bpubkeylen = bprikeylen;
        bprikeylen = tmp3;
        if (base64_decode(argv[1], bprikeylen, prikey, &prikeylen)) {
            printf("failed decode private key, function exit...\n");
            return;
        }
        if (base64_decode(argv[2], bpubkeylen, pubkey, &pubkeylen)) {
            printf("failed decode pubkey key, function exit...\n");
            return;
        }
    }
    else {
        if (base64_decode(argv[2], bprikeylen, prikey, &prikeylen)) {
            printf("failed decode private key, function exit...\n");
            return;
        }
        if (base64_decode(argv[1], bpubkeylen, pubkey, &pubkeylen)) {
            printf("failed decode pubkey key, function exit...\n");
            return;
        }
    }

    // if pubkey initiated with 0x04, trim it!
    if (pubkeylen == 65) {
        for (i = 0; i < 64; i++)
            pubkey[i] = pubkey[i + 1];
        pubkeylen -= 1;
    }
    else if (pubkeylen != 65 && pubkeylen != 64 || prikeylen != 32) {
        printf("invalid length of input key pair, function exit...\n");
        return;
    }

    // read in the prikey and re-generate the pubkey
    my_gp *gp = my_init_gp();
    if (gp == NULL) {
        printf("failed initializing gp, function exit..\n");
        return;
    }
    my_pbig mp_rand_k = NULL;
    my_pbig mp_a = NULL, mp_b = NULL, mp_n = NULL, mp_p = NULL, mp_Xg = NULL;
    my_pbig mp_Yg = NULL;
    my_pbig pub_x = NULL, pub_y = NULL;
    my_point *G = NULL, *pt_pubkey = NULL;
    mp_rand_k = my_init(0, gp);
    ret += gp->err_code;
    if (ret) {
        printf("failed my_init random k\n");
        return;
    }

    my_read_bin(32, (const char *)prikey, mp_rand_k, gp);
    ret += gp->err_code;
    if (ret) {
        printf("failed read in the prikey\n");
        return;
    }

    pt_pubkey = my_point_init(gp);
    ret += gp->err_code;
    G = my_point_init(gp);
    ret += gp->err_code;
    mp_a = my_init(0, gp);
    ret += gp->err_code;
    mp_b = my_init(0, gp);
    ret += gp->err_code;
    mp_n = my_init(0, gp);
    ret += gp->err_code;
    mp_p = my_init(0, gp);
    ret += gp->err_code;
    mp_Xg = my_init(0, gp);
    ret += gp->err_code;
    mp_Yg = my_init(0, gp);
    ret += gp->err_code;
    pub_x = my_init(0, gp);
    ret += gp->err_code;
    pub_y = my_init(0, gp);
    ret += gp->err_code;
    if (ret) {
        printf("failed my_init relevent parameters, try again...\n");
        my_clear(mp_rand_k);
        my_clear(mp_a);
        my_clear(mp_b);
        my_clear(mp_n);
        my_clear(mp_p);
        my_clear(mp_Xg);
        my_clear(mp_Yg);
        my_clear(pub_x);
        my_clear(pub_y);
        my_point_clear(G);
        my_point_clear(pt_pubkey);
        my_gp_clear(gp);
        return;
    }

    ret = std_param(mp_a, mp_b, mp_n, mp_p, mp_Xg, mp_Yg, gp);
    my_ecc_init(mp_a, mp_b, mp_p, gp);
    ret += gp->err_code;
    my_set_point(mp_Xg, mp_Yg, G, gp);
    ret += gp->err_code;
    my_point_mul(mp_rand_k, G, pt_pubkey, gp);
    ret += gp->err_code;
    my_get_point(pt_pubkey, pub_x, pub_y, gp);
    ret += gp->err_code;
    ret += check_point(pub_x, pub_y, mp_a, mp_b, mp_p, gp);
    if (ret) {
        printf("failed re-generating pubkey\n");
        my_clear(mp_rand_k);
        my_clear(mp_a);
        my_clear(mp_b);
        my_clear(mp_n);
        my_clear(mp_p);
        my_clear(mp_Xg);
        my_clear(mp_Yg);
        my_clear(pub_x);
        my_clear(pub_y);
        my_point_clear(G);
        my_point_clear(pt_pubkey);
        my_gp_clear(gp);
        return;
    }

    unsigned char new_pubkey[64] = {0};
    unsigned int Y_len = 32, X_len = 32;
    ret = mp_2_bin(new_pubkey + 32, &Y_len, pub_y, gp);
    if (Y_len != 32) {
        printf("y len not equal 32 bytes\n");
        return;
    }
    ret = mp_2_bin(new_pubkey, &X_len, pub_x, gp);
    if (X_len != 32) {
        printf("y len not equal 32 bytes\n");
        return;
    }

    if (memcmp(new_pubkey, pubkey, 64)) {
        printf("prikey and pubkey not paired!\n");
        printf("old pubkey is below:\n");
        for (i = 0; i < 64; i++)
            printf("%02X ", pubkey[i]);
        printf("\n");
        printf("while paired pubkey is below:\n");
        for (i = 0; i < 64; i++)
            printf("%02X ", new_pubkey[i]);
        printf("\n");
    }
    else {
        printf("Key is paired!\n");
    }

    return;
}
#endif

#ifdef ECCENCRYPT
// SM2 encrypt, compailed as ECC_encrypt
void printf_instruction()
{
    printf("\n-------------------- HELP --------------------\n");
    printf(
        "INSTRUCTION:\n"
        "    This program is created for SM2 Encryption, so that at least two\n"
        "    parameters should be input: the 'pubkey' as well as 'plaindata'.\n");
    printf(
        "SYNOPSIS:\n"
        "    ECC_verify [-p pubkey] [-d plaindata] [-i input_data_format]\n"
        "               [-o output_cipher_format]\n");
    printf(
        "USE:\n"
        "    -i indicate the format of input data, which could be 'base64', \n"
        "       'hex' or 'raw'. If not set, we assume the input is in base64\n"
        "       format.\n"
        "    -o indicate the format of output cipher, note that the cipher is \n"
        "       opaque, the default output will be 'base64', while 'hex' format\n"
        "       is also supported. 'hex' format will print as '01 02 ...'.\n"
        "-------------------- HELP --------------------\n\n");
    return;
}

void main(int argc, char **argv)
{
    int ch;
    opterr = 0;
    int ret = 0, i;

    if (argc < 3) {
        printf("Input parameters not enough...\n");
        printf_instruction();
        return;
    }

    // indicate the format of data, whether base64, hex or just raw data
    // 0: raw data, 1: hex, 2: base64, default is raw data
    int flag_data_format = 2;

    // indicate the format of output cipher, whether base64, hex or just raw data
    // 1: hex, 2: base64, default is raw data
    int flag_output_format = 2;

    unsigned char bpubkey[100] = {0};
    unsigned char pubkey[65] = {0};
    unsigned char *bdata = NULL;
    unsigned char *data = NULL;
    unsigned char *cipher = NULL;
    unsigned char *bcipher = NULL;
    unsigned int pubkeylen = 65;
    unsigned int bpubkeylen = 100;
    unsigned int bdatalen = 0;
    unsigned int datalen = 0;
    unsigned int cipherlen = 0;
    unsigned int bcipherlen = 0;

    // parse input parameters
    while ((ch = getopt(argc, argv, "p:P:d:D:i:o:")) != -1) {
        switch (ch) {
            case 'P':
            case 'p':
                // length detection
                if (strlen(optarg) >= 100) {
                    printf("Is this a real pubkey? It's way toooooo long\n");
                    return;
                }
                memcpy(bpubkey, optarg, strlen(optarg));
                bpubkeylen = strlen(optarg);
                break;

            // copy data
            case 'D':
            case 'd':
                bdatalen = strlen(optarg);
                bdata = (unsigned char *)calloc(bdatalen, 1);
                memcpy(bdata, optarg, bdatalen);
                break;

            // settle input data flag
            case 'i':
                if (optarg[0] == 'b' || optarg[0] == 'B')
                    flag_data_format = 2;
                else if (optarg[0] == 'h' || optarg[0] == 'H')
                    flag_data_format = 1;
                else if (optarg[0] == 'r' || optarg[0] == 'R')
                    flag_data_format = 0;
                else {
                    printf(
                        "Unknown input format of data, only: 'base64', 'hex', 'raw' is accepted\n");
                    return;
                }
                break;

            // settle output data flag
            case 'o':
                if (optarg[0] == 'b' || optarg[0] == 'B')
                    flag_output_format = 2;
                else if (optarg[0] == 'h' || optarg[0] == 'H')
                    flag_output_format = 1;
                else {
                    printf("Unknown output format of cipher, only: 'base64', 'hex' is accepted\n");
                    return;
                }
                break;

            // other input parameters
            default:
                printf("Unknown options...\n\n");
                printf_instruction();
                return;
        }
    }

    // work on plain
    data = (unsigned char *)calloc(bdatalen, 1);
    datalen = bdatalen;
    if (flag_data_format == 2) {
        if ((ret = base64_decode(bdata, bdatalen, data, &datalen))) {
            printf("base64 decode failed, check input data please\n");
            return;
        }
    }
    else if (flag_data_format == 1) {
        ret = hex_to_byte(bdata, data, &datalen);
        if (ret) {
            printf("hex to byte failed, ret: %d\n", ret);
            return;
        }
    }
    else if (flag_data_format == 0) {
        memcpy(data, bdata, bdatalen);
        datalen = bdatalen;
    }

    // work on pubkey
    if ((ret = base64_decode(bpubkey, bpubkeylen, pubkey, &pubkeylen))) {
        printf("base64 decode failed, check pubkey please\n");
        return;
    }
    if (pubkeylen > 64) {
        printf("Warning: pubkey too long, try to fetch the last 64 bytes\n");
        for (i = 0; i < 64; i++)
            pubkey[i] = pubkey[i + pubkeylen - 64];
        pubkeylen = 64;
    }

    cipherlen = datalen + 98;
    cipher = (unsigned char *)calloc(cipherlen, 1);
    ret = sm2_enc(cipher, &cipherlen, data, datalen, pubkey, pubkeylen);
    if (ret) {
        printf("SM2 encrypt failed, error code: %d\n", ret);
        return;
    }

    if (flag_output_format == 1) {
        for (i = 0; i < cipherlen; i++)
            printf("%02X ", cipher[i]);
        printf("\n");
    }
    else if (flag_output_format == 2) {
        if (NULL == (bcipher = b64_en(cipher, cipherlen, NULL))) {
            printf("base64 encode cipher failed\n");
            return;
        }
        printf("Cipher:\n%s\n", bcipher);
    }
    else {
        printf("Unknown flag of output flag, don't know how\n");
        return;
    }

    if (bcipher)
        free(bcipher);
    bcipher = NULL;
    if (cipher)
        free(cipher);
    cipher = NULL;
    if (data)
        free(data);
    data = NULL;
    if (bdata)
        free(bdata);
    bdata = NULL;

    return;
}
#endif

#ifdef SYMFUNC
void printf_instruction()
{
    printf(
        "\n-------------------- HELP --------------------\n"
        "INSTRUCTION:\n"
        "    This program is created for symmetric encryption and decryption.\n"
        "    The symmetric algorithm including SM1, SM4, DES, 3DES, as well as\n"
        "    AES-128. To properly execute the function, key and data should \n"
        "    at least be input. Other options including algorithm, encryption/\n"
        "    decryption mode, IV, padding option, and data format.\n");
    printf(
        "SYNOPSIS:\n"
        "    symfunc [-d data] [-k key] [-m mode] [-a algorithm] [-v iv] \n"
        "            [-i data format] [-p] [-f function] [-h]\n");
    printf(
        "USE:\n"
        "    -d data to be performed, could be either cipher or plaintext.\n"
        "    -k symmetric key, should be base64 encoded.\n"
        "    -m function mode, accept: ECB, CBC, CFB, OFB. ECB by default.\n"
        "    -a symmetric algorithm, accept: SM1, SM4, DES, 3DES, AES. SM4 default.\n"
        "    -v intiate value, should be in base64 encode.\n"
        "    -i input data encoding, if input data is in base64 codeing, you\n"
        "       could specify 'base64', 'raw' if it's raw data, base64 by default.\n"
        "    -p if you need to add pkcs#5 padding to input data, add -p option.\n"
        "       If not specified, then we won't pad for you.\n"
        "    -f this program can do either encrpyting or decrypting, and encrpyting\n"
        "       is default operation. But if you want to do decrypt, you can specify\n"
        "       '-f decrypt'\n"
        "    -h print help information.\n"
        "-------------------- HELP --------------------\n");
    return;
}

void main(int argc, char **argv)
{
    if (argc < 3) {
        printf_instruction();
        return;
    }

    int i, ret;

    opterr = 0;
    int ch;

    int algo = SM4;
    int mode = ECB;
    int informat = 0;    // 0: base64 1: raw
    int function = 0;    // 0: encrypt 1: decrypt

    unsigned char key[32] = {0};
    unsigned int keylen = 32;

    unsigned char *bdata = NULL;
    unsigned int bdatalen = 0;
    unsigned char *data = NULL;
    unsigned int datalen = 0;

    unsigned char iv[32] = {0};
    unsigned int ivlen = 0;

    unsigned char *out = NULL;
    unsigned int outlen = 0;
    unsigned char *bout = NULL;
    unsigned int boutlen = 0;

    unsigned int padding = NO_PADDING;

    while ((ch = getopt(argc, argv, "d:k:m:a:v:i:pf:")) != -1) {
        switch (ch) {
            case 'd':
                bdatalen = strlen(optarg);
                bdata = (unsigned char *)calloc(bdatalen, 1);
                memcpy(bdata, optarg, bdatalen);
                break;

            case 'k':
                ret = base64_decode(optarg, strlen(optarg), key, &keylen);
                if (ret) {
                    printf("base64 decode key failed, error code: %d\n", ret);
                    goto END;
                }
                break;

            case 'm':
                if (0 == strcmp(optarg, "ECB") || 0 == strcmp(optarg, "ecb"))
                    mode = ECB;
                else if (0 == strcmp(optarg, "CBC") || 0 == strcmp(optarg, "cbc"))
                    mode = CBC;
                else if (0 == strcmp(optarg, "CFB") || 0 == strcmp(optarg, "cfb"))
                    mode = CFB;
                else if (0 == strcmp(optarg, "OFB") || 0 == strcmp(optarg, "ofb"))
                    mode = OFB;
                else {
                    printf("invalid symmetric mode\n");
                    goto END;
                }
                break;

            case 'a':
                if (0 == strcmp(optarg, "SM4") || 0 == strcmp(optarg, "sm4"))
                    algo = SM4;
                else if (0 == strcmp(optarg, "SM1") || 0 == strcmp(optarg, "sm1"))
                    algo = SM1;
                else if (0 == strcmp(optarg, "AES") || 0 == strcmp(optarg, "aes"))
                    algo = AES;
                else if (0 == strcmp(optarg, "DES") || 0 == strcmp(optarg, "des"))
                    algo = DES;
                else if (0 == strcmp(optarg, "3DES") || 0 == strcmp(optarg, "3des"))
                    algo = DES3;
                else {
                    printf("invalid symmetric algorithm\n");
                    goto END;
                }
                break;

            case 'v':
                ivlen = 32;
                ret = base64_decode(optarg, strlen(optarg), iv, &ivlen);
                if (ret) {
                    printf("base64 decode iv failed, error code: %d\n", ret);
                    goto END;
                }
                break;

            case 'i':
                if ('b' == optarg[0] || 'B' == optarg[0])
                    informat = 0;
                else if ('r' == optarg[0] || 'R' == optarg[0])
                    informat = 1;
                else {
                    printf("invalid input format\n");
                    goto END;
                }
                break;

            case 'p':
                padding = PKCS5_PADDING;
                break;

            case 'f':
                if (optarg[0] == 'e')
                    function = 0;
                else
                    function = 1;
                break;

            case 'h':
                printf_instruction();
                goto END;
                break;

            default:
                printf("Unknown options...\n\n");
                printf_instruction();
                goto END;
                break;
        }
    }

    if (informat == 0) {
        data = b64_de(bdata, bdatalen, &datalen);
        if (!data) {
            printf("failed decode input data\n");
            goto END;
        }
    }
    else {
        data = (unsigned char *)calloc(bdatalen, 1);
        if (!data)
            goto END;
        datalen = bdatalen;
        memcpy(data, bdata, datalen);
    }

    outlen = datalen + 16;
    out = (unsigned char *)calloc(outlen, 1);
    if (!out) {
        printf("failed calloc memory\n");
        goto END;
    }

    if (function) {
        ret = sym_decrypt(algo, mode, key, keylen, iv, ivlen, padding, data, datalen, out, &outlen);
        if (ret) {
            printf("ret: %d\n", ret);
            return;
        }
    }
    else {
        ret = sym_encrypt(algo, mode, key, keylen, iv, ivlen, padding, data, datalen, out, &outlen);
        if (ret) {
            printf("ret: %d\n", ret);
            return;
        }
    }

    bout = b64_en(out, outlen, NULL);
    if (!bout) {
        printf("failed base64 encode outdata\n");
        goto END;
    }
    printf("%s\n", bout);

END:
    if (bdata)
        free(bdata);
    bdata = NULL;
    if (data)
        free(data);
    data = NULL;
    if (out)
        free(out);
    out = NULL;
    if (bout)
        free(bout);
    bout = NULL;

    return;
}
#endif    // SYMFUNC

#ifdef DIGEST

void printf_instruction()
{
    printf("\n-------------------- HELP --------------------\n");
    printf("INSTRUCTION:\n");
    printf("    This program is created for digestion, so that source data \n");
    printf("    should be input. If other paramenters is provided, then the \n");
    printf("    source data should be identified with flag 'd'.\n");
    printf("SYNOPSIS:\n");
    printf("    digest [-d data]  [-p pubkey] [-a algorithm] \n");
    printf("           [-i input_data_format] [-o output_cipher_format]\n");
    printf("USE:\n");
    printf("    -i indicate the format of input data, which could be 'base64', \n");
    printf("       'hex' or 'raw'. If not set, we assume the input is in raw\n");
    printf("       format.\n");
    printf("    -o indicate the format of output cipher, note that the cipher is \n");
    printf("       opaque, the default output will be 'base64', while 'hex' format\n");
    printf("       is also supported. 'hex' format will print as '01 02 ...'.\n");
    printf("    -p if 'sm3' algorithm is specified, then pubkey should be provided, \n");
    printf("        accepted format of pubkey is in base64 format.\n");
    printf("    -a digest algorithm, default is sm3 with no pubkey. sha1, sha256, md5 \n");
    printf("       is also supported.\n");
    printf("    -d data.\n");
    printf("-------------------- HELP --------------------\n");
    return;
}

void main(int argc, char **argv)
{
    int ret, i, ch;
    opterr = 0;

    if (argc < 2) {
        printf("Error: no input\n");
        printf_instruction();
        return;
    }

    // hash flag, 1: sm3, 2: sha1, 3: sha256
    int flag_hash_algo = 111;

    // input format, 1: base64, 2: hex 3: raw
    int flag_input_format = 3;

    // output format, 1: base64, 2: hex
    int flag_output_format = 1;

    unsigned char *temp = NULL;
    unsigned char *pubkey = NULL;
    unsigned int pubkeylen = 0;
    unsigned char *source = NULL;
    unsigned int sourcelen = 0;
    unsigned char *data = NULL;
    unsigned int datalen = 0;
    unsigned char hashbuf[56] = {0};
    unsigned int hashLen = 56;
    unsigned char bhash[45] = {0};
    unsigned int bhashLen = 45;
    unsigned int tempLen = 32;
    my_pbig mp_a = NULL, mp_b = NULL, mp_n = NULL, mp_p = NULL, mp_Xg = NULL, mp_Yg = NULL;
    my_pbig mp_XA = NULL, mp_YA = NULL, mp_dA = NULL, mp_r = NULL, mp_s = NULL, mp_e = NULL;
    my_point *G = NULL, *P = NULL;
    my_gp *gp = NULL;

    if (argc == 2) {
        sourcelen = strlen(argv[1]);
        source = (unsigned char *)calloc(sourcelen, 1);
        memcpy(source, argv[1], sourcelen);
    }
    else {
        while ((ch = getopt(argc, argv, "p:d:a:i:o:")) != -1) {
            switch (ch) {
                case 'p':
                    temp = b64_de(optarg, strlen(optarg), &pubkeylen);
                    if (temp == NULL) {
                        printf("re-check pubkey, format invalid\n");
                        goto END;
                    }
                    if (pubkeylen == 65 || pubkeylen == 64) {
                        pubkey = (unsigned char *)calloc(64, 1);
                        memcpy(pubkey, temp + pubkeylen - 64, 64);
                        pubkeylen = 64;
                    }
                    else {
                        printf("invalid length of pubkey\n");
                        goto END;
                    }
                    break;

                case 'd':
                    sourcelen = strlen(optarg);
                    source = (unsigned char *)calloc(sourcelen + 1, 1);
                    memcpy(source, optarg, sourcelen);

                    break;

                case 'a':
                    if (0 == strcmp(optarg, "sm3"))
                        flag_hash_algo = 111;
                    else if (0 == strcmp(optarg, "sha1"))
                        flag_hash_algo = 222;
                    else if (0 == strcmp(optarg, "sha256"))
                        flag_hash_algo = 333;
                    else if (0 == strcmp(optarg, "md5"))
                        flag_hash_algo = 444;
                    else {
                        printf("invalid hash algorithm\n");
                        goto END;
                    }
                    break;

                case 'i':
                    if (optarg[0] == 'b' || optarg[0] == 'B')
                        flag_input_format = 1;
                    else if (optarg[0] == 'h' || optarg[0] == 'H')
                        flag_input_format = 2;
                    else if (strcmp(optarg, "raw") == 0)
                        flag_input_format = 3;
                    else {
                        printf("invalid input data format\n");
                        goto END;
                    }
                    break;
                case 'o':
                    if (optarg[0] == 'b' || optarg[0] == 'B')
                        flag_output_format = 1;
                    else if (optarg[0] == 'h' || optarg[0] == 'H')
                        flag_output_format = 2;
                    else {
                        printf("invalid output data format\n");
                        goto END;
                    }
                    break;

                default:
                    printf("Unrecognized option\n");
                    printf_instruction();
                    goto END;
            }
        }
    }

    datalen = sourcelen;
    data = (unsigned char *)calloc(datalen, 1);
    if (flag_input_format == 1) {
        ret = base64_decode(source, sourcelen, data, &datalen);
        if (ret) {
            printf("base64 failed, error code: %d\n", ret);
            goto END;
        }
    }
    else if (flag_input_format == 2) {
        hex_to_byte(source, data, &datalen);
    }
    else if (flag_input_format == 3) {
        memcpy(data, source, sourcelen);
    }
    else {
        printf("Unrecognized option\n");
        printf_instruction();
        goto END;
    }

    if (pubkeylen == 64) {
        gp = my_init_gp();
        if (gp == NULL) {
            ret = 1;
            goto END;
        }
        mp_a = my_init(0, gp);
        ret = gp->err_code;
        CHECK(ret);
        mp_b = my_init(0, gp);
        ret = gp->err_code;
        CHECK(ret);
        mp_n = my_init(0, gp);
        ret = gp->err_code;
        CHECK(ret);
        mp_p = my_init(0, gp);
        ret = gp->err_code;
        CHECK(ret);
        mp_Xg = my_init(0, gp);
        ret = gp->err_code;
        CHECK(ret);
        mp_Yg = my_init(0, gp);
        ret = gp->err_code;
        CHECK(ret);
        mp_XA = my_init(0, gp);
        ret = gp->err_code;
        CHECK(ret);
        mp_YA = my_init(0, gp);
        ret = gp->err_code;
        CHECK(ret);
        mp_dA = my_init(0, gp);
        ret = gp->err_code;
        CHECK(ret);
        mp_r = my_init(0, gp);
        ret = gp->err_code;
        CHECK(ret);
        mp_s = my_init(0, gp);
        ret = gp->err_code;
        CHECK(ret);
        mp_e = my_init(0, gp);
        ret = gp->err_code;
        CHECK(ret);
        G = my_point_init(gp);
        ret = gp->err_code;
        CHECK(ret);
        P = my_point_init(gp);
        ret = gp->err_code;
        CHECK(ret);

        ret = std_param(mp_a, mp_b, mp_n, mp_p, mp_Xg, mp_Yg, gp);
        CHECK(ret);

        if (pubkey != NULL) {
            my_read_bin(32, (const char *)pubkey, mp_XA, gp);
            ret = gp->err_code;
            CHECK(ret);
            my_read_bin(32, (const char *)pubkey + 32, mp_YA, gp);
            ret = gp->err_code;
            CHECK(ret);
        }
        else {
            my_ecc_init(mp_a, mp_b, mp_p, gp);
            ret = gp->err_code;
            CHECK(ret);
            my_set_point(mp_Xg, mp_Yg, G, gp);
            ret = gp->err_code;
            CHECK(ret);
            my_point_mul(mp_dA, G, P, gp);
            ret = gp->err_code;
            CHECK(ret);
            my_get_point(P, mp_XA, mp_YA, gp);
            ret = gp->err_code;
            CHECK(ret);
        }
        ret = sm3_progress(hashbuf, &hashLen, data, datalen, "1234567812345678", 16, mp_XA, mp_YA,
                           gp);
        CHECK(ret);
    }
    else {
        ret = hash(flag_hash_algo, data, datalen, hashbuf, &hashLen);
        if (ret) {
            printf("hash failed, error code: %d\n", ret);
            goto END;
        }
    }

    if (flag_output_format == 1) {
        ret = base64_encode(hashbuf, hashLen, bhash, &bhashLen);
        printf("%s\n", bhash);
    }
    else if (flag_output_format == 2) {
        for (i = 0; i < hashLen; i++)
            printf("%02X ", hashbuf[i]);
        printf("\n");
    }

END:
    if (temp)
        free(temp);
    temp = NULL;
    if (pubkey)
        free(pubkey);
    pubkey = NULL;
    if (source)
        free(source);
    source = NULL;
    if (data)
        free(data);
    data = NULL;
    my_clear(mp_a);
    my_clear(mp_b);
    my_clear(mp_n);
    my_clear(mp_p);
    my_clear(mp_Xg);
    my_clear(mp_Yg);
    my_clear(mp_XA);
    my_clear(mp_YA);
    my_clear(mp_dA);
    my_clear(mp_r);
    my_clear(mp_s);
    my_clear(mp_e);
    my_point_clear(G);
    my_point_clear(P);
    my_gp_clear(gp);

    return;
}
#endif

#ifdef ECCDECRYPT

void printf_instruction()
{
    printf("\n-------------------- HELP --------------------\n");
    printf("INSTRUCTION:\n");
    printf("    This program is created for SM2 Decrypt, input SM2 private key &\n");
    printf("    SM2 encrypted data, the program will automatically compute source data.\n");
    printf("SYNOPSIS:\n");
    printf("    ECC_decrypt [-c cipher]  [-k private key]\n");
    printf("USE:\n");
    printf("    -k identify the private key\n");
    printf("    -c identify the cipher\n");
    printf("-------------------- HELP --------------------\n");
    return;
}

void main(int argc, char **argv)
{
    if (argc < 3) {
        printf("Error: input parameters not enough\n");
        printf_instruction();
        return;
    }

    int ret, i, ch;
    unsigned char *plain = NULL;
    unsigned int plainLen = 0;
    unsigned char *cipher = NULL;
    unsigned int cipherLen = 0;
    unsigned char *d = NULL;
    unsigned int dLen = 0;
    unsigned char *bplain = NULL;

    opterr = 0;

    while ((ch = getopt(argc, argv, "c:k:")) != -1) {
        switch (ch) {
            case 'c':
                cipher = b64_de(optarg, strlen(optarg), &cipherLen);
                if (cipher == NULL) {
                    printf("base64 decode cipher failed\n");
                    goto END;
                }
                break;

            case 'k':
                d = b64_de(optarg, strlen(optarg), &dLen);
                if (d == NULL) {
                    printf("base64 decode private failed\n");
                    goto END;
                }
                break;

            default:
                printf("Unrecognized option, type -h to print instruction\n");
                goto END;
        }
    }

    plainLen = cipherLen;
    plain = (unsigned char *)calloc(plainLen, 1);

    ret = sm2_dec(plain, &plainLen, cipher, cipherLen, d, dLen);
    if (ret) {
        printf("decrypt failed, ret: %d\n", ret);
        goto END;
    }

    bplain = b64_en(plain, plainLen, NULL);
    printf("message:\n%s\n", bplain);

END:
    if (d)
        free(d);
    d = NULL;
    if (cipher)
        free(cipher);
    cipher = NULL;
    if (bplain)
        free(bplain);
    bplain = NULL;

    return;
}
#endif    // ECCDECRYPT

#ifdef ECCSIGN

void printf_instruction(void)
{
    printf("\n-------------------- HELP --------------------\n");
    printf("INSTRUCTION:\n");
    printf("    This program is created for SM2 sign, input SM2 private \n");
    printf("    key and data to be sign, the program \n");
    printf("    will automatically compute signature.\n");
    printf("SYNOPSIS:\n");
    printf("    ECC_sign [-d data to be sign]  [-k private key] \n");
    printf("             [-p public key] [-h hashflag]\n");
    printf("USE:\n");
    printf("    -k private key\n");
    printf("    -d data to be sign (should be either raw data or raw data \n");
    printf("       with pre-procession\n");
    printf("    -p SM2 pubkey if input data haven't be dealt with pre-procession \n");
    printf("    -h if '-h' is identified, then input data with be dealt with \n");
    printf("       pre-procession; or else, the input data with be signed directly\n");
    printf("-------------------- HELP --------------------\n");
    return;
}

int main(int argc, char *argv[])
{
    int ret, i, ch;
    opterr = 0;

    unsigned char *prikey = NULL;
    unsigned char *input_data = NULL;
    unsigned char *raw_data = NULL;
    unsigned int input_datalen;
    unsigned int priLen;
    unsigned int raw_datalen;

    unsigned char *userID = (unsigned char *)"1234567812345678";
    unsigned int IDLen = 16;
    unsigned char *pubkey = NULL;
    unsigned int pubkeylen = 0;
    unsigned int hashFlag = NO_HASH;
    unsigned char signature[128] = {0};
    unsigned int signLen = 128;
    unsigned char *temp = NULL;

    unsigned char bsign[128] = {0};
    unsigned int bsignlen = 128;

    if (argc < 3) {
        printf("Error: no input\n");
        printf_instruction();
        return 1;
    }

    while ((ch = getopt(argc, argv, "k:d:p:h")) != -1) {
        switch (ch) {
            case 'k':
                prikey = b64_de(optarg, strlen(optarg), &priLen);
                if (prikey == NULL) {
                    printf("Error: base64 decode prikey failed\n");
                    goto END;
                }
                break;

            case 'd':
                input_datalen = strlen(optarg);
                input_data = (unsigned char *)calloc(input_datalen + 1, 1);
                memcpy(input_data, optarg, input_datalen);
                break;

            case 'h':
                hashFlag = WITH_HASH;
                break;

            case 'p':
                temp = b64_de(optarg, strlen(optarg), &pubkeylen);
                if (temp == NULL) {
                    printf("re-check pubkey, format invalid\n");
                    goto END;
                }
                if (pubkeylen == 65 || pubkeylen == 64) {
                    pubkey = (unsigned char *)calloc(64, 1);
                    memcpy(pubkey, temp + pubkeylen - 64, 64);
                    pubkeylen = 64;
                }
                else {
                    printf("invalid length of pubkey\n");
                    goto END;
                }
                break;
            default:
                printf("Unrecognized option\n");
                printf_instruction();
                goto END;
        }
    }

    raw_data = b64_de(input_data, input_datalen, &raw_datalen);
    if (raw_data == NULL) {
        printf("Error: base64 decode data failed\n");
        goto END;
    }

    // go!
    // 要不然就传原文的base，要不然就传做过预处理的杂凑值
    ret = sm2_sign(signature, &signLen, raw_data, raw_datalen, userID, IDLen, prikey, priLen,
                   pubkey, hashFlag);
    if (ret) {
        printf("SM2 sign failed, ret: %d\n", ret);
        goto END;
    }

    // encode outcome
    ret = base64_encode(signature, signLen, bsign, &bsignlen);
    if (ret) {
        printf("base64 encode outcome failed, ret: %d\n", ret);
        goto END;
    }

    // print outcome
    printf("%s\n", bsign);

END:
    if (prikey)
        free(prikey);
    prikey = NULL;
    if (raw_data)
        free(raw_data);
    raw_data = NULL;
    if (input_data)
        free(input_data);
    input_data = NULL;

    return ret;
}

#endif    // ECCSIGN

#ifdef RANDOM

void printf_instruction(void) { printf("please input length of random number to be generate\n"); }

int main(int argc, char *argv[])
{
    if (argc < 2) {
        printf("Error: no input\n");
        printf_instruction();
        return 1;
    }

    unsigned char *random = NULL;
    int len = atoi(argv[1]);
    if (len == -1) {
        printf("FATAL: exceed error\n");
        return 1;
    }

    int segment_num = len / 1024;
    int rest = len % 1024;

    if (segment_num)
        printf("--- random number is divided into 1024 bytes per block ---\n");

    while (segment_num > 0 || rest) {
        int this_grouplen = (segment_num ? 1024 : rest);

        if (--segment_num == -1)
            rest = 0;

        random = (unsigned char *)calloc(this_grouplen + 1, 1);

        int ret = my_random(random, this_grouplen);
        if (ret) {
            printf("failed generate random\n");
            return 1;
        }
        unsigned int brandomlen = (this_grouplen + 3) / 3 * 4 + 1;
        unsigned char *brandom = (unsigned char *)calloc(brandomlen, 1);

        ret = base64_encode(random, this_grouplen, brandom, &brandomlen);
        if (ret) {
            printf("base64 failed\n");
            return 1;
        }
        printf("%s\n", brandom);
        if (random)
            free(random);
        random = NULL;
        if (brandom)
            free(brandom);
        brandom = NULL;
    }

    return 0;
}

#endif    // RANDOM

#ifdef SM2GENKEY

int main(int argc, char *argv[])
{
    unsigned char prikey[33] = {0};
    unsigned int priLen = 33;
    unsigned char pubkey[64] = {0};
    int ret = sm2_gen_keypair(prikey, &priLen, pubkey);
    if (ret) {
        printf("generate SM2 keypair failed, ret: %d\n", ret);
        return ret;
    }

    unsigned char *bprikey = b64_en(prikey, priLen, NULL);
    if (bprikey == NULL) {
        printf("encode prikey failed\n");
        return 1;
    }

    unsigned char *bpubkey = b64_en(pubkey, 64, NULL);
    if (bpubkey == NULL) {
        printf("encode pubkey failed\n");
        return 1;
    }

    printf("prikey: %s\n", bprikey);
    printf("pubkey: %s\n", bpubkey);

    return 0;
}

#endif    // SM2GENKEY

#ifdef DH

int main()
{
    int i;
    int ret = 0;

    time_t start_time, end_time;

    time(&start_time);

    for (i = 0; i < 10000; i++) {
        unsigned int L = 1024;
        unsigned int m = 160;

        unsigned char p[4097] = {0};
        unsigned int p_len = 4096;
        unsigned char q[4097] = {0};
        unsigned int q_len = 4096;
        unsigned char seed[4097] = {0};
        unsigned int seed_len = 4096;
        unsigned int pgenCounter = 0;
        unsigned char g[2049] = {0};
        unsigned int g_len = 2048;

        ret = prime_generation(L, m, p, &p_len, q, &q_len, seed, &seed_len, &pgenCounter);
        if (ret) {
            ret = prime_generation(L, m, p, &p_len, q, &q_len, seed, &seed_len, &pgenCounter);
            if (ret) {
                printf("failed at prime_generation, ret: %d\n", ret);
                return ret;
            }
        }

        print_byte("p", p, p_len);
        print_byte("q", q, q_len);
        print_byte("seed", seed, seed_len);

        ret = select_generator(p, p_len, q, q_len, g, &g_len);
        if (ret) {
            printf("failed at select_generator, ret: %d\n", ret);
            return ret;
        }

        print_byte("g", g, g_len);

        ret = prime_validation(p, p_len, q, q_len, seed, seed_len, L, m, pgenCounter);
        if (ret) {
            printf("failed at prime_validation, ret: %d\n", ret);
            return ret;
        }

        printf("prime is valid\n");

        // party U
        unsigned char u_pubkey[4096] = {0};
        unsigned int u_pubkey_len = 4096;
        unsigned char u_prikey[4096] = {0};
        unsigned int u_prikey_len = 4096;

        ret = generate_key_pair(p, p_len, q, q_len, g, g_len, u_pubkey, &u_pubkey_len, u_prikey,
                                &u_prikey_len);
        if (ret) {
            printf("ret: %d\n", ret);
            return ret;
        }

        print_byte("u_pubkey", u_pubkey, u_pubkey_len);
        print_byte("u_prikey", u_prikey, u_prikey_len);

        ret = public_key_validation(p, p_len, q, q_len, g, g_len, seed, seed_len, u_pubkey,
                                    u_pubkey_len);
        if (ret) {
            printf("ret: %d\n", ret);
            return ret;
        }

        printf("u's public key is valid\n");

        // party V
        unsigned char v_pubkey[4096] = {0};
        unsigned int v_pubkey_len = 4096;
        unsigned char v_prikey[4096] = {0};
        unsigned int v_prikey_len = 4096;

        ret = generate_key_pair(p, p_len, q, q_len, g, g_len, v_pubkey, &v_pubkey_len, v_prikey,
                                &v_prikey_len);
        if (ret) {
            printf("ret: %d\n", ret);
            return ret;
        }

        print_byte("v_pubkey", v_pubkey, v_pubkey_len);
        print_byte("v_prikey", v_prikey, v_prikey_len);

        ret = public_key_validation(p, p_len, q, q_len, g, g_len, seed, seed_len, v_pubkey,
                                    v_pubkey_len);
        if (ret) {
            printf("ret: %d\n", ret);
            return ret;
        }

        printf("v's public key is valid\n");

        unsigned char u_zz[4096] = {0};
        unsigned int u_zz_len = 4096;
        unsigned char v_zz[4096] = {0};
        unsigned int v_zz_len = 4096;

        ret = calculate_zz(p, p_len, q, q_len, g, g_len, v_pubkey, v_pubkey_len, u_prikey,
                           u_prikey_len, u_zz, &u_zz_len);
        if (ret) {
            printf("ret: %d\n", ret);
            return ret;
        }

        ret = calculate_zz(p, p_len, q, q_len, g, g_len, u_pubkey, u_pubkey_len, v_prikey,
                           v_prikey_len, v_zz, &v_zz_len);
        if (ret) {
            printf("ret: %d\n", ret);
            return ret;
        }

        print_byte("U's ZZ", u_zz, u_zz_len);
        print_byte("V's ZZ", v_zz, v_zz_len);
    }

    time(&end_time);
    printf("total time: %f seconds\n", difftime(end_time, start_time));

    return ret;
}

#endif // DH