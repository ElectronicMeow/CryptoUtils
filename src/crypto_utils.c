//
// Created by Reverier-Xu on 2021/10/3.
//

#include "crypto_utils.h"

#include <gmp.h>
#include <unistd.h>
#include <fcntl.h>

/** MACRO INIT_RANDOM_GENERATOR()
 * 初始化GMP的随机数生成器，工具片段。调用此宏之后可以使用grt变量获取已经初始化完成的随机数生成器。
 */
#define INIT_RANDOM_GENERATOR() \
        gmp_randstate_t grt; \
        gmp_randinit_default(grt); \
        unsigned int seed; \
        int random_fd = open("/dev/urandom", O_RDONLY); \
        read(random_fd, &seed, sizeof(unsigned int)); \
        close(random_fd); \
        gmp_randseed_ui(grt, seed);

/**
 * 根据公共参数N、g与公钥pk对信息m进行加密操作，结果通过字符串返回给 (res_A_hex, res_B_hex)。
 * -*- 内存管理提示 -*- ：本函数不会对传入的字符串进行释放操作，
 * 返回值 A，B 会自动申请字符串空间，无需提前申请。
 * A，B 自动申请的空间大小为 strlen(str) + 1，如有需要请自行释放。
 * @param public_N_hex  公共参数N，应当是一个十六进制字符串。
 * @param public_g_hex  公共参数g，应当是一个十六进制字符串。
 * @param pk_hex  公钥，应当是一个十六进制字符串。
 * @param m_hex  需要加密的明文，应当是一个十六进制字符串。
 * @param res_A_hex  加密结果密文对 (A, B) 中的 A。
 * @param res_B_hex  加密结果密文对 (A, B) 中的 B。
 * @return 本函数什么也不返回，结果通过 (res_A_hex, res_B_hex) 进行传递。
 */
void encrypt(const char *public_N_hex,
             const char *public_g_hex,
             const char *pk_hex,
             const char *m_hex,
             char **res_A_hex,
             char **res_B_hex) {
    INIT_RANDOM_GENERATOR()
    mpz_t N, g, N2, r, A, B, pk, m;
    mpz_init_set_str(N, public_N_hex, 16);
    mpz_init_set_str(g, public_g_hex, 16);
    mpz_init_set_str(pk, pk_hex, 16);
    mpz_init_set_str(m, m_hex, 16);
    mpz_init(N2);
    mpz_init(r);
    mpz_init(A);
    mpz_init(B);
    mpz_mul(N2, N, N);
    mpz_urandomm(r, grt, N2);
    mpz_powm(A, g, r, N2);

    mpz_t r_tmp;
    mpz_init(r_tmp);
    mpz_powm(B, pk, r, N2);
    mpz_mul(r_tmp, m, N);
    mpz_add_ui(r_tmp, r_tmp, 1);
    mpz_mul(B, B, r_tmp);
    mpz_mod(B, B, N2);

    mpz_clear(N);
    mpz_clear(g);
    mpz_clear(N2);
    mpz_clear(r);
    mpz_clear(r_tmp);

    *res_A_hex = mpz_get_str(NULL, 16, A);
    *res_B_hex = mpz_get_str(NULL, 16, B);

    mpz_clear(A);
    mpz_clear(B);
}

/**
 * 根据公共参数N与私钥sk将密文对 (W, Z) 解密，结果通过字符串返回给 result_hex。
 * -*- 内存管理提示 -*- ：本函数不会对传入的字符串进行释放操作，
 * 返回值 result_hex 会自动申请字符串空间，无需提前申请。
 * result_hex 自动申请的空间大小为 strlen(str) + 1，如有需要请自行释放。
 * @param public_N_hex  公共参数N，应当是一个十六进制字符串。
 * @param sk_hex  私钥，应当是一个十六进制字符串。
 * @param W_hex  密文对中的 W，应当是一个十六进制字符串。
 * @param Z_hex  密文对中的  Z，应当是一个十六进制字符串。
 * @return 本函数什么也不返回，结果通过 result_hex 进行传递。
 */
void decrypt(const char *public_N_hex,
             const char *sk_hex,
             const char *W_hex,
             const char *Z_hex,
             char **result_hex) {
    mpz_t N, N2, up, sk_tmp, sk, W, Z;
    mpz_init_set_str(N, public_N_hex, 16);
    mpz_init_set_str(sk, sk_hex, 16);
    mpz_init_set_str(W, W_hex, 16);
    mpz_init_set_str(Z, Z_hex, 16);
    mpz_init(N2);
    mpz_init(up);
    mpz_init(sk_tmp);
    mpz_mul(N2, N, N);
    mpz_mul_si(sk_tmp, sk, -1);
    mpz_powm(W, W, sk_tmp, N2);
    mpz_mul(Z, Z, W);
    mpz_sub_ui(Z, Z, 1);
    mpz_mod(up, Z, N2);
    mpz_fdiv_q(up, up, N);

    *result_hex = mpz_get_str(NULL, 16, up);

    mpz_clear(N);
    mpz_clear(N2);
    mpz_clear(up);
    mpz_clear(sk_tmp);
}
