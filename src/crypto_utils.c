//
// Created on 2021/10/3.
// Algorithm developed in Python by @D33BaT0
// Exported to C by @XWanan
// Refactored by @Reverier-Xu
//

#include "crypto_utils.h"

#include <gmp.h>
#include <unistd.h>
#include <fcntl.h>

#define DEFAULT_MASTER_P_ "16D1F12C3F7A38F318C23A0A75491C89" \
                          "629FADF2005B217ADAC7CEFEE96FD2EF" \
                          "40BD70D1E17AB49F547AE04FADF4C64C" \
                          "DBAADA32FD090B98E9C87532DF55A4B7" \
                          "6298725E35AE5E73AF6E7FDA4218E906" \
                          "8ACE591F1E76E63B0CBC46AF434C9DC0" \
                          "87F7E4E61CAE1466E6A3AB478AEF8105" \
                          "8DA6965F21F09CE9B9FC9F008EB8D247"

#define DEFAULT_MASTER_Q_ "39E8F5DDEC7A52EF02AA5E7EC66D351F" \
                          "3A8F747E0526B25966B3CB253544C85A" \
                          "44A32AC4F07AF7389FA226C73BE96623" \
                          "71F2F92AA5318805502F3BCF4307E39A" \
                          "02623E940AD935D391730AA3089FF347" \
                          "33F5C1C0A62B8284DD84AA25B52C49CB" \
                          "3931D52C9D7D99C9C22F9AE88C231161" \
                          "C02CE45D78EB79CE44A8FE0E8A679CA7"

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
 * @return 有个锤子返回值。
 */
void encrypt(const char *public_N_hex,
             const char *public_g_hex,
             const char *pk_hex,
             const char *m_hex,
             char **res_A_hex,
             char **res_B_hex) {
    INIT_RANDOM_GENERATOR();
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
    mpz_clear(pk);
    mpz_clear(m);
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
 * @return 有个锤子返回值。
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
    mpz_clear(sk);
    mpz_clear(W);
    mpz_clear(Z);
}

/**
 * 根据公共参数 N，g 生成密钥对，公钥和密钥分别通过指针参数 public_key 与 secret_key 以十六进制数字字符串返回。
 * @param public_N_hex 公共参数 N。
 * @param public_g_hex 公共参数 g。
 * @param public_key 生成的密钥对结果中的公钥。
 * @param secret_key 生成的密钥对结果中的私钥。
 * @return 有个锤子返回值。
 */
void key_gen(const char *public_N_hex,
             const char *public_g_hex,
             char **public_key,
             char **secret_key) {
    INIT_RANDOM_GENERATOR();
    mpz_t N, g, N2, sk, pk;
    mpz_init_set_str(N, public_N_hex, 16);
    mpz_init_set_str(g, public_g_hex, 16);
    mpz_init(N2);
    mpz_init(sk);
    mpz_init(pk);
    mpz_mul(N2, N, N);
    mpz_urandomm(sk, grt, N2);
    mpz_powm(pk, g, sk, N2);

    *secret_key = mpz_get_str(NULL, 16, sk);
    *public_key = mpz_get_str(NULL, 16, pk);

    mpz_clear(N);
    mpz_clear(g);
    mpz_clear(N2);
    mpz_clear(sk);
    mpz_clear(pk);
}

/**
 * 生成 master key 所使用的函数。当 p，q 传入空指针时，将使用代码中默认的 p，q （不安全！！）
 * @param p_hex master key 参数 p。
 * @param q_hex master key 参数 q。
 * @param sec_p 生成的私钥参数 p。
 * @param sec_q 生成的私钥参数 q。
 * @param pub_N 生成的公钥参数 N。
 * @param pub_k 生成的公钥参数 k。
 * @param pub_g 生成的公钥参数 g。
 * @return 有个锤子返回值。
 */
void key_gen_main(const char *p_hex,
                  const char *q_hex,
                  char **sec_p,
                  char **sec_q,
                  char **pub_N,
                  char **pub_k,
                  char **pub_g) {

    mpz_t p, p_tmp;
    mpz_init(p);
    mpz_init(p_tmp);
    if (p_hex)
        mpz_set_str(p, p_hex, 16);
    else
        mpz_set_str(p, DEFAULT_MASTER_P_, 16);

    mpz_sub_ui(p_tmp, p, 1);
    mpz_fdiv_q_ui(p_tmp, p_tmp, 2);

    mpz_t q, q_tmp;
    mpz_init(q);
    mpz_init(q_tmp);
    if (q_hex)
        mpz_set_str(q, q_hex, 16);
    else
        mpz_set_str(q, DEFAULT_MASTER_Q_, 16);

    mpz_sub_ui(q_tmp, q, 1);
    mpz_fdiv_q_ui(q_tmp, q_tmp, 2);

    mpz_t N;
    mpz_init(N);
    mpz_mul(N, p, q);

    mpz_t N2;
    mpz_init(N2);
    mpz_mul(N2, N, N);

    mpz_t pt_qt;
    mpz_init(pt_qt);
    mpz_mul(pt_qt, p_tmp, q_tmp);

    mpz_t g, r_tmp, r_mod, r_div, N_tmp;
    mpz_init(g);
    mpz_init(r_tmp);
    mpz_init(r_mod);
    mpz_init(r_div);
    mpz_init(N_tmp);

    INIT_RANDOM_GENERATOR();

    while (1) {
        mpz_urandomm(g, grt, N2);
        mpz_powm(r_tmp, g, pt_qt, N2);
        mpz_sub_ui(r_tmp, r_tmp, 1);
        mpz_mod(r_mod, r_tmp, N);
        mpz_fdiv_q(r_div, r_tmp, N);
        mpz_sub_ui(N_tmp, N, 1);
        if (mpz_cmp_ui(r_mod, 0) == 0 &&
            mpz_cmp_ui(r_div, 1) >= 0 &&
            mpz_cmp(r_div, N_tmp) <= 0) {
            break;
        }
    }
    mpz_clear(r_mod);
    mpz_clear(r_div);
    mpz_clear(N_tmp);
    mpz_clear(pt_qt);

    mpz_t k;
    mpz_init(k);
    mpz_init(r_tmp);
    mpz_mul(r_tmp, p_tmp, q_tmp);
    mpz_powm(r_tmp, g, r_tmp, N2);
    mpz_sub_ui(r_tmp, r_tmp, 1);
    mpz_fdiv_q(k, r_tmp, N);

    // Returns here.
    *sec_p = mpz_get_str(NULL, 16, p_tmp);
    *sec_q = mpz_get_str(NULL, 16, q_tmp);

    *pub_N = mpz_get_str(NULL, 16, N);
    *pub_k = mpz_get_str(NULL, 16, k);
    *pub_g = mpz_get_str(NULL, 16, g);

    mpz_clear(N);
    mpz_clear(k);
    mpz_clear(g);
    mpz_clear(p_tmp);
    mpz_clear(q_tmp);
    mpz_clear(r_tmp);
    mpz_clear(p);
    mpz_clear(q);
}

/**
 * 统一解密，通过master key将使用不同密钥的密文全部解密出来。
 * @param public_N_hex master key 生成时使用的公共参数 N，十六进制字符串。
 * @param public_k_hex master key 生成时使用的公共参数 k，十六进制字符串。
 * @param public_g_hex master key 生成时使用的公共参数 g，十六进制字符串。
 * @param pk_hex 加密此信息使用的公钥，十六进制字符串。
 * @param secret_p_hex master key 中的 p，十六进制字符串。
 * @param secret_q_hex master key 中的 q，十六进制字符串。
 * @param A_hex 密文对中的 A，十六进制字符串。
 * @param B_hex 密文对中的 B，十六进制字符串。
 * @param result_m 解密后的明文结果，以十六进制字符串的格式返回。
 * @return 有个锤子返回值。
 */
void unique_decrypt(const char *public_N_hex,
                    const char *public_k_hex,
                    const char *public_g_hex,
                    const char* pk_hex,
                    const char *secret_p_hex,
                    const char *secret_q_hex,
                    const char *A_hex,
                    const char *B_hex,
                    char ** result_m) {
    // 初始化参数
    mpz_t p_sec, q_sec, N, k, g, h, N2, k_1;

    mpz_t pk, A, B;
    mpz_init_set_str(pk, pk_hex, 16);
    mpz_init_set_str(A, A_hex, 16);
    mpz_init_set_str(B, B_hex, 16);

    mpz_init_set_str(p_sec, secret_p_hex, 16);
    mpz_init_set_str(q_sec, secret_q_hex, 16);

    mpz_init_set_str(N, public_N_hex, 16);
    mpz_init_set_str(k, public_k_hex, 16);
    mpz_init_set_str(g, public_g_hex, 16);

    mpz_init(N2);
    mpz_mul(N2, N, N);

    mpz_init_set(h, pk);

    mpz_init(k_1);
    mpz_invert(k_1, k, N);

    //计算a, r, delta, gamma
    mpz_t r_tmp, ps_qs, a, r, delta, gamma;
    mpz_init(ps_qs);
    mpz_mul(ps_qs, p_sec, q_sec);

    mpz_init(a);
    mpz_init(r_tmp);
    mpz_powm(r_tmp, h, ps_qs, N2);
    mpz_sub_ui(r_tmp, r_tmp, 1);
    mpz_mod(r_tmp, r_tmp, N2);
    mpz_fdiv_q(r_tmp, r_tmp, N);
    mpz_mul(r_tmp, r_tmp, k_1);
    mpz_mod(a, r_tmp, N);

    mpz_init(r);
    mpz_init(r_tmp);
    mpz_powm(r_tmp, A, ps_qs, N2);
    mpz_sub_ui(r_tmp, r_tmp, 1);
    mpz_mod(r_tmp, r_tmp, N2);
    mpz_fdiv_q(r_tmp, r_tmp, N);
    mpz_mul(r_tmp, r_tmp, k_1);
    mpz_mod(r, r_tmp, N);

    mpz_init(delta);
    mpz_init(gamma);
    mpz_invert(delta, ps_qs, N);

    mpz_init(r_tmp);
    mpz_mul(r_tmp, a, r);
    mpz_mod(gamma, r_tmp, N);

    // 解密消息
    // m = ((((pow(B * invert(powmod(g,gamma,N2),N2),p_sec * q_sec, N2) - 1 ) %N2) // N) * delta )%N
    mpz_t m;
    mpz_init(r_tmp);
    mpz_init(m);
    mpz_powm(r_tmp, g, gamma, N2);
    mpz_invert(r_tmp, r_tmp, N2);
    mpz_mul(r_tmp, r_tmp, B);
    mpz_powm(r_tmp, r_tmp, ps_qs, N2);
    mpz_sub_ui(r_tmp, r_tmp, 1);
    mpz_mod(r_tmp, r_tmp, N2);
    mpz_fdiv_q(r_tmp, r_tmp, N);
    mpz_mul(r_tmp, r_tmp, delta);
    mpz_mod(m, r_tmp, N2);

//    gmp_printf("message= %Zd\n\n", m);
    *result_m = mpz_get_str(NULL, 16, m);

    mpz_clear(p_sec);
    mpz_clear(q_sec);
    mpz_clear(N);
    mpz_clear(k);
    mpz_clear(g);
    mpz_clear(h);
    mpz_clear(N2);
    mpz_clear(k_1);
    mpz_clear(ps_qs);
    mpz_clear(a);
    mpz_clear(r);
    mpz_clear(delta);
    mpz_clear(gamma);
    mpz_clear(r_tmp);
    mpz_clear(m);
    mpz_clear(A);
    mpz_clear(B);
    mpz_clear(pk);
}

