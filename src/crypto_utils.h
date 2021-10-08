//
// Created on 2021/10/3.
// Algorithm developed in Python by @D33BaT0
// Exported to C by @XWanan
// Refactored by @Reverier-Xu
//

#ifndef MEOW_CRYPTO_UTILS_H
#define MEOW_CRYPTO_UTILS_H


#include <gmp.h>

typedef unsigned char uint8_t;

void encrypt(const char *public_N_hex,
             const char *public_g_hex,
             const char *pk,
             const char *m,
             char **res_A,
             char **res_B);

void decrypt(const char *public_N_hex,
             const char *sk_hex,
             const char *W_hex,
             const char *Z_hex,

             char **result_hex);

void key_gen(const char* public_N_hex,
             const char* public_g_hex,

             char ** public_key,
             char ** secret_key);

void key_gen_main(const char *p_hex,
                  const char *q_hex,

                  char **sec_p,
                  char **sec_q,
                  char **pub_N,
                  char **pub_k,
                  char **pub_g);

void unique_decrypt(const char *public_N_hex,
                    const char *public_k_hex,
                    const char *public_g_hex,
                    const char* pk_hex,
                    const char *secret_p_hex,
                    const char *secret_q_hex,
                    const char *A_hex,
                    const char *B_hex,
                    char ** result_m);

void get_master_pk(const char*public_N_hex, const char * pks[], int pks_length, char ** prod_pk);


#endif //MEOW_CRYPTO_UTILS_H
