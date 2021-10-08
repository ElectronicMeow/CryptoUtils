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
             const char *public_key_hex,
             const char *plaintext_hex,
             char **res_encrypted_pair_a,
             char **res_encrypted_pair_b);

void decrypt(const char *public_N_hex,
             const char *secret_key_hex,
             const char *encrypted_pair_a_hex,
             const char *encrypted_pair_b_hex,
             char **res_plaintext);

void key_gen(const char* public_N_hex,
             const char* public_g_hex,

             char ** public_key,
             char ** secret_key);

void key_gen_main(char **public_N_hex, char **public_k_hex, char **public_g_hex, const char *prime_p_hex,
                  const char *prime_q_hex, char **secret_key_pair_p, char **secret_key_pair_q);

void unique_decrypt(const char *public_N_hex,
                    const char *public_k_hex,
                    const char *public_g_hex,
                    const char* public_key_hex,
                    const char *secret_key_pair_p_hex,
                    const char *secret_key_pair_q_hex,
                    const char *encrypted_pair_a_hex,
                    const char *encrypted_pair_b_hex,
                    char ** res_plaintext);

void get_master_pk(const char*public_N_hex, const char * pks[], int pks_length, char ** prod_pk);


#endif //MEOW_CRYPTO_UTILS_H
