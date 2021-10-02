//
// Created by Reverier-Xu on 2021/10/3.
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

#endif //MEOW_CRYPTO_UTILS_H
