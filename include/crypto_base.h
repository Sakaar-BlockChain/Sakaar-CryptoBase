#ifndef CRYPTO_BASE_H
#define CRYPTO_BASE_H

#include "struct.h"
#include "crypto_code.h"
#include "hash_code.h"

#define BASE_SECP256K1 1

struct crypto_base{
    void (*_encode)(const struct string_st *public, const struct string_st *private, const struct string_st *str, unsigned hash_type, unsigned crypto_type, struct string_st *res);
    void (*_decode)(const struct string_st *public, const struct string_st *private, const struct string_st *str, unsigned hash_type, unsigned crypto_type, struct string_st *res);
    void (*_encode_self)(const struct string_st *private, const struct string_st *str, unsigned hash_type, unsigned crypto_type, struct string_st *res);
    void (*_decode_self)(const struct string_st *private, const struct string_st *str, unsigned hash_type, unsigned crypto_type, struct string_st *res);

    void (*_get_public)(const struct string_st *private, struct string_st *public);
    void (*_from_string)(struct string_st *private, const struct string_st *str);
    void (*_generate)(struct string_st *private);


    void (*_create_sign)(struct string_st *sign, const struct string_st *private, const struct string_st *hash);
    int (*_check_sign)(const struct string_st *sign, const struct string_st *public, const struct string_st *hash);
};

extern struct crypto_base secp256k1;
struct crypto_base get_crypto_base(unsigned code);

#endif //CRYPTO_BASE_H
