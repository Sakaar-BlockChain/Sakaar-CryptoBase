#ifndef CRYPTO_BASE_H
#define CRYPTO_BASE_H

#include "struct.h"
#include "crypto_code.h"
#include "hash_code.h"

#define BASE_ECC        0x1000

#define BASE_SECP       (BASE_ECC | 0x0100)
#define BASE_SECT       (BASE_ECC | 0x0200)

#define BASE_SECP_K     (BASE_SECP | 0x0010)
#define BASE_SECP_R     (BASE_SECP | 0x0020)
#define BASE_SECT_K     (BASE_SECT | 0x0010)
#define BASE_SECT_R     (BASE_SECT | 0x0020)

#define BASE_SECP112R1  (0x0001 | BASE_SECP_R)
#define BASE_SECP112R2  (0x0002 | BASE_SECP_R)
#define BASE_SECP128R1  (0x0003 | BASE_SECP_R)
#define BASE_SECP128R2  (0x0004 | BASE_SECP_R)
#define BASE_SECP160K1  (0x0001 | BASE_SECP_K)
#define BASE_SECP160R1  (0x0005 | BASE_SECP_R)
#define BASE_SECP160R2  (0x0006 | BASE_SECP_R)
#define BASE_SECP192K1  (0x0002 | BASE_SECP_K)
#define BASE_SECP192R1  (0x0007 | BASE_SECP_R)
#define BASE_SECP224K1  (0x0003 | BASE_SECP_K)
#define BASE_SECP224R1  (0x0008 | BASE_SECP_R)
#define BASE_SECP256K1  (0x0004 | BASE_SECP_K)
#define BASE_SECP256R1  (0x0009 | BASE_SECP_R)
#define BASE_SECP384R1  (0x000a | BASE_SECP_R)
#define BASE_SECP521R1  (0x000b | BASE_SECP_R)

struct crypto_base{
    int (*_encode)(const struct string_st *public, const struct string_st *private, const struct string_st *str, unsigned hash_type, unsigned crypto_type, struct string_st *res);
    int (*_decode)(const struct string_st *public, const struct string_st *private, const struct string_st *str, unsigned hash_type, unsigned crypto_type, struct string_st *res);
    int (*_encode_self)(const struct string_st *private, const struct string_st *str, unsigned hash_type, unsigned crypto_type, struct string_st *res);
    int (*_decode_self)(const struct string_st *private, const struct string_st *str, unsigned hash_type, unsigned crypto_type, struct string_st *res);

    int (*_get_public)(const struct string_st *private, struct string_st *public);
    void (*_from_string)(struct string_st *private, const struct string_st *str);
    void (*_generate)(struct string_st *private);


    int (*_create_sign)(struct string_st *sign, const struct string_st *private, const struct string_st *hash);
    int (*_check_sign)(const struct string_st *sign, const struct string_st *public, const struct string_st *hash);
};

extern struct crypto_base secp112r1;
extern struct crypto_base secp112r2;
extern struct crypto_base secp128r1;
extern struct crypto_base secp128r2;
extern struct crypto_base secp160k1;
extern struct crypto_base secp160r1;
extern struct crypto_base secp160r2;
extern struct crypto_base secp192k1;
extern struct crypto_base secp192r1;
extern struct crypto_base secp224k1;
extern struct crypto_base secp224r1;
extern struct crypto_base secp256k1;
extern struct crypto_base secp256r1;
extern struct crypto_base secp384r1;
extern struct crypto_base secp521r1;

struct crypto_base get_crypto_base(unsigned code);

#endif //CRYPTO_BASE_H
