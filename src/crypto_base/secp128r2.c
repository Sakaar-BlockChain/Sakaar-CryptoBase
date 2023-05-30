#include "crypto_base.h"
#include "ecc.h"

int secp128r2_encode(const struct string_st *public, const struct string_st *private, const struct string_st *str, unsigned hash_type, unsigned crypto_type, struct string_st *res) {
    struct ecc_curve *curve = ecc_curve_new();
    struct ecc_key *public_key = ecc_key_new();
    struct ecc_key *private_key = ecc_key_new();
    struct string_st *hash = string_new();
    int result;

    ecc_curve_secp128r2(curve);
    if((result = ecc_key_set_str(public_key, public, curve))) goto end;
    if((result = ecc_key_set_str(private_key, private, curve))) goto end;

    ecc_key_get_key(public_key, private_key, curve, hash);
    get_hash_code(hash_type)._code(hash, hash);
    get_crypto_code(crypto_type)._encode(res, str, hash);
    end:
    ecc_key_free(private_key);
    ecc_key_free(public_key);
    ecc_curve_free(curve);
    string_free(hash);
    return result;
}
int secp128r2_decode(const struct string_st *public, const struct string_st *private, const struct string_st *str, unsigned hash_type, unsigned crypto_type, struct string_st *res) {
    struct ecc_curve *curve = ecc_curve_new();
    struct ecc_key *public_key = ecc_key_new();
    struct ecc_key *private_key = ecc_key_new();
    struct string_st *hash = string_new();
    int result;

    ecc_curve_secp128r2(curve);
    if((result = ecc_key_set_str(public_key, public, curve))) goto end;
    if((result = ecc_key_set_str(private_key, private, curve))) goto end;

    ecc_key_get_key(public_key, private_key, curve, hash);
    get_hash_code(hash_type)._code(hash, hash);
    get_crypto_code(crypto_type)._decode(res, str, hash);
    end:
    ecc_key_free(private_key);
    ecc_key_free(public_key);
    ecc_curve_free(curve);
    string_free(hash);
    return result;
}
int secp128r2_encode_self(const struct string_st *private, const struct string_st *str, unsigned hash_type, unsigned crypto_type, struct string_st *res) {
    struct ecc_curve *curve = ecc_curve_new();
    struct ecc_key *key = ecc_key_new();
    struct string_st *hash = string_new();
    int result;

    ecc_curve_secp128r2(curve);
    if((result = ecc_key_set_str(key, private, curve))) goto end;

    ecc_key_get_key_self(key, curve, hash);
    get_hash_code(hash_type)._code(hash, hash);
    get_crypto_code(crypto_type)._encode(res, str, hash);
    end:
    ecc_key_free(key);
    ecc_curve_free(curve);
    string_free(hash);
    return result;
}
int secp128r2_decode_self(const struct string_st *private, const struct string_st *str, unsigned hash_type, unsigned crypto_type, struct string_st *res) {
    struct ecc_curve *curve = ecc_curve_new();
    struct ecc_key *key = ecc_key_new();
    struct string_st *hash = string_new();
    int result;

    ecc_curve_secp128r2(curve);
    if((result = ecc_key_set_str(key, private, curve))) goto end;

    ecc_key_get_key_self(key, curve, hash);
    get_hash_code(hash_type)._code(hash, hash);
    get_crypto_code(crypto_type)._decode(res, str, hash);
    end:
    ecc_key_free(key);
    ecc_curve_free(curve);
    string_free(hash);
    return result;
}


int secp128r2_get_public(const struct string_st *private, struct string_st *public) {
    struct ecc_curve *curve = ecc_curve_new();
    struct ecc_key *key = ecc_key_new();
    int result;

    ecc_curve_secp128r2(curve);
    if((result = ecc_key_set_str(key, private, curve))) goto end;

    ecc_key_get_address(key, public);
    end:
    ecc_key_free(key);
    ecc_curve_free(curve);
    return result;
}
void secp128r2_from_string(struct string_st *private, const struct string_st *str) {
    struct ecc_curve *curve = ecc_curve_new();
    struct ecc_key *key = ecc_key_new();

    ecc_curve_secp128r2(curve);
    ecc_key_generate(key, str, curve);

    ecc_key_get_str(key, private);

    ecc_key_free(key);
    ecc_curve_free(curve);
}
void secp128r2_generate(struct string_st *private) {
    struct ecc_curve *curve = ecc_curve_new();
    struct ecc_key *key = ecc_key_new();

    ecc_curve_secp128r2(curve);
    ecc_key_generate_f(key, curve);

    ecc_key_get_str(key, private);

    ecc_key_free(key);
    ecc_curve_free(curve);
}


int secp128r2_create_sign(struct string_st *sign, const struct string_st *private, const struct string_st *hash) {
    struct ecc_curve *curve = ecc_curve_new();
    struct ecc_sign *signature = ecc_sign_new();
    struct ecc_key *key = ecc_key_new();
    int result;

    ecc_curve_secp128r2(curve);
    if((result = ecc_key_set_str(key, private, curve))) goto end;
    ecc_sign_create(signature, key, hash, curve);

    ecc_sign_get_str(signature, sign);
    end:
    ecc_key_free(key);
    ecc_sign_free(signature);
    ecc_curve_free(curve);
    return result;
}
int secp128r2_check_sign(const struct string_st *sign, const struct string_st *public, const struct string_st *hash) {
    struct ecc_curve *curve = ecc_curve_new();
    struct ecc_sign *signature = ecc_sign_new();
    struct ecc_key *key = ecc_key_new();
    int result;

    ecc_curve_secp128r2(curve);
    if((result = ecc_key_set_str(key, public, curve))) goto end;
    if((result = ecc_sign_set_str(signature, sign))) goto end;

    result = ecc_sign_check(signature, key, hash, curve);
    end:
    ecc_key_free(key);
    ecc_sign_free(signature);
    ecc_curve_free(curve);
    return result;
}


struct crypto_base secp128r2 = {
        &secp128r2_encode,
        &secp128r2_decode,
        &secp128r2_encode_self,
        &secp128r2_decode_self,

        &secp128r2_get_public,
        &secp128r2_from_string,
        &secp128r2_generate,

        &secp128r2_create_sign,
        &secp128r2_check_sign
};