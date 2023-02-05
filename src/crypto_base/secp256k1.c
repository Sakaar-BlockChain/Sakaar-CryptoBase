#include "crypto_base.h"
#include "ecc.h"

void secp256k1_encode(const struct string_st *public, const struct string_st *private, const struct string_st *str, unsigned hash_type, unsigned crypto_type, struct string_st *res) {
    struct ecc_curve *curve = ecc_curve_new();
    struct ecc_key *public_key = ecc_key_new();
    struct ecc_key *private_key = ecc_key_new();
    struct string_st *hash = string_new();

    ecc_curve_secp256k1(curve);
    ecc_key_set_str(public_key, public, curve);
    ecc_key_set_str(private_key, private, curve);

    ecc_key_get_key(public_key, private_key, curve, hash);
    get_hash_code(hash_type)._code(hash, hash);
    get_crypto_code(crypto_type)._encode(res, str, hash);

    ecc_key_free(private_key);
    ecc_key_free(public_key);
    ecc_curve_free(curve);
    string_free(hash);
}
void secp256k1_decode(const struct string_st *public, const struct string_st *private, const struct string_st *str, unsigned hash_type, unsigned crypto_type, struct string_st *res) {
    struct ecc_curve *curve = ecc_curve_new();
    struct ecc_key *public_key = ecc_key_new();
    struct ecc_key *private_key = ecc_key_new();
    struct string_st *hash = string_new();

    ecc_curve_secp256k1(curve);
    ecc_key_set_str(public_key, public, curve);
    ecc_key_set_str(private_key, private, curve);

    ecc_key_get_key(public_key, private_key, curve, hash);
    get_hash_code(hash_type)._code(hash, hash);
    get_crypto_code(crypto_type)._decode(res, str, hash);

    ecc_key_free(private_key);
    ecc_key_free(public_key);
    ecc_curve_free(curve);
    string_free(hash);
}
void secp256k1_encode_self(const struct string_st *private, const struct string_st *str, unsigned hash_type, unsigned crypto_type, struct string_st *res) {
    struct ecc_curve *curve = ecc_curve_new();
    struct ecc_key *key = ecc_key_new();
    struct string_st *hash = string_new();

    ecc_curve_secp256k1(curve);
    ecc_key_set_str(key, private, curve);

    ecc_key_get_key_self(key, curve, hash);
    get_hash_code(hash_type)._code(hash, hash);
    get_crypto_code(crypto_type)._encode(res, str, hash);

    ecc_key_free(key);
    ecc_curve_free(curve);
    string_free(hash);
}
void secp256k1_decode_self(const struct string_st *private, const struct string_st *str, unsigned hash_type, unsigned crypto_type, struct string_st *res) {
    struct ecc_curve *curve = ecc_curve_new();
    struct ecc_key *key = ecc_key_new();
    struct string_st *hash = string_new();

    ecc_curve_secp256k1(curve);
    ecc_key_set_str(key, private, curve);

    ecc_key_get_key_self(key, curve, hash);
    get_hash_code(hash_type)._code(hash, hash);
    get_crypto_code(crypto_type)._decode(res, str, hash);

    ecc_key_free(key);
    ecc_curve_free(curve);
    string_free(hash);
}


void secp256k1_get_public(const struct string_st *private, struct string_st *public) {
    struct ecc_curve *curve = ecc_curve_new();
    struct ecc_key *key = ecc_key_new();

    ecc_curve_secp256k1(curve);
    ecc_key_set_str(key, private, curve);

    ecc_key_get_address(key, public);

    ecc_key_free(key);
    ecc_curve_free(curve);
}
void secp256k1_from_string(struct string_st *private, const struct string_st *str) {
    struct ecc_curve *curve = ecc_curve_new();
    struct ecc_key *key = ecc_key_new();

    ecc_curve_secp256k1(curve);
    ecc_key_generate(key, str, curve);

    ecc_key_get_str(key, private);

    ecc_key_free(key);
    ecc_curve_free(curve);
}
void secp256k1_generate(struct string_st *private) {
    struct ecc_curve *curve = ecc_curve_new();
    struct ecc_key *key = ecc_key_new();

    ecc_curve_secp256k1(curve);
    ecc_key_generate_f(key, curve);

    ecc_key_get_str(key, private);

    ecc_key_free(key);
    ecc_curve_free(curve);
}


void secp256k1_create_sign(struct string_st *sign, const struct string_st *private, const struct string_st *hash) {
    struct ecc_curve *curve = ecc_curve_new();
    struct ecc_sign *signature = ecc_sign_new();
    struct ecc_key *key = ecc_key_new();

    ecc_curve_secp256k1(curve);
    ecc_key_set_str(key, private, curve);
    ecc_sign_create(signature, key, hash, curve);

    ecc_sign_get_str(signature, sign);

    ecc_key_free(key);
    ecc_sign_free(signature);
    ecc_curve_free(curve);
}
int secp256k1_check_sign(const struct string_st *sign, const struct string_st *public, const struct string_st *hash) {
    struct ecc_curve *curve = ecc_curve_new();
    struct ecc_sign *signature = ecc_sign_new();
    struct ecc_key *key = ecc_key_new();

    ecc_curve_secp256k1(curve);
    ecc_key_set_str(key, public, curve);
    ecc_sign_set_str(signature, sign);

    int res = ecc_sign_check(signature, key, hash, curve);

    ecc_key_free(key);
    ecc_sign_free(signature);
    ecc_curve_free(curve);
    return res;
}


struct crypto_base secp256k1 = {
        &secp256k1_encode,
        &secp256k1_decode,
        &secp256k1_encode_self,
        &secp256k1_decode_self,

        &secp256k1_get_public,
        &secp256k1_from_string,
        &secp256k1_generate,

        &secp256k1_create_sign,
        &secp256k1_check_sign
};