#include "crypto_base.h"
#include "ecc.h"

int secp224k1_encode(const struct string_st *public, const struct string_st *private, const struct string_st *str, unsigned hash_type, unsigned crypto_type, struct string_st *res) {
    struct ecc_key private_key;
    struct ecc_key public_key;
    struct ecc_curve curve;
    struct string_st hash;
    int result;

    ecc_key_data_init(&private_key);
    ecc_key_data_init(&public_key);
    ecc_curve_data_init(&curve);
    string_data_init(&hash);

    ecc_curve_secp224k1(&curve);
    if((result = ecc_key_set_str(&public_key, public, &curve))) goto end;
    if((result = ecc_key_set_str(&private_key, private, &curve))) goto end;

    ecc_key_get_key(&public_key, &private_key, &curve, &hash);
    get_hash_code(hash_type)._code(&hash, &hash);
    get_crypto_code(crypto_type)._encode(res, str, &hash);
    end:
    string_data_free(&hash);
    ecc_curve_data_free(&curve);
    ecc_key_data_free(&public_key);
    ecc_key_data_free(&private_key);
    return result;
}
int secp224k1_decode(const struct string_st *public, const struct string_st *private, const struct string_st *str, unsigned hash_type, unsigned crypto_type, struct string_st *res) {
    struct ecc_key private_key;
    struct ecc_key public_key;
    struct ecc_curve curve;
    struct string_st hash;
    int result;

    ecc_key_data_init(&private_key);
    ecc_key_data_init(&public_key);
    ecc_curve_data_init(&curve);
    string_data_init(&hash);

    ecc_curve_secp224k1(&curve);
    if((result = ecc_key_set_str(&public_key, public, &curve))) goto end;
    if((result = ecc_key_set_str(&private_key, private, &curve))) goto end;

    ecc_key_get_key(&public_key, &private_key, &curve, &hash);
    get_hash_code(hash_type)._code(&hash, &hash);
    get_crypto_code(crypto_type)._decode(res, str, &hash);
    end:
    string_data_free(&hash);
    ecc_curve_data_free(&curve);
    ecc_key_data_free(&public_key);
    ecc_key_data_free(&private_key);
    return result;
}
int secp224k1_encode_self(const struct string_st *private, const struct string_st *str, unsigned hash_type, unsigned crypto_type, struct string_st *res) {
    struct ecc_curve curve;
    struct string_st hash;
    struct ecc_key key;
    int result;

    ecc_curve_data_init(&curve);
    string_data_init(&hash);
    ecc_key_data_init(&key);

    ecc_curve_secp224k1(&curve);
    if((result = ecc_key_set_str(&key, private, &curve))) goto end;

    ecc_key_get_key_self(&key, &curve, &hash);
    get_hash_code(hash_type)._code(&hash, &hash);
    get_crypto_code(crypto_type)._encode(res, str, &hash);
    end:
    ecc_key_data_free(&key);
    string_data_free(&hash);
    ecc_curve_data_free(&curve);
    return result;
}
int secp224k1_decode_self(const struct string_st *private, const struct string_st *str, unsigned hash_type, unsigned crypto_type, struct string_st *res) {
    struct ecc_curve curve;
    struct string_st hash;
    struct ecc_key key;
    int result;

    ecc_curve_data_init(&curve);
    string_data_init(&hash);
    ecc_key_data_init(&key);

    ecc_curve_secp224k1(&curve);
    if((result = ecc_key_set_str(&key, private, &curve))) goto end;

    ecc_key_get_key_self(&key, &curve, &hash);
    get_hash_code(hash_type)._code(&hash, &hash);
    get_crypto_code(crypto_type)._decode(res, str, &hash);
    end:
    ecc_key_data_free(&key);
    string_data_free(&hash);
    ecc_curve_data_free(&curve);
    return result;
}


int secp224k1_get_public(const struct string_st *private, struct string_st *public) {
    struct ecc_curve curve;
    struct ecc_key key;
    int result;

    ecc_curve_data_init(&curve);
    ecc_key_data_init(&key);

    ecc_curve_secp224k1(&curve);
    if((result = ecc_key_set_str(&key, private, &curve))) goto end;

    ecc_key_get_address(&key, public);
    end:
    ecc_key_data_free(&key);
    ecc_curve_data_free(&curve);
    return result;
}
void secp224k1_from_string(struct string_st *private, const struct string_st *str) {
    struct ecc_curve curve;
    struct ecc_key key;

    ecc_curve_data_init(&curve);
    ecc_key_data_init(&key);

    ecc_curve_secp224k1(&curve);
    ecc_key_generate(&key, str, &curve);

    ecc_key_get_str(&key, private);

    ecc_key_data_free(&key);
    ecc_curve_data_free(&curve);
}
void secp224k1_generate(struct string_st *private) {
    struct ecc_curve curve;
    struct ecc_key key;

    ecc_curve_data_init(&curve);
    ecc_key_data_init(&key);

    ecc_curve_secp224k1(&curve);
    ecc_key_generate_f(&key, &curve);

    ecc_key_get_str(&key, private);

    ecc_key_data_free(&key);
    ecc_curve_data_free(&curve);
}


int secp224k1_create_sign(struct string_st *sign, const struct string_st *private, const struct string_st *hash) {
    struct ecc_sign signature;
    struct ecc_curve curve;
    struct ecc_key key;
    int result;

    ecc_sign_data_init(&signature);
    ecc_curve_data_init(&curve);
    ecc_key_data_init(&key);

    ecc_curve_secp224k1(&curve);
    if((result = ecc_key_set_str(&key, private, &curve))) goto end;
    ecc_sign_create(&signature, &key, hash, &curve);

    ecc_sign_get_str(&signature, sign);
    end:
    ecc_key_data_free(&key);
    ecc_curve_data_free(&curve);
    ecc_sign_data_free(&signature);
    return result;
}
int secp224k1_check_sign(const struct string_st *sign, const struct string_st *public, const struct string_st *hash) {
    struct ecc_sign signature;
    struct ecc_curve curve;
    struct ecc_key key;
    int result;

    ecc_sign_data_init(&signature);
    ecc_curve_data_init(&curve);
    ecc_key_data_init(&key);

    ecc_curve_secp224k1(&curve);
    if((result = ecc_key_set_str(&key, public, &curve))) goto end;
    if((result = ecc_sign_set_str(&signature, sign))) goto end;

    result = ecc_sign_check(&signature, &key, hash, &curve);
    end:
    ecc_key_data_free(&key);
    ecc_curve_data_free(&curve);
    ecc_sign_data_free(&signature);
    return result;
}


struct crypto_base secp224k1 = {
        &secp224k1_encode,
        &secp224k1_decode,
        &secp224k1_encode_self,
        &secp224k1_decode_self,

        &secp224k1_get_public,
        &secp224k1_from_string,
        &secp224k1_generate,

        &secp224k1_create_sign,
        &secp224k1_check_sign
};