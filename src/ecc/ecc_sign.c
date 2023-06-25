#include "ecc.h"

void ecc_sign_data_init(struct ecc_sign *res) {
    integer_data_init(&res->r);
    integer_data_init(&res->s);
}
void ecc_sign_data_free(struct ecc_sign *res) {
    integer_data_free(&res->r);
    integer_data_free(&res->s);
}

void ecc_sign_clear(struct ecc_sign *res) {
    integer_clear(&res->r);
    integer_clear(&res->s);
}

int ecc_sign_set_str(struct ecc_sign *res, const struct string_st *tlv) {
    if (res == NULL) return ERR_DATA_NULL;
    ecc_sign_clear(res);
    int result = tlv_get_tag(tlv);
    if (result < 0) return result;
    if (result != ECC_SIGN_TLV) return ERR_TLV_TAG;

    struct string_st _tlv, _tlv_data;
    string_data_init(&_tlv_data);
    string_data_init(&_tlv);
    if ((result = tlv_get_value(tlv, &_tlv))) goto end;

    if ((result = tlv_get_next_tlv(&_tlv, &_tlv_data))) goto end;
    if ((result = integer_set_tlv(&res->r, &_tlv_data))) goto end;

    if ((result = tlv_get_next_tlv(&_tlv, &_tlv_data))) goto end;
    if ((result = integer_set_tlv(&res->s, &_tlv_data))) goto end;
    end:
    string_data_free(&_tlv);
    string_data_free(&_tlv_data);
    return result;
}
void ecc_sign_get_str(const struct ecc_sign *sign, struct string_st *res) {
    if (res == NULL) return;
    if (sign == NULL) return string_clear(res);

    struct string_st _tlv_data;
    string_data_init(&_tlv_data);
    integer_get_tlv(&sign->r, res);

    integer_get_tlv(&sign->s, &_tlv_data);
    string_concat(res, &_tlv_data);

    tlv_set_string(res, ECC_SIGN_TLV, res);
    string_data_free(&_tlv_data);
}

void ecc_sign_create(struct ecc_sign *res, const struct ecc_key *key, const struct string_st *hash, const struct ecc_curve *curve) {
    if (!key->priv) return;

    struct integer_st hash_int;
    struct integer_st temp;
    struct integer_st k;
    struct ecc_point R;

    integer_data_init(&hash_int);
    integer_data_init(&temp);
    integer_data_init(&k);
    ecc_point_data_init(&R);

    integer_set_str(&hash_int, hash);
    do {
        do {
            integer_random(&k, &curve->n);
        } while (integer_is_null(&k) || integer_cmp(&key->d, &k) == 0);
        ecc_point_mul(&R, &curve->g, &k, curve);

        integer_inv(&res->s, &k, &curve->n);
        integer_mul(&temp, &R.x, &key->d);
        integer_add(&temp, &temp, &hash_int);
        integer_mul(&res->s, &res->s, &temp);
        integer_mod(&res->s, &res->s, &curve->n);

    } while (integer_is_null(&res->s));

    integer_set(&res->r, &R.x);

    ecc_point_data_free(&R);
    integer_data_free(&k);
    integer_data_free(&temp);
    integer_data_free(&hash_int);
}
int ecc_sign_check(const struct ecc_sign *res, const struct ecc_key *key, const struct string_st *hash, const struct ecc_curve *curve) {
    struct integer_st hash_int;
    struct integer_st s1;
    struct ecc_point _point1;
    struct ecc_point _point2;

    integer_data_init(&hash_int);
    integer_data_init(&s1);
    ecc_point_data_init(&_point1);
    ecc_point_data_init(&_point2);

    integer_set_str(&hash_int, hash);


    integer_inv(&s1, &res->s, &curve->n);
    integer_mul(&hash_int, &hash_int, &s1);
    ecc_point_mul(&_point1, &curve->g, &hash_int, curve);

    integer_mul(&hash_int, &res->r, &s1);
    ecc_point_mul(&_point2, &key->p, &hash_int, curve);

    ecc_point_add(&_point1, &_point1, &_point2, curve);

    int result = ERR_SUCCESS;
    if (integer_cmp(&_point1.x, &res->r)) result = ERR_DATA_CHECK;

    ecc_point_data_free(&_point1);
    ecc_point_data_free(&_point2);
    integer_data_free(&s1);
    integer_data_free(&hash_int);
    return result;
}