#include "ecc.h"

struct ecc_sign *ecc_sign_new() {
    struct ecc_sign *res = skr_malloc(ECC_SIGN_SIZE);
    integer_data_init(&res->r);
    integer_data_init(&res->s);
    return res;
}
void ecc_sign_clear(struct ecc_sign *res) {
    integer_clear(&res->r);
    integer_clear(&res->s);
}
void ecc_sign_free(struct ecc_sign *res) {
    integer_data_free(&res->r);
    integer_data_free(&res->s);
    skr_free(res);
}

int ecc_sign_set_str(struct ecc_sign *res, const struct string_st *tlv) {
    if (res == NULL) return 0;
    ecc_sign_clear(res);
    int result = tlv_get_tag(tlv);
    if (result < 0) return result;
    if (result != ECC_SIGN_TLV) return ERR_TLV_TAG;

    struct string_st _tlv = {NULL, 0, 0}, _tlv_data  = {NULL, 0, 0};
    if ((result = tlv_get_value(tlv, &_tlv)) != 0) goto end;

    if ((result = tlv_get_next_tlv(&_tlv, &_tlv_data)) != 0) goto end;
    if ((result = integer_set_tlv(&res->r, &_tlv_data)) != 0) goto end;

    if ((result = tlv_get_next_tlv(&_tlv, &_tlv_data)) != 0) goto end;
    if ((result = integer_set_tlv(&res->s, &_tlv_data)) != 0) goto end;
    end:
    string_data_free(&_tlv);
    string_data_free(&_tlv_data);
    return result;
}
void ecc_sign_get_str(const struct ecc_sign *sign, struct string_st *res) {
    if (res == NULL) return;
    if (sign == NULL) return string_clear(res);

    struct string_st _tlv_data = {NULL, 0, 0};
    integer_get_tlv(&sign->r, res);

    integer_get_tlv(&sign->s, &_tlv_data);
    string_concat(res, &_tlv_data);

    tlv_set_string(res, ECC_SIGN_TLV, res);
    string_data_free(&_tlv_data);
}

void ecc_sign_create(struct ecc_sign *res, const struct ecc_key *key, const struct string_st *hash, const struct ecc_curve *curve) {
    if (!key->priv) return;

    struct integer_st *k = integer_new();
    struct integer_st *temp = integer_new();
    struct integer_st *hash_int = integer_new();

    integer_set_str(hash_int, hash);
    struct ecc_point *R = ecc_point_new();
    do {
        do {
            integer_random(k, &curve->n);
        } while (integer_is_null(k) || integer_cmp(&key->d, k) == 0);
        ecc_point_mul(R, curve->g, k, curve);

        integer_inv(&res->s, k, &curve->n);
        integer_mul(temp, &R->x, &key->d);
        integer_add(temp, temp, hash_int);
        integer_mul(&res->s, &res->s, temp);
        integer_mod(&res->s, &res->s, &curve->n);

    } while (integer_is_null(&res->s));

    integer_set(&res->r, &R->x);

    integer_free(hash_int);
    integer_free(temp);
    integer_free(k);
    ecc_point_free(R);
}
int ecc_sign_check(const struct ecc_sign *res, const struct ecc_key *key, const struct string_st *hash, const struct ecc_curve *curve) {
    struct integer_st *s1 = integer_new();
    struct integer_st *hash_int = integer_new();

    integer_set_str(hash_int, hash);
    struct ecc_point *_point1 = ecc_point_new();
    struct ecc_point *_point2 = ecc_point_new();


    integer_inv(s1, &res->s, &curve->n);
    integer_mul(hash_int, hash_int, s1);
    ecc_point_mul(_point1, curve->g, hash_int, curve);

    integer_mul(hash_int, &res->r, s1);
    ecc_point_mul(_point2, key->p, hash_int, curve);

    ecc_point_add(_point1, _point1, _point2, curve);

    int result = (integer_cmp(&_point1->x, &res->r) == 0);

    integer_free(hash_int);
    integer_free(s1);

    ecc_point_free(_point1);
    ecc_point_free(_point2);
    return result;
}