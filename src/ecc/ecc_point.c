#include "ecc.h"

void ecc_point_data_init(struct ecc_point *res) {
    integer_data_init(&res->x);
    integer_data_init(&res->y);
}
void ecc_point_data_free(struct ecc_point *res) {
    integer_data_free(&res->x);
    integer_data_free(&res->y);
}

void ecc_point_set(struct ecc_point *res, const struct ecc_point *a) {
    if (a == NULL) return;
    integer_set(&res->x, &a->x);
    integer_set(&res->y, &a->y);
}
void ecc_point_clear(struct ecc_point *res) {
    integer_clear(&res->x);
    integer_clear(&res->y);
}

int8_t ecc_point_set_str(struct ecc_point *res, const struct string_st *str, const struct ecc_curve *curve) {
    if (res == NULL) return ERR_DATA_NULL;
    ecc_point_clear(res);
    if (curve == NULL || string_is_null(str)) return ERR_DATA_NULL;
    int32_t tag = tlv_get_tag(str);
    if (tag < 0) return (int8_t) tag;
    if ((tag | 1) != (TLV_ECC_POINT | 1)) return ERR_TLV_TAG;

    int8_t result = integer_set_tlv_(&res->x, str);
    if (result < 0) return result;

    struct integer_st temp;

    integer_data_init(&temp);

    // y = (x^3 + ax + b) % p
    integer_set_ui(&temp, 3);
    integer_powm(&res->y, &res->x, &temp, &curve->p);
    integer_add(&res->y, &res->y, &curve->b);
    integer_mul(&temp, &res->x, &curve->a);
    integer_add(&res->y, &res->y, &temp);
    integer_mod(&res->y, &res->y, &curve->p);


    // y = y ^ ((p+1)//4) % p
    integer_set_ui(&temp, 1);
    integer_add(&temp, &curve->p, &temp);
    integer_rs(&temp, &temp, 2);
    integer_powm(&res->y, &res->y, &temp, &curve->p);
    if ((tag - ECC_POINT_TLV) != integer_get_ui(&res->y) % 2) integer_sub(&res->y, &curve->p, &res->y);

    integer_data_free(&temp);
    return ERR_SUCCESS;
}
void ecc_point_get_str(const struct ecc_point *P, struct string_st *res) {
    if (res == NULL) return;
    if (P == NULL) return string_clear(res);
    integer_get_tlv_(&P->x, res, integer_get_ui(&P->y) % 2 + ECC_POINT_TLV);
}

void ecc_point_double(struct ecc_point *res, const struct ecc_point *P, const struct ecc_curve *curve) {
    if (integer_is_null(&P->y)) return ecc_point_clear(res);
    struct integer_st slope;
    struct integer_st temp;

    integer_data_init(&slope);
    integer_data_init(&temp);

    // slope = (P.x^2 * 3 + a) / (2 * P.y)
    integer_mul(&slope, &P->x, &P->x);
    integer_set_ui(&temp, 3);
    integer_mul(&slope, &slope, &temp);
    integer_add(&slope, &slope, &curve->a);
    integer_set_ui(&temp, 2);
    integer_mul(&temp, &P->y, &temp);
    integer_inv(&temp, &temp, &curve->p);
    integer_mul(&slope, &slope, &temp);
    integer_mod(&slope, &slope, &curve->p);

    // x = slope^2 - 2*x
    integer_set(&temp, &P->x);
    integer_mul(&res->x, &slope, &slope);
    integer_sub(&res->x, &res->x, &temp);
    integer_sub(&res->x, &res->x, &temp);

    // x = slope^2 - 2*x
    integer_sub(&temp, &temp, &res->x);
    integer_mul(&temp, &temp, &slope);
    integer_sub(&res->y, &temp, &P->y);

    integer_mod(&res->x, &res->x, &curve->p);
    integer_mod(&res->y, &res->y, &curve->p);

    integer_data_free(&temp);
    integer_data_free(&slope);
}
void ecc_point_add(struct ecc_point *res, const struct ecc_point *P, const struct ecc_point *Q, const struct ecc_curve *curve) {
    if (integer_is_null(&P->x) && integer_is_null(&P->y)) return ecc_point_set(res, Q);
    if (integer_is_null(&Q->x) && integer_is_null(&Q->y)) return ecc_point_set(res, P);
    if (integer_cmp(&P->x, &Q->x) == 0) return ecc_point_double(res, P, curve);

    struct integer_st slope;
    struct integer_st temp1;
    struct integer_st temp;

    integer_data_init(&slope);
    integer_data_init(&temp1);
    integer_data_init(&temp);

    integer_sub(&temp, &P->x, &Q->x);
    integer_mod(&temp, &temp, &curve->p);
    integer_inv(&temp, &temp, &curve->p);
    integer_sub(&slope, &P->y, &Q->y);
    integer_mul(&slope, &slope, &temp);
    integer_mod(&slope, &slope, &curve->p);


    // x = slope^2 - X1 - X2
    integer_mul(&temp, &slope, &slope);
    integer_sub(&temp, &temp, &P->x);
    integer_sub(&temp, &temp, &Q->x);

    // x = slope * (X1 - X2) -
    integer_sub(&temp1, &P->x, &temp);
    integer_mul(&temp1, &temp1, &slope);
    integer_sub(&temp1, &temp1, &P->y);

    integer_mod(&res->x, &temp, &curve->p);
    integer_mod(&res->y, &temp1, &curve->p);

    integer_data_free(&temp);
    integer_data_free(&temp1);
    integer_data_free(&slope);
}
void ecc_point_mul(struct ecc_point *res, const struct ecc_point *P, const struct integer_st *M, const struct ecc_curve *curve) {
    if (integer_is_null(&P->y)) return ecc_point_clear(res);
    struct ecc_point Res;
    struct ecc_point Q;
    struct string_st str;

    ecc_point_data_init(&Res);
    ecc_point_data_init(&Q);
    string_data_init(&str);

    ecc_point_set(&Q, P);
    integer_get_str(M, &str);
    size_t size = str.size * 4;
    size_t _size = size;
    for (size_t i = size; i > 0; i--)
        if (set_char_16(str.data[(i - 1) / 4]) & (1 << ((4 - i) % 4))) _size = i;
    for (size_t i = size; i >= _size; i--) {
        if (set_char_16(str.data[(i - 1) / 4]) & (1 << ((4 - i) % 4)))
            ecc_point_add(&Res, &Res, &Q, curve);
        ecc_point_double(&Q, &Q, curve);
    }
    ecc_point_set(res, &Res);

    string_data_free(&str);
    ecc_point_data_free(&Q);
    ecc_point_data_free(&Res);
}

