#include <time.h>
#include "ecc.h"
#include "hash_code.h"

void ecc_key_data_init(struct ecc_key *res) {
    ecc_point_data_init(&res->p);
    integer_data_init(&res->d);
    res->priv = 0;
}
void ecc_key_data_free(struct ecc_key *res) {
    if (res == NULL) return;
    ecc_point_data_free(&res->p);
    integer_data_free(&res->d);
}

void ecc_key_clear(struct ecc_key *res) {
    if (res == NULL) return;
    ecc_point_clear(&res->p);
    integer_clear(&res->d);
    res->priv = 0;
}

int ecc_key_set_str(struct ecc_key *res, const struct string_st *str, const struct ecc_curve *curve) {
    if (res == NULL) return ERR_DATA_NULL;
    ecc_key_clear(res);
    if (string_is_null(str) || curve == NULL) return ERR_DATA_NULL;
    unsigned _tag = tlv_get_tag(str);

    int result = ERR_TLV_TAG;
    if (_tag == ECC_KEY_TLV) {
        res->priv = 1;
        if ((result = integer_set_tlv_(&res->d, str))) return result;
        ecc_point_mul(&res->p, &curve->g, &res->d, curve);
    } else if (_tag == ECC_POINT_TLV || _tag == ECC_POINT_TLV + 1) {
        res->priv = 0;
        if ((result = ecc_point_set_str(&res->p, str, curve))) return result;
    }
    return result;
}
void ecc_key_get_str(const struct ecc_key *res, struct string_st *str) {
    if (str == NULL) return;
    if (res == NULL) return string_clear(str);
    if (!res->priv) return ecc_point_get_str(&res->p, str);
    integer_get_tlv_(&res->d, str, ECC_KEY_TLV);
}
void ecc_key_get_address(const struct ecc_key *res, struct string_st *tlv) {
    if (res == NULL || tlv == NULL) return;
    return ecc_point_get_str(&res->p, tlv);
}

void ecc_key_get_key_self(const struct ecc_key *key, const struct ecc_curve *curve, struct string_st *res) {
    if (res == NULL) return;
    if (curve == NULL || key == NULL || !key->priv) return string_clear(res);
    struct ecc_point point;

    ecc_point_data_init(&point);

    ecc_point_mul(&point, &key->p, &key->d, curve);
    ecc_point_get_str(&point, res);

    ecc_point_data_free(&point);
}
void ecc_key_get_key(const struct ecc_key *key1, const struct ecc_key *key2, const struct ecc_curve *curve, struct string_st *res) {
    if (res == NULL) return;
    if (curve == NULL || key1 == NULL || key2 == NULL || !key2->priv) return string_clear(res);
    struct ecc_point point;

    ecc_point_data_init(&point);

    ecc_point_mul(&point, &key1->p, &key2->d, curve);
    ecc_point_get_str(&point, res);

    ecc_point_data_free(&point);
}

void ecc_key_generate(struct ecc_key *res, const struct string_st *str, const struct ecc_curve *curve) {
    res->priv = 1;

    struct string_st master_key;
    struct integer_st counter;
    struct string_st priv_key;
    struct string_st temp_str;
    struct integer_st one;
    struct string_st y;

    string_data_init(&master_key);
    integer_data_init(&counter);
    string_data_init(&priv_key);
    string_data_init(&temp_str);
    integer_data_init(&one);
    string_data_init(&y);

    integer_clear(&counter);
    integer_set_ui(&one, 1);

    { // master_key = sha256(sha256(str) + str)
        sha256_code._code(&master_key, str);
        string_concat(&master_key, str);
        sha256_code._code(&master_key, &master_key);
    }
    {
        integer_get_str(&curve->n, &priv_key);
        size_t pos, size;

        do {
            do {
                integer_add(&counter, &counter, &one);
                integer_get_str(&counter, &temp_str);
                string_set(&y, &master_key);

                pos = 0;
                size = priv_key.size;
                for (size_t i = 0; i < size; i++) priv_key.data[i] = 0;
                while (pos < size) {
                    string_concat(&y, &temp_str);
                    sha256_code._code(&y, &y);
                    for (unsigned j = 0; j < y.size && pos < size; j++, pos++)
                        priv_key.data[pos] = y.data[j];
                }
                integer_set_str(&res->d, &priv_key);
            } while (integer_is_null(&res->d) || integer_cmp(&res->d, &curve->n) == 0);
            integer_mod(&res->d, &res->d, &curve->n);

            ecc_point_mul(&res->p, &curve->g, &res->d, curve);
        } while (integer_is_null(&res->p.x));
    }


    string_data_free(&y);
    integer_data_free(&one);
    string_data_free(&temp_str);
    string_data_free(&priv_key);
    integer_data_free(&counter);
    string_data_free(&master_key);
}
void ecc_key_generate_f(struct ecc_key *res, const struct ecc_curve *curve) {
    res->priv = 1;
    {
        while (1) {
            integer_random(&res->d, &curve->n);
            integer_mod(&res->d, &res->d, &curve->n);
            ecc_point_mul(&res->p, &curve->g, &res->d, curve);
            if (!integer_is_null(&res->p.x) && !integer_is_null(&res->d)) break;
        }
    }
}
