#ifndef ECC_SIGN_H
#define ECC_SIGN_H

#include "struct.h"
#include "ecc_key.h"

struct ecc_sign {
    struct integer_st r;
    struct integer_st s;
};

void ecc_sign_data_init(struct ecc_sign *);
void ecc_sign_data_free(struct ecc_sign *);

void ecc_sign_clear(struct ecc_sign *);

int8_t ecc_sign_set_str(struct ecc_sign *, const struct string_st *);
void ecc_sign_get_str(const struct ecc_sign *, struct string_st *);

void ecc_sign_create(struct ecc_sign *, const struct ecc_key *, const struct string_st *, const struct ecc_curve *);
int8_t ecc_sign_check(const struct ecc_sign *, const struct ecc_key *, const struct string_st *, const struct ecc_curve *);

#endif //ECC_SIGN_H