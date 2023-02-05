#ifndef ECC_KEY_H
#define ECC_KEY_H

#include "struct.h"
#include "ecc_curve.h"


struct ecc_key {
    struct ecc_point *p;
    struct integer_st *d;
    int priv;
};

struct ecc_key *ecc_key_new();
void ecc_key_clear(struct ecc_key *);
void ecc_key_free(struct ecc_key *);

void ecc_key_set_str(struct ecc_key *, const struct string_st *, const struct ecc_curve *);
void ecc_key_get_str(const struct ecc_key *, struct string_st *);
void ecc_key_get_address(const struct ecc_key *, struct string_st *);

void ecc_key_get_key_self(const struct ecc_key *, const struct ecc_curve *, struct string_st *key);
void ecc_key_get_key(const struct ecc_key *, const struct ecc_key *, const struct ecc_curve *, struct string_st *key);

void ecc_key_generate(struct ecc_key *, const struct string_st *, const struct ecc_curve *);
void ecc_key_generate_f(struct ecc_key *, const struct ecc_curve *);

#endif //ECC_KEY_H