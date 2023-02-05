#ifndef ECC_CURVE_H
#define ECC_CURVE_H

#include "struct.h"
#include "ecc_point.h"

struct ecc_curve {
    struct ecc_point *g;
    struct integer_st *h;
    struct integer_st *a;
    struct integer_st *b;
    struct integer_st *n;
    struct integer_st *p;
};

struct ecc_curve *ecc_curve_new();
void ecc_curve_free(struct ecc_curve *);

void ecc_curve_secp256k1(struct ecc_curve *);


#endif //ECC_CURVE_H