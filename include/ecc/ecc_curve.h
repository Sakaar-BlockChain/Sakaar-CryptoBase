#ifndef ECC_CURVE_H
#define ECC_CURVE_H

#include "struct.h"
#include "ecc_point.h"

struct ecc_curve {
    struct ecc_point g;
    struct integer_st h;
    struct integer_st a;
    struct integer_st b;
    struct integer_st n;
    struct integer_st p;
};

void ecc_curve_data_init(struct ecc_curve *);
void ecc_curve_data_free(struct ecc_curve *);

void ecc_curve_secp112r1(struct ecc_curve *);
void ecc_curve_secp112r2(struct ecc_curve *);
void ecc_curve_secp128r1(struct ecc_curve *);
void ecc_curve_secp128r2(struct ecc_curve *);
void ecc_curve_secp160k1(struct ecc_curve *);
void ecc_curve_secp160r1(struct ecc_curve *);
void ecc_curve_secp160r2(struct ecc_curve *);
void ecc_curve_secp192k1(struct ecc_curve *);
void ecc_curve_secp192r1(struct ecc_curve *);
void ecc_curve_secp224k1(struct ecc_curve *);
void ecc_curve_secp224r1(struct ecc_curve *);
void ecc_curve_secp256k1(struct ecc_curve *);
void ecc_curve_secp256r1(struct ecc_curve *);
void ecc_curve_secp384r1(struct ecc_curve *);
void ecc_curve_secp521r1(struct ecc_curve *);


#endif //ECC_CURVE_H