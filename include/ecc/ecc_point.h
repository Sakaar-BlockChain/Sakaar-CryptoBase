#ifndef ECC_POINT_H
#define ECC_POINT_H

#include "struct.h"


struct ecc_curve;
struct ecc_point {
    struct integer_st x;
    struct integer_st y;
};

void ecc_point_data_init(struct ecc_point *);
void ecc_point_data_free(struct ecc_point *);

void ecc_point_set(struct ecc_point *, const struct ecc_point *);
void ecc_point_clear(struct ecc_point *);

int8_t ecc_point_set_str(struct ecc_point *, const struct string_st *tlv, const struct ecc_curve *curve);
void ecc_point_get_str(const struct ecc_point *P, struct string_st *);

void ecc_point_double(struct ecc_point *, const struct ecc_point *P, const struct ecc_curve *curve);
void ecc_point_add(struct ecc_point *, const struct ecc_point *P, const struct ecc_point *Q, const struct ecc_curve *curve);
void ecc_point_mul(struct ecc_point *, const struct ecc_point *P, const struct integer_st *M, const struct ecc_curve *curve);


#endif //ECC_POINT_H