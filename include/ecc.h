#ifndef ECC_H
#define ECC_H

#include "struct.h"

#include "ecc/ecc_point.h"
#include "ecc/ecc_curve.h"
#include "ecc/ecc_sign.h"
#include "ecc/ecc_key.h"


#define TLV_ECC_POINT   0xC2
#define TLV_ECC_SIGN    0xF4
#define TLV_ECC_KEY     0xC4


#define ECC_POINT_SIZE  sizeof(struct ecc_point)
#define ECC_CURVE_SIZE  sizeof(struct ecc_curve)
#define ECC_SIGN_SIZE   sizeof(struct ecc_sign)
#define ECC_KEY_SIZE    sizeof(struct ecc_key)

#endif //ECC_H