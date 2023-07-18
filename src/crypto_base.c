#include <stdio.h>
#include "crypto_base.h"

struct crypto_base get_crypto_base(unsigned code) {
    if ((code & BASE_ECC) == BASE_ECC) {
        if ((code & BASE_SECP) == BASE_SECP) {
            switch (code) {
                case BASE_SECP112R1:
                    return secp112r1;
                case BASE_SECP112R2:
                    return secp112r2;
                case BASE_SECP128R1:
                    return secp128r1;
                case BASE_SECP128R2:
                    return secp128r2;
                case BASE_SECP160K1:
                    return secp160k1;
                case BASE_SECP160R1:
                    return secp160r1;
                case BASE_SECP160R2:
                    return secp160r2;
                case BASE_SECP192K1:
                    return secp192k1;
                case BASE_SECP192R1:
                    return secp192r1;
                case BASE_SECP224K1:
                    return secp224k1;
                case BASE_SECP224R1:
                    return secp224r1;
                case BASE_SECP256K1:
                    return secp256k1;
                case BASE_SECP256R1:
                    return secp256r1;
                case BASE_SECP384R1:
                    return secp384r1;
                case BASE_SECP521R1:
                    return secp521r1;
                default:
                    break;
            }
        }
    }
    fprintf(stderr, "Not recognized Crypto Base : %d\n", code);
    exit(0);
}