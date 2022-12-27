#include "crypto_base.h"

struct crypto_base get_crypto_base(unsigned code) {
    switch (code) {
        case BASE_SECP256K1:
            return secp256k1;
    }
    exit(0);
}