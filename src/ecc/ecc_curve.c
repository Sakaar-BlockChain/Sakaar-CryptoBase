#include "ecc.h"

struct ecc_curve *ecc_curve_new() {
    struct ecc_curve *res = skr_malloc(ECC_CURVE_SIZE);
    res->g = ecc_point_new();
    res->h = integer_new();
    res->a = integer_new();
    res->b = integer_new();
    res->n = integer_new();
    res->p = integer_new();
    return res;
}
void ecc_curve_free(struct ecc_curve *res) {
    ecc_point_free(res->g);
    integer_free(res->h);
    integer_free(res->a);
    integer_free(res->b);
    integer_free(res->n);
    integer_free(res->p);
    skr_free(res);
}

void ecc_curve_secp256k1(struct ecc_curve *res) {
    if (res == NULL) return;
    integer_set_ui(res->h, 1);
    integer_set_ui(res->a, 0);
    integer_set_ui(res->b, 7);
    _integer_set_str(res->p, "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F\0", 64);
    _integer_set_str(res->n, "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141\0", 64);
    _integer_set_str(res->g->x, "79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798\0", 64);
    _integer_set_str(res->g->y, "483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8\0", 64);
}