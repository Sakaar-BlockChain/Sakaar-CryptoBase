#include "ecc.h"

struct ecc_curve *ecc_curve_new() {
    struct ecc_curve *res = skr_malloc(ECC_CURVE_SIZE);
    res->g = ecc_point_new();
    integer_data_init(&res->h);
    integer_data_init(&res->a);
    integer_data_init(&res->b);
    integer_data_init(&res->n);
    integer_data_init(&res->p);
    return res;
}
void ecc_curve_free(struct ecc_curve *res) {
    ecc_point_free(res->g);
    integer_data_free(&res->h);
    integer_data_free(&res->a);
    integer_data_free(&res->b);
    integer_data_free(&res->n);
    integer_data_free(&res->p);
    skr_free(res);
}

void ecc_curve_secp112r1(struct ecc_curve *res) {
    if (res == NULL) return;
    integer_set_ui(&res->h, 1);
    integer_set_str_(&res->a, "db7c2abf62e35e668076bead2088\0", 28);
    integer_set_str_(&res->b, "659ef8ba043916eede8911702b22\0", 28);
    integer_set_str_(&res->p, "db7c2abf62e35e668076bead208b\0", 28);
    integer_set_str_(&res->n, "db7c2abf62e35e7628dfac6561c5\0", 28);
    integer_set_str_(&res->g->x, "09487239995a5ee76b55f9c2f098\0", 28);
    integer_set_str_(&res->g->y, "a89ce5af8724c0a23e0e0ff77500\0", 28);
}
void ecc_curve_secp112r2(struct ecc_curve *res) {
    if (res == NULL) return;
    integer_set_ui(&res->h, 4);
    integer_set_str_(&res->a, "6127c24c05f38a0aaaf65c0ef02c\0", 28);
    integer_set_str_(&res->b, "51def1815db5ed74fcc34c85d709\0", 28);
    integer_set_str_(&res->p, "db7c2abf62e35e668076bead208b\0", 28);
    integer_set_str_(&res->n, "36df0aafd8b8d7597ca10520d04b\0", 28);
    integer_set_str_(&res->g->x, "4ba30ab5e892b4e1649dd0928643\0", 28);
    integer_set_str_(&res->g->y, "adcd46f5882e3747def36e956e97\0", 28);
}
void ecc_curve_secp128r1(struct ecc_curve *res) {
    if (res == NULL) return;
    integer_set_ui(&res->h, 1);
    integer_set_str_(&res->a, "fffffffdfffffffffffffffffffffffc\0", 32);
    integer_set_str_(&res->b, "e87579c11079f43dd824993c2cee5ed3\0", 32);
    integer_set_str_(&res->p, "fffffffdffffffffffffffffffffffff\0", 32);
    integer_set_str_(&res->n, "fffffffe0000000075a30d1b9038a115\0", 32);
    integer_set_str_(&res->g->x, "161ff7528b899b2d0c28607ca52c5b86\0", 32);
    integer_set_str_(&res->g->y, "cf5ac8395bafeb13c02da292dded7a83\0", 32);
}
void ecc_curve_secp128r2(struct ecc_curve *res) {
    if (res == NULL) return;
    integer_set_ui(&res->h, 4);
    integer_set_str_(&res->a, "d6031998d1b3bbfebf59cc9bbff9aee1\0", 32);
    integer_set_str_(&res->b, "5eeefca380d02919dc2c6558bb6d8a5d\0", 32);
    integer_set_str_(&res->p, "fffffffdffffffffffffffffffffffff\0", 32);
    integer_set_str_(&res->n, "3fffffff7fffffffbe0024720613b5a3\0", 32);
    integer_set_str_(&res->g->x, "7b6aa5d85e572983e6fb32a7cdebc140\0", 32);
    integer_set_str_(&res->g->y, "27b6916a894d3aee7106fe805fc34b44\0", 32);
}
void ecc_curve_secp160k1(struct ecc_curve *res) {
    if (res == NULL) return;
    integer_set_ui(&res->h, 1);
    integer_set_ui(&res->a, 0);
    integer_set_ui(&res->b, 7);
    integer_set_str_(&res->p, "fffffffffffffffffffffffffffffffeffffac73\0", 40);
    integer_set_str_(&res->n, "0100000000000000000001b8fa16dfab9aca16b6b3\0", 42);
    integer_set_str_(&res->g->x, "3b4c382ce37aa192a4019e763036f4f5dd4d7ebb\0", 40);
    integer_set_str_(&res->g->y, "938cf935318fdced6bc28286531733c3f03c4fee\0", 40);
}
void ecc_curve_secp160r1(struct ecc_curve *res) {
    if (res == NULL) return;
    integer_set_ui(&res->h, 1);
    integer_set_str_(&res->a, "ffffffffffffffffffffffffffffffff7ffffffc\0", 40);
    integer_set_str_(&res->b, "1c97befc54bd7a8b65acf89f81d4d4adc565fa45\0", 40);
    integer_set_str_(&res->p, "ffffffffffffffffffffffffffffffff7fffffff\0", 40);
    integer_set_str_(&res->n, "0100000000000000000001f4c8f927aed3ca752257\0", 42);
    integer_set_str_(&res->g->x, "4a96b5688ef573284664698968c38bb913cbfc82\0", 40);
    integer_set_str_(&res->g->y, "23a628553168947d59dcc912042351377ac5fb32\0", 40);
}
void ecc_curve_secp160r2(struct ecc_curve *res) {
    if (res == NULL) return;
    integer_set_ui(&res->h, 1);
    integer_set_str_(&res->a, "fffffffffffffffffffffffffffffffeffffac70\0", 40);
    integer_set_str_(&res->b, "b4e134d3fb59eb8bab57274904664d5af50388ba\0", 40);
    integer_set_str_(&res->p, "fffffffffffffffffffffffffffffffeffffac73\0", 40);
    integer_set_str_(&res->n, "0100000000000000000000351ee786a818f3a1a16b\0", 42);
    integer_set_str_(&res->g->x, "52dcb034293a117e1f4ff11b30f7199d3144ce6d\0", 40);
    integer_set_str_(&res->g->y, "feaffef2e331f296e071fa0df9982cfea7d43f2e\0", 40);
}
void ecc_curve_secp192k1(struct ecc_curve *res) {
    if (res == NULL) return;
    integer_set_ui(&res->h, 1);
    integer_set_ui(&res->a, 0);
    integer_set_ui(&res->b, 3);
    integer_set_str_(&res->p, "fffffffffffffffffffffffffffffffffffffffeffffee37\0", 48);
    integer_set_str_(&res->n, "fffffffffffffffffffffffe26f2fc170f69466a74defd8d\0", 48);
    integer_set_str_(&res->g->x, "db4ff10ec057e9ae26b07d0280b7f4341da5d1b1eae06c7d\0", 48);
    integer_set_str_(&res->g->y, "9b2f2f6d9c5628a7844163d015be86344082aa88d95e2f9d\0", 48);
}
void ecc_curve_secp192r1(struct ecc_curve *res) {
    if (res == NULL) return;
    integer_set_ui(&res->h, 1);
    integer_set_str_(&res->a, "fffffffffffffffffffffffffffffffefffffffffffffffc\0", 48);
    integer_set_str_(&res->b, "64210519e59c80e70fa7e9ab72243049feb8deecc146b9b1\0", 48);
    integer_set_str_(&res->p, "fffffffffffffffffffffffffffffffeffffffffffffffff\0", 48);
    integer_set_str_(&res->n, "ffffffffffffffffffffffff99def836146bc9b1b4d22831\0", 48);
    integer_set_str_(&res->g->x, "188da80eb03090f67cbf20eb43a18800f4ff0afd82ff1012\0", 48);
    integer_set_str_(&res->g->y, "07192b95ffc8da78631011ed6b24cdd573f977a11e794811\0", 48);
}
void ecc_curve_secp224k1(struct ecc_curve *res) {
    if (res == NULL) return;
    integer_set_ui(&res->h, 1);
    integer_set_ui(&res->a, 0);
    integer_set_ui(&res->b, 5);
    integer_set_str_(&res->p, "fffffffffffffffffffffffffffffffffffffffffffffffeffffe56d\0", 56);
    integer_set_str_(&res->n, "10000000000000000000000000001dce8d2ec6184caf0a971769fb1f7\0", 57);
    integer_set_str_(&res->g->x, "a1455b334df099df30fc28a169a467e9e47075a90f7e650eb6b7a45c\0", 56);
    integer_set_str_(&res->g->y, "7e089fed7fba344282cafbd6f7e319f7c0b0bd59e2ca4bdb556d61a5\0", 56);
}
void ecc_curve_secp224r1(struct ecc_curve *res) {
    if (res == NULL) return;
    integer_set_ui(&res->h, 1);
    integer_set_str_(&res->a, "fffffffffffffffffffffffffffffffefffffffffffffffffffffffe\0", 56);
    integer_set_str_(&res->b, "b4050a850c04b3abf54132565044b0b7d7bfd8ba270b39432355ffb4\0", 56);
    integer_set_str_(&res->p, "ffffffffffffffffffffffffffffffff000000000000000000000001\0", 56);
    integer_set_str_(&res->n, "ffffffffffffffffffffffffffff16a2e0b8f03e13dd29455c5c2a3d\0", 56);
    integer_set_str_(&res->g->x, "b70e0cbd6bb4bf7f321390b94a03c1d356c21122343280d6115c1d21\0", 56);
    integer_set_str_(&res->g->y, "bd376388b5f723fb4c22dfe6cd4375a05a07476444d5819985007e34\0", 56);
}
void ecc_curve_secp256k1(struct ecc_curve *res) {
    if (res == NULL) return;
    integer_set_ui(&res->h, 1);
    integer_set_ui(&res->a, 0);
    integer_set_ui(&res->b, 7);
    integer_set_str_(&res->p, "fffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2f\0", 64);
    integer_set_str_(&res->n, "fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141\0", 64);
    integer_set_str_(&res->g->x, "79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798\0", 64);
    integer_set_str_(&res->g->y, "483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8\0", 64);
}
void ecc_curve_secp256r1(struct ecc_curve *res) {
    if (res == NULL) return;
    integer_set_ui(&res->h, 1);
    integer_set_str_(&res->a, "ffffffff00000001000000000000000000000000fffffffffffffffffffffffc\0", 64);
    integer_set_str_(&res->b, "5ac635d8aa3a93e7b3ebbd55769886bc651d06b0cc53b0f63bce3c3e27d2604b\0", 64);
    integer_set_str_(&res->p, "ffffffff00000001000000000000000000000000ffffffffffffffffffffffff\0", 64);
    integer_set_str_(&res->n, "ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551\0", 64);
    integer_set_str_(&res->g->x, "6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296\0", 64);
    integer_set_str_(&res->g->y, "4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5\0", 64);
}
void ecc_curve_secp384r1(struct ecc_curve *res) {
    if (res == NULL) return;
    integer_set_ui(&res->h, 1);
    integer_set_str_(&res->a, "fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffeffffffff0000000000000000fffffffc\0", 96);
    integer_set_str_(&res->b, "b3312fa7e23ee7e4988e056be3f82d19181d9c6efe8141120314088f5013875ac656398d8a2ed19d2a85c8edd3ec2aef\0", 96);
    integer_set_str_(&res->p, "fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffeffffffff0000000000000000ffffffff\0", 96);
    integer_set_str_(&res->n, "ffffffffffffffffffffffffffffffffffffffffffffffffc7634d81f4372ddf581a0db248b0a77aecec196accc52973\0", 96);
    integer_set_str_(&res->g->x, "aa87ca22be8b05378eb1c71ef320ad746e1d3b628ba79b9859f741e082542a385502f25dbf55296c3a545e3872760ab7\0", 96);
    integer_set_str_(&res->g->y, "3617de4a96262c6f5d9e98bf9292dc29f8f41dbd289a147ce9da3113b5f0b8c00a60b1ce1d7e819d7a431d7c90ea0e5f\0", 96);
}
void ecc_curve_secp521r1(struct ecc_curve *res) {
    if (res == NULL) return;
    integer_set_ui(&res->h, 1);
    integer_set_str_(&res->a, "01fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffc\0", 132);
    integer_set_str_(&res->b, "0051953eb9618e1c9a1f929a21a0b68540eea2da725b99b315f3b8b489918ef109e156193951ec7e937b1652c0bd3bb1bf073573df883d2c34f1ef451fd46b503f00\0", 132);
    integer_set_str_(&res->p, "01ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff\0", 132);
    integer_set_str_(&res->n, "01fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffa51868783bf2f966b7fcc0148f709a5d03bb5c9b8899c47aebb6fb71e91386409\0", 132);
    integer_set_str_(&res->g->x, "00c6858e06b70404e9cd9e3ecb662395b4429c648139053fb521f828af606b4d3dbaa14b5e77efe75928fe1dc127a2ffa8de3348b3c1856a429bf97e7e31c2e5bd66\0", 132);
    integer_set_str_(&res->g->y, "011839296a789a3bc0045c8a5fb42c7d1bd998f54449579b446817afbd17273e662c97ee72995ef42640c550b9013fad0761353c7086a272c24088be94769fd16650\0", 132);
}