#ifndef ED25519_REF10_H__
#define ED25519_REF10_H__

/**
 * Generate a public key from a given private key.
 */
int ed25519_ref10_pubkey(unsigned char* pk, const unsigned char* sk);

int ed25519_ref10_open(
    const unsigned char* sig,
    const unsigned char* m, size_t mlen,
    const unsigned char*pk
);

int ed25519_ref10_sign(
    unsigned char* sig,
    const unsigned char* m, size_t mlen,
    const unsigned char* sk, const unsigned char* pk
);


#endif // ED25519_REF10_H__
