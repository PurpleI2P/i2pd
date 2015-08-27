#ifndef CRYPTO_HASH_SHA512_H__
#define CRYPTO_HASH_SHA512_H__

#include <cryptopp/sha.h>

inline void crypto_hash_sha512(unsigned char* output, const unsigned char* input,
 unsigned long long len)
{
    CryptoPP::SHA512 hash;
    hash.CalculateDigest(output, input, len);
}

inline void crypto_hash_sha512_2(unsigned char* out,
    const unsigned char* in1, unsigned long long len1, 
    const unsigned char* in2, unsigned long long len2
)
{
    CryptoPP::SHA512 hash;
    hash.Update(in1, len1);
    hash.Update(in2, len2);
    hash.Final(out);
}

inline void crypto_hash_sha512_3(unsigned char* out,
    const unsigned char* in1, unsigned long long len1, 
    const unsigned char* in2, unsigned long long len2,
    const unsigned char* in3, unsigned long long len3
    )
{
    CryptoPP::SHA512 hash;
    hash.Update(in1, len1);
    hash.Update(in2, len2);
    hash.Update(in3, len3);
    hash.Final(out);
}

#endif // CRYPTO_HASH_SHA512_H__
