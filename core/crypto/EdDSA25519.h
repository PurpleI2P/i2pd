#ifndef EDDSA25519_H__
#define EDDSA25519_H__

#include "SignatureBase.h"

namespace i2p {
namespace crypto {

// EdDSA
const size_t EDDSA25519_PUBLIC_KEY_LENGTH = 32;
const size_t EDDSA25519_SIGNATURE_LENGTH = 64;
const size_t EDDSA25519_PRIVATE_KEY_LENGTH = 32;        

class EDDSA25519Verifier : public Verifier {
public:

    EDDSA25519Verifier(const uint8_t* signingKey);
    bool Verify(const uint8_t* buf, size_t len, const uint8_t* signature) const;

    size_t GetPublicKeyLen() const;
    size_t GetSignatureLen() const;

private:

    uint8_t m_PublicKey[EDDSA25519_PUBLIC_KEY_LENGTH];
};

class EDDSA25519Signer : public Signer {
public:

    /**
     * @todo allow passing the public key too as an optimization
     */
    EDDSA25519Signer(const uint8_t * signingPrivateKey);

    /**
     * @todo do not pass random number generator, EdDSA does not require a random
     *  source
     */
    void Sign(CryptoPP::RandomNumberGenerator&, const uint8_t* buf, int len, uint8_t* signature) const; 

    uint8_t m_PrivateKey[EDDSA25519_PRIVATE_KEY_LENGTH];
    uint8_t m_PublicKey[EDDSA25519_PUBLIC_KEY_LENGTH];
};

void CreateEDDSARandomKeys(CryptoPP::RandomNumberGenerator& rnd, uint8_t* privateKey,
    uint8_t* publicKey);

}
}

#endif // EDDSA25519_H__
