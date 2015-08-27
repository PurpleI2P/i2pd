#include "EdDSA25519.h"
#include "ed25519/ed25519_ref10.h"
#include <cstring>

namespace i2p {
namespace crypto {


EDDSA25519Verifier::EDDSA25519Verifier(const uint8_t* signingKey)
{

    std::memcpy(m_PublicKey, signingKey, EDDSA25519_PUBLIC_KEY_LENGTH);
}

bool EDDSA25519Verifier::Verify(const uint8_t* buf, size_t len, const uint8_t* signature) const
{
    return ed25519_ref10_open(signature, buf, len, m_PublicKey) > 0;
}

size_t EDDSA25519Verifier::GetPublicKeyLen() const
{
    return EDDSA25519_PUBLIC_KEY_LENGTH;
}


size_t EDDSA25519Verifier::GetSignatureLen() const
{
    return EDDSA25519_SIGNATURE_LENGTH;
}


EDDSA25519Signer::EDDSA25519Signer(const uint8_t* signingPrivateKey)
{
    std::memcpy(m_PrivateKey, signingPrivateKey, EDDSA25519_PRIVATE_KEY_LENGTH);
    ed25519_ref10_pubkey(m_PublicKey, m_PrivateKey);
}

void EDDSA25519Signer::Sign(CryptoPP::RandomNumberGenerator& rnd, const uint8_t* buf, int len, uint8_t* signature) const
{
    ed25519_ref10_sign(signature, buf, len, m_PrivateKey, m_PublicKey);
}

}
}
