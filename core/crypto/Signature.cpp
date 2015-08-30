#include <memory>
#include <cryptopp/integer.h>
#include <cryptopp/eccrypto.h>
#include "util/Log.h"
#include "Signature.h"

namespace i2p {
namespace crypto {

DSASigner::DSASigner(const uint8_t * signingPrivateKey)
{
    m_PrivateKey.Initialize(
        dsap, dsaq, dsag,
        CryptoPP::Integer(signingPrivateKey, DSA_PRIVATE_KEY_LENGTH)
    );
}

void DSASigner::Sign(CryptoPP::RandomNumberGenerator& rnd, const uint8_t * buf,
 int len, uint8_t * signature) const
{
    CryptoPP::DSA::Signer signer(m_PrivateKey);
    signer.SignMessage(rnd, buf, len, signature);
}

void CreateDSARandomKeys(CryptoPP::RandomNumberGenerator& rnd,
  uint8_t* signingPrivateKey, uint8_t* signingPublicKey)
{
    CryptoPP::DSA::PrivateKey privateKey;
    CryptoPP::DSA::PublicKey publicKey;
    privateKey.Initialize(rnd, dsap, dsaq, dsag);
    privateKey.MakePublicKey(publicKey);
    privateKey.GetPrivateExponent().Encode(signingPrivateKey, DSA_PRIVATE_KEY_LENGTH);    
    publicKey.GetPublicElement().Encode(signingPublicKey, DSA_PUBLIC_KEY_LENGTH);
}

   
} // crypto
} // i2p
