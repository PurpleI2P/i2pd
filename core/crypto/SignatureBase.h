#ifndef SIGNATUREBASE_H__
#define SIGNATUREBASE_H__

#include <cryptopp/osrng.h>

namespace i2p {
namespace crypto {

class Verifier {
public:
    
    virtual ~Verifier() {};
    virtual bool Verify(const uint8_t * buf, size_t len, const uint8_t * signature) const = 0;
    virtual size_t GetPublicKeyLen() const = 0;
    virtual size_t GetSignatureLen() const = 0;
    virtual size_t GetPrivateKeyLen() const { return GetSignatureLen()/2; };
};

class Signer {
public:

    virtual ~Signer() {};      
    virtual void Sign(CryptoPP::RandomNumberGenerator& rnd, const uint8_t * buf, int len, uint8_t * signature) const = 0; 
};


}
}
#endif // SIGNATUREBASE_H__
