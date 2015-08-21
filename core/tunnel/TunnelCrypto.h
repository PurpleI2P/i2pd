#ifndef TUNNEL_CRYPTO_H__
#define TUNNEL_CRYPTO_H__

#include "crypto/aes.h"

namespace i2p {
namespace crypto {

class TunnelEncryption { // with double IV encryption
public:
    void SetKeys (const AESKey& layerKey, const AESKey& ivKey);

    void Encrypt (const uint8_t * in, uint8_t * out); // 1024 bytes (16 IV + 1008 data)     

private:

    ECBEncryption m_IVEncryption;
#ifdef AESNI
    ECBEncryption m_LayerEncryption;
#else
    CBCEncryption m_LayerEncryption;
#endif
};

class TunnelDecryption { // with double IV encryption
public:

    void SetKeys (const AESKey& layerKey, const AESKey& ivKey)
    {
        m_LayerDecryption.SetKey (layerKey);
        m_IVDecryption.SetKey (ivKey);
    }           

    void Decrypt (const uint8_t * in, uint8_t * out); // 1024 bytes (16 IV + 1008 data) 

private:

    ECBDecryption m_IVDecryption;
#ifdef AESNI
    ECBDecryption m_LayerDecryption;
#else
    CBCDecryption m_LayerDecryption;
#endif
};

} // crypto
} // i2p

#endif
