#include "TunnelCrypto.h"
#include "TunnelBase.h"
#include "crypto/AESNIMacros.h" 

namespace i2p {
namespace crypto {

void TunnelEncryption::SetKeys (const AESKey& layerKey, const AESKey& ivKey)
{
    m_LayerEncryption.SetKey (layerKey);
    m_IVEncryption.SetKey (ivKey);
}

void TunnelEncryption::Encrypt (const uint8_t * in, uint8_t * out)
{
#ifdef AESNI
    __asm__
    (
        // encrypt IV 
        "movups (%[in]), %%xmm0 \n"
        EncryptAES256(sched_iv)
        "movaps %%xmm0, %%xmm1 \n"
        // double IV encryption
        EncryptAES256(sched_iv)
        "movups %%xmm0, (%[out]) \n"
        // encrypt data, IV is xmm1
        "1: \n"
        "add $16, %[in] \n"
        "add $16, %[out] \n"
        "movups (%[in]), %%xmm0 \n"
        "pxor %%xmm1, %%xmm0 \n"
        EncryptAES256(sched_l)
        "movaps %%xmm0, %%xmm1 \n"  
        "movups %%xmm0, (%[out]) \n"
        "dec %[num] \n"
        "jnz 1b \n"     
        : 
        : [sched_iv]"r"(m_IVEncryption.GetKeySchedule ()), [sched_l]"r"(m_LayerEncryption.GetKeySchedule ()), 
          [in]"r"(in), [out]"r"(out), [num]"r"(63) // 63 blocks = 1008 bytes
        : "%xmm0", "%xmm1", "cc", "memory"
    );
#else
    m_IVEncryption.Encrypt ((const ChipherBlock *)in, (ChipherBlock *)out); // iv
    m_LayerEncryption.SetIV (out);
    m_LayerEncryption.Encrypt (in + 16, i2p::tunnel::TUNNEL_DATA_ENCRYPTED_SIZE, out + 16); // data
    m_IVEncryption.Encrypt ((ChipherBlock *)out, (ChipherBlock *)out); // double iv
#endif
    }

void TunnelDecryption::Decrypt (const uint8_t * in, uint8_t * out)
{
#ifdef AESNI
    __asm__
    (
        // decrypt IV 
        "movups (%[in]), %%xmm0 \n"
        DecryptAES256(sched_iv)
        "movaps %%xmm0, %%xmm1 \n"
        // double IV encryption
        DecryptAES256(sched_iv)
        "movups %%xmm0, (%[out]) \n"
        // decrypt data, IV is xmm1
        "1: \n"
        "add $16, %[in] \n"
        "add $16, %[out] \n"
        "movups (%[in]), %%xmm0 \n"
        "movaps %%xmm0, %%xmm2 \n"
        DecryptAES256(sched_l)
        "pxor %%xmm1, %%xmm0 \n"
        "movups %%xmm0, (%[out]) \n"
        "movaps %%xmm2, %%xmm1 \n"
        "dec %[num] \n"
        "jnz 1b \n"     
        : 
        : [sched_iv]"r"(m_IVDecryption.GetKeySchedule ()), [sched_l]"r"(m_LayerDecryption.GetKeySchedule ()), 
          [in]"r"(in), [out]"r"(out), [num]"r"(63) // 63 blocks = 1008 bytes
        : "%xmm0", "%xmm1", "%xmm2", "cc", "memory"
    );
#else
    m_IVDecryption.Decrypt ((const ChipherBlock *)in, (ChipherBlock *)out); // iv
    m_LayerDecryption.SetIV (out);  
    m_LayerDecryption.Decrypt (in + 16, i2p::tunnel::TUNNEL_DATA_ENCRYPTED_SIZE, out + 16); // data
    m_IVDecryption.Decrypt ((ChipherBlock *)out, (ChipherBlock *)out); // double iv
#endif
}

} // crypto
} // i2p
