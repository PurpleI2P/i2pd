#include <stdlib.h>
#include "aes.h"

namespace i2p {
namespace crypto {

#ifdef AESNI
#include "AESNIMacros.h" 

void ECBCryptoAESNI::ExpandKey (const AESKey& key)
{
    __asm__
    (
        "movups (%[key]), %%xmm1 \n"
        "movups 16(%[key]), %%xmm3 \n"
        "movaps %%xmm1, (%[sched]) \n"
        "movaps %%xmm3, 16(%[sched]) \n"
        "aeskeygenassist $1, %%xmm3, %%xmm2 \n"
        KeyExpansion256(32,48)
        "aeskeygenassist $2, %%xmm3, %%xmm2 \n"
        KeyExpansion256(64,80)
        "aeskeygenassist $4, %%xmm3, %%xmm2 \n"
        KeyExpansion256(96,112)
        "aeskeygenassist $8, %%xmm3, %%xmm2 \n"
        KeyExpansion256(128,144)
        "aeskeygenassist $16, %%xmm3, %%xmm2 \n"
        KeyExpansion256(160,176)
        "aeskeygenassist $32, %%xmm3, %%xmm2 \n"
        KeyExpansion256(192,208)
        "aeskeygenassist $64, %%xmm3, %%xmm2 \n"
        // key expansion final
        "pshufd $0xff, %%xmm2, %%xmm2 \n"
        "movaps %%xmm1, %%xmm4 \n" 
        "pslldq $4, %%xmm4 \n"
        "pxor %%xmm4, %%xmm1 \n"
        "pslldq $4, %%xmm4 \n"
        "pxor %%xmm4, %%xmm1 \n"
        "pslldq $4, %%xmm4 \n"
        "pxor %%xmm4, %%xmm1 \n"
        "pxor %%xmm2, %%xmm1 \n"
        "movups %%xmm1, 224(%[sched]) \n"
        : // output
        : [key]"r"((const uint8_t *)key), [sched]"r"(GetKeySchedule ()) // input
        : "%xmm1", "%xmm2", "%xmm3", "%xmm4", "memory" // clogged
    );
}

void ECBEncryptionAESNI::Encrypt (const ChipherBlock * in, ChipherBlock * out)
{
    __asm__
    (
        "movups (%[in]), %%xmm0 \n"
        EncryptAES256(sched)
        "movups %%xmm0, (%[out]) \n"    
        : : [sched]"r"(GetKeySchedule ()), [in]"r"(in), [out]"r"(out) : "%xmm0", "memory"
    );
}       


void ECBDecryptionAESNI::Decrypt (const ChipherBlock * in, ChipherBlock * out)
{
    __asm__
    (
        "movups (%[in]), %%xmm0 \n"
        DecryptAES256(sched)
        "movups %%xmm0, (%[out]) \n"    
        : : [sched]"r"(GetKeySchedule ()), [in]"r"(in), [out]"r"(out) : "%xmm0", "memory"
    );      
}

void ECBDecryptionAESNI::SetKey (const AESKey& key)
{
    ExpandKey (key); // expand encryption key first
    // then  invert it using aesimc
    __asm__
    (
        CallAESIMC(16)
        CallAESIMC(32)
        CallAESIMC(48)
        CallAESIMC(64)
        CallAESIMC(80)
        CallAESIMC(96)
        CallAESIMC(112)
        CallAESIMC(128)
        CallAESIMC(144)
        CallAESIMC(160)
        CallAESIMC(176)
        CallAESIMC(192)
        CallAESIMC(208)
        : : [shed]"r"(GetKeySchedule ()) : "%xmm0", "memory"
    );
}

#endif      


void CBCEncryption::Encrypt (int numBlocks, const ChipherBlock * in, ChipherBlock * out)
{
#ifdef AESNI
    __asm__
    (
        "movups (%[iv]), %%xmm1 \n"
        "1: \n"
        "movups (%[in]), %%xmm0 \n"
        "pxor %%xmm1, %%xmm0 \n"
        EncryptAES256(sched)
        "movaps %%xmm0, %%xmm1 \n"  
        "movups %%xmm0, (%[out]) \n"
        "add $16, %[in] \n"
        "add $16, %[out] \n"
        "dec %[num] \n"
        "jnz 1b \n"     
        "movups %%xmm1, (%[iv]) \n"
        : 
        : [iv]"r"(&m_LastBlock), [sched]"r"(m_ECBEncryption.GetKeySchedule ()), 
          [in]"r"(in), [out]"r"(out), [num]"r"(numBlocks)
        : "%xmm0", "%xmm1", "cc", "memory"
    ); 
#else       
    for (int i = 0; i < numBlocks; i++)
    {
        m_LastBlock ^= in[i];
        m_ECBEncryption.Encrypt (&m_LastBlock, &m_LastBlock);
        out[i] = m_LastBlock;
    }
#endif      
}

void CBCEncryption::Encrypt (const uint8_t * in, std::size_t len, uint8_t * out)
{
    // len/16
    int numBlocks = len >> 4;
    if (numBlocks > 0)
        Encrypt (numBlocks, (const ChipherBlock *)in, (ChipherBlock *)out); 
}

void CBCEncryption::Encrypt (const uint8_t * in, uint8_t * out)
{
#ifdef AESNI
    __asm__
    (
        "movups (%[iv]), %%xmm1 \n"
        "movups (%[in]), %%xmm0 \n"
        "pxor %%xmm1, %%xmm0 \n"
        EncryptAES256(sched)
        "movups %%xmm0, (%[out]) \n"
        "movups %%xmm0, (%[iv]) \n"
        : 
        : [iv]"r"(&m_LastBlock), [sched]"r"(m_ECBEncryption.GetKeySchedule ()), 
          [in]"r"(in), [out]"r"(out)
        : "%xmm0", "%xmm1", "memory"
    );      
#else
    Encrypt (1, (const ChipherBlock *)in, (ChipherBlock *)out); 
#endif
}

void CBCDecryption::Decrypt (int numBlocks, const ChipherBlock * in, ChipherBlock * out)
{
#ifdef AESNI
    __asm__
    (
        "movups (%[iv]), %%xmm1 \n"
        "1: \n"
        "movups (%[in]), %%xmm0 \n"
        "movaps %%xmm0, %%xmm2 \n"
        DecryptAES256(sched)
        "pxor %%xmm1, %%xmm0 \n"
        "movups %%xmm0, (%[out]) \n"
        "movaps %%xmm2, %%xmm1 \n"
        "add $16, %[in] \n"
        "add $16, %[out] \n"
        "dec %[num] \n"
        "jnz 1b \n"     
        "movups %%xmm1, (%[iv]) \n"
        : 
        : [iv]"r"(&m_IV), [sched]"r"(m_ECBDecryption.GetKeySchedule ()), 
          [in]"r"(in), [out]"r"(out), [num]"r"(numBlocks)
        : "%xmm0", "%xmm1", "%xmm2", "cc", "memory"
    ); 
#else
    for (int i = 0; i < numBlocks; i++)
    {
        ChipherBlock tmp = in[i];
        m_ECBDecryption.Decrypt (in + i, out + i);
        out[i] ^= m_IV;
        m_IV = tmp;
    }
#endif
}

void CBCDecryption::Decrypt (const uint8_t * in, std::size_t len, uint8_t * out)
{
    int numBlocks = len >> 4;
    if (numBlocks > 0)
        Decrypt (numBlocks, (const ChipherBlock *)in, (ChipherBlock *)out); 
}

void CBCDecryption::Decrypt (const uint8_t * in, uint8_t * out)
{
#ifdef AESNI
    __asm__
    (
        "movups (%[iv]), %%xmm1 \n"
        "movups (%[in]), %%xmm0 \n"
        "movups %%xmm0, (%[iv]) \n"
        DecryptAES256(sched)
        "pxor %%xmm1, %%xmm0 \n"
        "movups %%xmm0, (%[out]) \n"    
        : 
        : [iv]"r"(&m_IV), [sched]"r"(m_ECBDecryption.GetKeySchedule ()), 
          [in]"r"(in), [out]"r"(out)
        : "%xmm0", "%xmm1", "memory"
    );
#else
    Decrypt (1, (const ChipherBlock *)in, (ChipherBlock *)out); 
#endif
}

} // crypto
} // i2p

