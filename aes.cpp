#include <stdlib.h>
#include "aes.h"

namespace i2p
{
namespace crypto
{

#ifdef __x86_64__

	ECBCryptoAESNI::ECBCryptoAESNI ()
	{
		m_KeySchedule = m_UnalignedBuffer;
		uint8_t rem = ((uint64_t)m_KeySchedule) & 0x0f;
		if (rem)
			m_KeySchedule += (16 - rem);
	}	
	
	#define KeyExpansion256 \
		"pshufd	$0xff, %%xmm2, %%xmm2 \n" \
		"movaps	%%xmm1, %%xmm4 \n" \
		"pslldq	$4, %%xmm4 \n" \
		"pxor %%xmm4, %%xmm1 \n" \
		"pslldq	$4, %%xmm4 \n" \
		"pxor %%xmm4, %%xmm1 \n" \
		"pslldq	$4, %%xmm4 \n" \
		"pxor %%xmm4, %%xmm1 \n" \
		"pxor %%xmm2, %%xmm1 \n" \
		"movaps	%%xmm1, (%%rcx) \n" \
		"aeskeygenassist $0, %%xmm1, %%xmm4 \n" \
		"pshufd	$0xaa, %%xmm4, %%xmm2 \n" \
		"movaps	%%xmm3, %%xmm4 \n" \
		"pslldq	$4, %%xmm4 \n" \
		"pxor %%xmm4, %%xmm3 \n" \
	    "pslldq	$4, %%xmm4 \n" \
		"pxor %%xmm4, %%xmm3 \n" \
		"pslldq	$4, %%xmm4 \n" \
		"pxor %%xmm4, %%xmm3 \n" \
		"pxor %%xmm2, %%xmm3 \n" \
		"movaps	%%xmm3, 16(%%rcx) \n" \
		"add $32, %%rcx \n"	
		

	void ECBCryptoAESNI::ExpandKey (const uint8_t * key)
	{
		__asm__
		(
			"movups (%[key]), %%xmm1 \n"
			"movups 16(%[key]), %%xmm3 \n"
			"movaps %%xmm1, (%[sched]) \n"
			"movaps %%xmm3, 16(%[sched]) \n"
			"lea 32(%[sched]), %%rcx \n"
			"aeskeygenassist $1, %%xmm3, %%xmm2 \n"
			KeyExpansion256
			"aeskeygenassist $2, %%xmm3, %%xmm2 \n"
			KeyExpansion256
			"aeskeygenassist $4, %%xmm3, %%xmm2 \n"
			KeyExpansion256
			"aeskeygenassist $8, %%xmm3, %%xmm2 \n"
			KeyExpansion256
			"aeskeygenassist $16, %%xmm3, %%xmm2 \n"
			KeyExpansion256
			"aeskeygenassist $32, %%xmm3, %%xmm2 \n"
			KeyExpansion256
			"aeskeygenassist $64, %%xmm3, %%xmm2 \n"
			// key expansion final
			"pshufd	$0xff, %%xmm2, %%xmm2 \n"
			"movaps	%%xmm1, %%xmm4 \n" 
			"pslldq	$4, %%xmm4 \n"
			"pxor %%xmm4, %%xmm1 \n"
			"pslldq	$4, %%xmm4 \n"
			"pxor %%xmm4, %%xmm1 \n"
			"pslldq	$4, %%xmm4 \n"
			"pxor %%xmm4, %%xmm1 \n"
			"pxor %%xmm2, %%xmm1 \n"
			"movups	%%xmm1, (%%rcx) \n"
			: // output
			: [key]"r"(key), [sched]"r"(m_KeySchedule) // input
			: "%rcx", "%xmm1", "%xmm2", "%xmm3", "%xmm4" // clogged
		);
	}

	#define EncryptAES256 \
		"pxor (%[sched]), %%xmm0 \n" \
		"aesenc	16(%[sched]), %%xmm0 \n" \
		"aesenc	32(%[sched]), %%xmm0 \n" \
		"aesenc	48(%[sched]), %%xmm0 \n" \
		"aesenc	64(%[sched]), %%xmm0 \n" \
		"aesenc	80(%[sched]), %%xmm0 \n" \
		"aesenc	96(%[sched]), %%xmm0 \n" \
		"aesenc	112(%[sched]), %%xmm0 \n" \
		"aesenc	128(%[sched]), %%xmm0 \n" \
		"aesenc	144(%[sched]), %%xmm0 \n" \
		"aesenc	160(%[sched]), %%xmm0 \n" \
		"aesenc	176(%[sched]), %%xmm0 \n" \
		"aesenc	192(%[sched]), %%xmm0 \n" \
		"aesenc	208(%[sched]), %%xmm0 \n" \
		"aesenclast	224(%[sched]), %%xmm0 \n"
		
	void ECBEncryptionAESNI::Encrypt (const ChipherBlock * in, ChipherBlock * out)
	{
		__asm__
		(
			"movups	(%[in]), %%xmm0 \n"
			EncryptAES256
			"movups	%%xmm0, (%[out]) \n"	
			: : [sched]"r"(m_KeySchedule), [in]"r"(in), [out]"r"(out) : "%xmm0"
		);
	}		

	#define DecryptAES256 \
		"pxor 224(%[sched]), %%xmm0 \n" \
		"aesdec	208(%[sched]), %%xmm0 \n" \
		"aesdec	192(%[sched]), %%xmm0 \n" \
		"aesdec	176(%[sched]), %%xmm0 \n" \
		"aesdec	160(%[sched]), %%xmm0 \n" \
		"aesdec	144(%[sched]), %%xmm0 \n" \
		"aesdec	128(%[sched]), %%xmm0 \n" \
		"aesdec	112(%[sched]), %%xmm0 \n" \
		"aesdec	96(%[sched]), %%xmm0 \n" \
		"aesdec	80(%[sched]), %%xmm0 \n" \
		"aesdec	64(%[sched]), %%xmm0 \n" \
		"aesdec	48(%[sched]), %%xmm0 \n" \
		"aesdec	32(%[sched]), %%xmm0 \n" \
		"aesdec	16(%[sched]), %%xmm0 \n" \
		"aesdeclast (%[sched]), %%xmm0 \n"
	
	void ECBDecryptionAESNI::Decrypt (const ChipherBlock * in, ChipherBlock * out)
	{
		__asm__
		(
			"movups	(%[in]), %%xmm0 \n"
			DecryptAES256
			"movups	%%xmm0, (%[out]) \n"	
			: : [sched]"r"(m_KeySchedule), [in]"r"(in), [out]"r"(out) : "%xmm0"
		);		
	}

	#define CallAESIMC(offset) \
		"movaps "#offset"(%[shed]), %%xmm0 \n"	\
		"aesimc %%xmm0, %%xmm0 \n" \
		"movaps %%xmm0, "#offset"(%[shed]) \n" 

	void ECBDecryptionAESNI::SetKey (const uint8_t * key)
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
			: : [shed]"r"(m_KeySchedule) : "%xmm0"
		);
	}

#endif		


	void CBCEncryption::Encrypt (int numBlocks, const ChipherBlock * in, ChipherBlock * out)
	{
#ifdef __x86_64__
		__asm__
		(
		 	"movups	(%[iv]), %%xmm1 \n"
		 	"block: \n"
		 	"movups	(%[in]), %%xmm0 \n"
		 	"pxor %%xmm1, %%xmm0 \n"
		 	EncryptAES256
		 	"movaps	%%xmm0, %%xmm1 \n"	
		 	"movups	%%xmm0, (%[out]) \n"
		 	"add $16, %[in] \n"
		 	"add $16, %[out] \n"
		 	"dec %[num] \n"
		 	"jnz block; \n"	 	
		 	"movups	%%xmm1, (%[iv]) \n"
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

	bool CBCEncryption::Encrypt (const uint8_t * in, std::size_t len, uint8_t * out)
	{
		div_t d = div (len, 16);
		if (d.rem) return false; // len is not multipple of 16
		Encrypt (d.quot, (const ChipherBlock *)in, (ChipherBlock *)out); 
		return true;
	}

	void CBCDecryption::Decrypt (int numBlocks, const ChipherBlock * in, ChipherBlock * out)
	{
		for (int i = 0; i < numBlocks; i++)
		{
			ChipherBlock tmp = in[i];
			m_ECBDecryption.Decrypt (in + i, out + i);
			out[i] ^= m_IV;
			m_IV = tmp;
		}
	}

	bool CBCDecryption::Decrypt (const uint8_t * in, std::size_t len, uint8_t * out)
	{
		div_t d = div (len, 16);
		if (d.rem) return false; // len is not multipple of 16
		Decrypt (d.quot, (const ChipherBlock *)in, (ChipherBlock *)out); 
		return true;
	}
}
}

