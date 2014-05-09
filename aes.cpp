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
		"movups	%%xmm1, (%%rcx) \n" \
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
		"movups	%%xmm3, 16(%%rcx) \n" \
		"add $32, %%rcx \n"	
		

	void ECBCryptoAESNI::ExpandKey (const uint8_t * key)
	{
		__asm__
		(
			"movups (%%rsi), %%xmm1 \n"
			"movups 16(%%rsi), %%xmm3 \n"
			"movups %%xmm1, (%%rdi) \n"
			"movups %%xmm3, 16(%%rdi) \n"
			"lea 32(%%rdi), %%rcx \n"
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
			: "S" (key), "D" (m_KeySchedule) // input
			: "%rcx" // clogged
		);
	}

	void ECBEncryptionAESNI::Encrypt (const ChipherBlock * in, ChipherBlock * out)
	{
		__asm__
		(
			"movups	(%%rsi), %%xmm0 \n"
			"pxor (%%rdx), %%xmm0 \n"
			"aesenc	16(%%rdx), %%xmm0 \n"
			"aesenc	32(%%rdx), %%xmm0 \n"
			"aesenc	48(%%rdx), %%xmm0 \n"
			"aesenc	64(%%rdx), %%xmm0 \n"
			"aesenc	80(%%rdx), %%xmm0 \n"
			"aesenc	96(%%rdx), %%xmm0 \n"
			"aesenc	112(%%rdx), %%xmm0 \n"
			"aesenc	128(%%rdx), %%xmm0 \n"
			"aesenc	144(%%rdx), %%xmm0 \n"
			"aesenc	160(%%rdx), %%xmm0 \n"
			"aesenc	176(%%rdx), %%xmm0 \n"
			"aesenc	192(%%rdx), %%xmm0 \n"
			"aesenc	208(%%rdx), %%xmm0 \n"
			"aesenclast	224(%%rdx), %%xmm0 \n"
			"movups	%%xmm0, (%%rdi) \n"	
			: : "d" (m_KeySchedule), "S" (in), "D" (out)
		);
	}		

	void ECBDecryptionAESNI::Decrypt (const ChipherBlock * in, ChipherBlock * out)
	{
		__asm__
		(
			"movups	(%%rsi), %%xmm0 \n"
			"pxor 224(%%rdx), %%xmm0 \n"
			"aesdec	208(%%rdx), %%xmm0 \n"
			"aesdec	192(%%rdx), %%xmm0 \n"
			"aesdec	176(%%rdx), %%xmm0 \n"
			"aesdec	160(%%rdx), %%xmm0 \n"
			"aesdec	144(%%rdx), %%xmm0 \n"
			"aesdec	128(%%rdx), %%xmm0 \n"
			"aesdec	112(%%rdx), %%xmm0 \n"
			"aesdec	96(%%rdx), %%xmm0 \n"
			"aesdec	80(%%rdx), %%xmm0 \n"
			"aesdec	64(%%rdx), %%xmm0 \n"
			"aesdec	48(%%rdx), %%xmm0 \n"
			"aesdec	32(%%rdx), %%xmm0 \n"
			"aesdec	16(%%rdx), %%xmm0 \n"
			"aesdeclast (%%rdx), %%xmm0 \n"
			"movups	%%xmm0, (%%rdi) \n"	
			: : "d" (m_KeySchedule), "S" (in), "D" (out)
		);		
	}

	#define CallAESIMC(offset) \
		"movups "#offset"(%%rdx), %%xmm0 \n"	\
		"aesimc %%xmm0, %%xmm0 \n" \
		"movups %%xmm0, "#offset"(%%rdx) \n" 

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
			: : "d" (m_KeySchedule)
		);
	}

#endif		


	void CBCEncryption::Encrypt (int numBlocks, const ChipherBlock * in, ChipherBlock * out)
	{
		for (int i = 0; i < numBlocks; i++)
		{
			m_LastBlock ^= in[i];
			m_ECBEncryption.Encrypt (&m_LastBlock, &m_LastBlock);
			out[i] = m_LastBlock;
		}
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

