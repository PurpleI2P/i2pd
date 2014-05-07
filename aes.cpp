#include <stdlib.h>
#include "aes.h"

namespace i2p
{
namespace crypto
{

#ifdef __x86_64__
		
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
		

	void ECNEncryptionAESNI::SetKey (const uint8_t * key)
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
			"aeskeygenassist $10, %%xmm3, %%xmm2 \n"
			KeyExpansion256
			"aeskeygenassist $20, %%xmm3, %%xmm2 \n"
			KeyExpansion256
			"aeskeygenassist $40, %%xmm3, %%xmm2 \n"
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
			: "%rcx" // modified
		);
	}

#endif		


	void CBCEncryption::Encrypt (int numBlocks, const ChipherBlock * in, ChipherBlock * out)
	{
		for (int i = 0; i < numBlocks; i++)
		{
			m_LastBlock.ll[0] ^= in[i].ll[0];
			m_LastBlock.ll[1] ^= in[i].ll[1];
			m_ECBEncryption.ProcessData (m_LastBlock.buf, m_LastBlock.buf, 16);
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
			m_ECBDecryption.ProcessData (out[i].buf, in[i].buf, 16);
			out[i].ll[0] ^= m_IV.ll[0];
			out[i].ll[1] ^= m_IV.ll[1];
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

