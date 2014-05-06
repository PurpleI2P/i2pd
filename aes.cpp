#include <stdlib.h>
#include "aes.h"

namespace i2p
{
namespace crypto
{
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

