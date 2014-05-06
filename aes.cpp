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

	void CBCDecryption::Decrypt (int numBlocks, const ChipherBlock * in, ChipherBlock * out)
	{
		for (int i = 0; i < numBlocks; i++)
		{
			m_ECBDecryption.ProcessData (out[i].buf, in[i].buf, 16);
			out[i].ll[0] ^= m_IV.ll[0];
			out[i].ll[1] ^= m_IV.ll[1];
			m_IV = in[i];
		}
	}
}
}

