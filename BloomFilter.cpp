#include "BloomFilter.h"
#include "I2PEndian.h"
#include <array>
#include <openssl/sha.h>

namespace i2p
{
namespace util
{

	/** @brief decaying bloom filter implementation */
	class DecayingBloomFilter : public IBloomFilter
	{
	public:

		DecayingBloomFilter(const std::size_t size)
		{
			m_Size = size;
			m_Data = new uint8_t[size];
		}

		/** @brief implements IBloomFilter::~IBloomFilter */
		~DecayingBloomFilter()
		{
			delete [] m_Data;
		}

		/** @brief implements IBloomFilter::Add */
		bool Add(const uint8_t * data, std::size_t len)
		{
			std::size_t idx;
			uint8_t mask;
			Get(data, len, idx, mask);
			if(m_Data[idx] & mask) return false; // filter hit
			m_Data[idx] |= mask;
			return true;
		}

		/** @brief implements IBloomFilter::Decay */
		void Decay()
		{
			// reset bloom filter buffer
			memset(m_Data, 0, m_Size);
		}

	private:
		/** @brief get bit index for for data */
		void Get(const uint8_t * data, std::size_t len, std::size_t & idx, uint8_t & bm)
		{
			bm = 1;
			uint8_t digest[32];
			// TODO: use blake2 because it's faster
			SHA256(data, len, digest);
			uint64_t i = buf64toh(digest);
			idx = i % m_Size;
			bm <<= (i % 8);
		}

		uint8_t * m_Data;
		std::size_t m_Size;
	};


	BloomFilterPtr BloomFilter(std::size_t capacity)
	{
		return std::make_shared<DecayingBloomFilter>(capacity);
	}
}
}
