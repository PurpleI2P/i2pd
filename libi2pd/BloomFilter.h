/*
* Copyright (c) 2013-2020, The PurpleI2P Project
*
* This file is part of Purple i2pd project and licensed under BSD3
*
* See full license text in LICENSE file at top of project tree
*/

#ifndef BLOOM_FILTER_H_
#define BLOOM_FILTER_H_
#include <memory>
#include <cstdint>

namespace i2p
{
namespace util
{

	/** @brief interface for bloom filter */
	struct IBloomFilter
	{

		/** @brief destructor */
		virtual ~IBloomFilter() {};
		/** @brief add entry to bloom filter, return false if filter hit otherwise return true */
		virtual bool Add(const uint8_t * data, std::size_t len) = 0;
		/** @brief optionally decay old entries */
		virtual void Decay() = 0;
	};

	typedef std::shared_ptr<IBloomFilter> BloomFilterPtr;

	/** @brief create bloom filter */
	BloomFilterPtr BloomFilter(std::size_t capacity = 1024 * 8);

}
}

#endif
