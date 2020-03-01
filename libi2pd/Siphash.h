/**
 * This code is licensed under the MCGSI Public License
 * Copyright 2018 Jeff Becker
 *
 * Kovri go write your own code
 *
 */
#ifndef SIPHASH_H
#define SIPHASH_H

#include <cstdint>
#include "Crypto.h"

#if !OPENSSL_SIPHASH
namespace i2p
{
namespace crypto
{
	namespace siphash
	{
		constexpr int crounds = 2;
		constexpr int drounds = 4;

		inline uint64_t rotl(const uint64_t & x, int b)
		{
			uint64_t ret = x << b;
			ret |= x >> (64 - b);
			return ret;
		}

		inline void u32to8le(const uint32_t & v, uint8_t * p)
		{
			p[0] = (uint8_t) v;
			p[1] = (uint8_t) (v >> 8);
			p[2] = (uint8_t) (v >> 16);
			p[3] = (uint8_t) (v >> 24);
		}

		inline void u64to8le(const uint64_t & v, uint8_t * p)
		{
			p[0] = v & 0xff;
			p[1] = (v >> 8)  & 0xff;
			p[2] = (v >> 16) & 0xff;
			p[3] = (v >> 24) & 0xff;
			p[4] = (v >> 32) & 0xff;
			p[5] = (v >> 40) & 0xff;
			p[6] = (v >> 48) & 0xff;
			p[7] = (v >> 56) & 0xff;
		}

		inline uint64_t u8to64le(const uint8_t * p)
		{
			uint64_t i = 0;
			int idx = 0;
			while(idx < 8)
			{
				i |= ((uint64_t) p[idx]) << (idx * 8);
				++idx;
			}
			return i;
		}

		inline void round(uint64_t & _v0, uint64_t & _v1, uint64_t & _v2, uint64_t & _v3)
		{
			_v0 += _v1;
			_v1 = rotl(_v1, 13);
			_v1 ^= _v0;
			_v0 = rotl(_v0, 32);
			_v2 += _v3;
			_v3 = rotl(_v3, 16);
			_v3 ^= _v2;
			_v0 += _v3;
			_v3 = rotl(_v3, 21);
			_v3 ^= _v0;
			_v2 += _v1;
			_v1 = rotl(_v1, 17);
			_v1 ^= _v2;
			_v2 = rotl(_v2, 32);
		}
	}

	/** hashsz must be 8 or 16 */
	template<std::size_t hashsz>
	inline void Siphash(uint8_t * h, const uint8_t * buf, std::size_t bufsz, const uint8_t * key)
	{
		uint64_t v0 = 0x736f6d6570736575ULL;
		uint64_t v1 = 0x646f72616e646f6dULL;
		uint64_t v2 = 0x6c7967656e657261ULL;
		uint64_t v3 = 0x7465646279746573ULL;
		const uint64_t k0 = siphash::u8to64le(key);
		const uint64_t k1 = siphash::u8to64le(key + 8);
		uint64_t msg;
		int i;
		const uint8_t * end = buf + bufsz - (bufsz % sizeof(uint64_t));
		auto left = bufsz & 7;
		uint64_t b = ((uint64_t)bufsz) << 56;
		v3 ^= k1;
		v2 ^= k0;
		v1 ^= k1;
		v0 ^= k0;

		if(hashsz == 16) v1 ^= 0xee;

		while(buf != end)
		{
			msg = siphash::u8to64le(buf);
			v3 ^= msg;
			for(i = 0; i < siphash::crounds; ++i)
				siphash::round(v0, v1, v2, v3);

			v0 ^= msg;
			buf += 8;
		}

		while(left)
		{
			--left;
			b |= ((uint64_t)(buf[left])) << (left * 8);
		}

		v3 ^= b;

		for(i = 0; i < siphash::crounds; ++i)
			siphash::round(v0, v1, v2, v3);

		v0 ^= b;


		if(hashsz == 16)
			v2 ^= 0xee;
		else
			v2 ^= 0xff;

		for(i = 0; i < siphash::drounds; ++i)
			siphash::round(v0, v1, v2, v3);

		b = v0 ^ v1 ^ v2 ^ v3;

		siphash::u64to8le(b, h);

		if(hashsz == 8) return;

		v1 ^= 0xdd;

		for (i = 0; i < siphash::drounds; ++i)
			siphash::round(v0, v1, v2, v3);

		b = v0 ^ v1 ^ v2 ^ v3;
		siphash::u64to8le(b, h + 8);
	}
}
}
#endif

#endif
