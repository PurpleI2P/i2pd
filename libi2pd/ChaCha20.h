/*
* Copyright (c) 2013-2020, The PurpleI2P Project
*
* This file is part of Purple i2pd project and licensed under BSD3
*
* See full license text in LICENSE file at top of project tree
*
* Kovri go write your own code
*
*/
#ifndef LIBI2PD_CHACHA20_H
#define LIBI2PD_CHACHA20_H
#include <cstdint>
#include <cstring>
#include <inttypes.h>
#include <string.h>
#include "Crypto.h"

#if !OPENSSL_AEAD_CHACHA20_POLY1305
namespace i2p
{
namespace crypto
{
	const std::size_t CHACHA20_KEY_BYTES = 32;
	const std::size_t CHACHA20_NOUNCE_BYTES = 12;

namespace chacha
{
	constexpr std::size_t blocksize = 64;
	constexpr int rounds = 20;

	struct Chacha20State;
	struct Chacha20Block
	{
		Chacha20Block () {};
		Chacha20Block (Chacha20Block &&) = delete;

		uint8_t data[blocksize];

		void operator << (const Chacha20State & st);
	};

	struct Chacha20State
	{
		Chacha20State (): offset (0) {};
		Chacha20State (Chacha20State &&) = delete;

		Chacha20State & operator += (const Chacha20State & other)
		{
			for(int i = 0; i < 16; i++)
				data[i] += other.data[i];
			return *this;
		}

		void Copy(const Chacha20State & other)
		{
			memcpy(data, other.data, sizeof(uint32_t) * 16);
		}
		uint32_t data[16];
		Chacha20Block block;
		size_t offset;
	};

	void Chacha20Init (Chacha20State& state, const uint8_t * nonce, const uint8_t * key, uint32_t counter);
	void Chacha20SetCounter (Chacha20State& state, uint32_t counter);
	void Chacha20Encrypt (Chacha20State& state, uint8_t * buf, size_t sz); // encrypt buf in place
} // namespace chacha
} // namespace crypto
} // namespace i2p

#endif
#endif
