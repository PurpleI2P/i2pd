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

#include "I2PEndian.h"
#include "ChaCha20.h"

#if !OPENSSL_AEAD_CHACHA20_POLY1305
namespace i2p
{
namespace crypto
{
namespace chacha
{
void u32t8le(uint32_t v, uint8_t * p)
{
	p[0] = v & 0xff;
	p[1] = (v >> 8) & 0xff;
	p[2] = (v >> 16) & 0xff;
	p[3] = (v >> 24) & 0xff;
}

uint32_t u8t32le(const uint8_t * p)
{
	uint32_t value = p[3];

	value = (value << 8) | p[2];
	value = (value << 8) | p[1];
	value = (value << 8) | p[0];

	return value;
}

uint32_t rotl32(uint32_t x, int n)
{
	return x << n | (x >> (-n & 31));
}

void quarterround(uint32_t *x, int a, int b, int c, int d)
{
	x[a] += x[b]; x[d] = rotl32(x[d] ^ x[a], 16);
	x[c] += x[d]; x[b] = rotl32(x[b] ^ x[c], 12);
	x[a] += x[b]; x[d] = rotl32(x[d] ^ x[a],  8);
	x[c] += x[d]; x[b] = rotl32(x[b] ^ x[c],  7);
}


void Chacha20Block::operator << (const Chacha20State & st)
{
	int i;
	for (i = 0; i < 16; i++)
		u32t8le(st.data[i], data + (i << 2));
}

void block (Chacha20State &input, int rounds)
{
	int i;
	Chacha20State x;
	x.Copy(input);

	for (i = rounds; i > 0; i -= 2)
	{
		quarterround(x.data, 0, 4,  8, 12);
		quarterround(x.data, 1, 5,  9, 13);
		quarterround(x.data, 2, 6, 10, 14);
		quarterround(x.data, 3, 7, 11, 15);
		quarterround(x.data, 0, 5, 10, 15);
		quarterround(x.data, 1, 6, 11, 12);
		quarterround(x.data, 2, 7,  8, 13);
		quarterround(x.data, 3, 4,  9, 14);
	}
	x += input;
	input.block << x;
}

void Chacha20Init (Chacha20State& state, const uint8_t * nonce, const uint8_t * key, uint32_t counter)
{
	state.data[0] = 0x61707865;
	state.data[1] = 0x3320646e;
	state.data[2] = 0x79622d32;
	state.data[3] = 0x6b206574;
	for (size_t i = 0; i < 8; i++)
		state.data[4 + i] = chacha::u8t32le(key + i * 4);

	state.data[12] = htole32 (counter);
	for (size_t i = 0; i < 3; i++)
		state.data[13 + i] = chacha::u8t32le(nonce + i * 4);
}

void Chacha20SetCounter (Chacha20State& state, uint32_t counter)
{
	state.data[12] = htole32 (counter);
	state.offset = 0;
}

void Chacha20Encrypt (Chacha20State& state, uint8_t * buf, size_t sz)
{
	if (state.offset > 0)
	{
		// previous block if any
		auto s = chacha::blocksize - state.offset;
		if (sz < s) s = sz;
		for (size_t i = 0; i < s; i++)
			buf[i] ^= state.block.data[state.offset + i];
		buf += s;
		sz -= s;
		state.offset += s;
		if (state.offset >= chacha::blocksize) state.offset = 0;
	}
	for (size_t i = 0; i < sz; i += chacha::blocksize)
	{
		chacha::block(state, chacha::rounds);
		state.data[12]++;
		for (size_t j = i; j < i + chacha::blocksize; j++)
		{
			if (j >= sz)
			{
				state.offset = j & 0x3F; // % 64
				break;
			}
			buf[j] ^= state.block.data[j - i];
		}
	}
}

} // namespace chacha
} // namespace crypto
} // namespace i2p

#endif
