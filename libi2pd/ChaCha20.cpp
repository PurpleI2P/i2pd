#include "ChaCha20.h"

/**
   This code is licensed under the MCGSI Public License
   Copyright 2018 Jeff Becker

   Kovri go write your own code

 */
namespace i2p
{
namespace crypto
{
namespace chacha
{
constexpr int rounds = 20;
constexpr std::size_t blocksize = 64;

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

    struct State_t
    {
      State_t() {};
      State_t(State_t &&) = delete;
      
      State_t & operator += (const State_t & other)
      {
        for(int i = 0; i < 16; i++)
            data[i] += other.data[i];
        return *this;
      }

      void Copy(const State_t & other)
      {
           memcpy(data, other.data, sizeof(uint32_t) * 16);
      }
      uint32_t data[16];
    };

    struct Block_t
    {
      Block_t() {};
      Block_t(Block_t &&) = delete;

      uint8_t data[blocksize];

      void operator << (const State_t & st)
      {
        int i;
        for (i = 0; i < 16; i++) 
            u32t8le(st.data[i], data + (i << 2));
      }
    };

void block(const State_t &input, Block_t & block, int rounds)
{
    int i;
    State_t x;
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
    block << x;

}
} // namespace chacha





void chacha20(uint8_t * buf, size_t sz, const uint8_t * nonce, const uint8_t * key, uint32_t counter)
{
    chacha::State_t state;
    chacha::Block_t block;
    size_t i, j;

    state.data[0] = 0x61707865;
    state.data[1] = 0x3320646e;
    state.data[2] = 0x79622d32;
    state.data[3] = 0x6b206574;

    for (i = 0; i < 8; i++) 
        state.data[4 + i] = chacha::u8t32le(key + i * 4);
    

    state.data[12] = counter;

    for (i = 0; i < 3; i++) 
        state.data[13 + i] = chacha::u8t32le(nonce + i * 4);

    
    for (i = 0; i < sz; i += chacha::blocksize) 
    {
        chacha::block(state, block, chacha::rounds);
        state.data[12]++;
        for (j = i; j < i + chacha::blocksize; j++) 
        {
            if (j >= sz) break;
            buf[j] ^= block.data[j - i];
        }
    }

}

}
}