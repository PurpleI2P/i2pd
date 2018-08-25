/**
   This code is licensed under the MCGSI Public License
   Copyright 2018 Jeff Becker

   Kovri go write your own code

 */
#ifndef LIBI2PD_POLY1305_H
#define LIBI2PD_POLY1305_H
#include <cstdint>
#include <cstring>

namespace i2p
{
namespace crypto
{
  const std::size_t POLY1305_DIGEST_BYTES = 16;
  const std::size_t POLY1305_DIGEST_DWORDS = 4;
  const std::size_t POLY1305_KEY_BYTES = 32;
  const std::size_t POLY1305_KEY_DWORDS = 8;
  const std::size_t POLY1305_BLOCK_BYTES = 16;

  void Poly1305HMAC(uint32_t * out, const uint32_t * key, const uint8_t * buf, std::size_t sz);
  
}
}

#endif
