/**
   This code is licensed under the MCGSI Public License
   Copyright 2018 Jeff Becker

   Kovri go write your own code

 */
#ifndef LIBI2PD_CHACHA20_H
#define LIBI2PD_CHACHA20_H
#include <cstdint>
#include <cstring>

namespace i2p
{
namespace crypto
{
  const std::size_t CHACHA20_KEY_BYTES = 32;
  const std::size_t CHACHA20_NOUNCE_BYTES = 12;

  /** encrypt buf in place with chacha20 */
  void chacha20(uint8_t * buf, size_t sz, const uint8_t * nonce, const uint8_t * key, uint32_t counter=1);

}
}

#endif
