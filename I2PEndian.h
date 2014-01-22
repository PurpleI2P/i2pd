#ifndef I2PENDIAN_H__
#define I2PENDIAN_H__

#ifndef _WIN32
#include <endian.h>
#else
#include <cstdint>
//
//uint16_t htobe16(uint16_t int16);
//uint32_t htobe32(uint32_t int32);
//uint64_t htobe64(uint64_t int64);
//
//uint16_t be16toh(uint16_t big16);
//uint32_t be32toh(uint32_t big32);
//uint64_t be64toh(uint64_t big64);

#include "portable_endian.h"

#endif

#endif // I2PENDIAN_H__