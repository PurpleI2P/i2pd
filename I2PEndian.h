#ifndef I2PENDIAN_H__
#define I2PENDIAN_H__

#ifdef __linux__
#include <endian.h>
#elif __FreeBSD__
#include <sys/endian.h>
#elif __MACH__ // Mac OS X
#include <machine/endian.h>
#else
#include <cstdint>

uint16_t htobe16(uint16_t int16);
uint32_t htobe32(uint32_t int32);
uint64_t htobe64(uint64_t int64);

uint16_t be16toh(uint16_t big16);
uint32_t be32toh(uint32_t big32);
uint64_t be64toh(uint64_t big64);

#endif

#endif // I2PENDIAN_H__