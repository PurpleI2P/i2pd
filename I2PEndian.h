#ifndef I2PENDIAN_H__
#define I2PENDIAN_H__

#if defined(__linux__) || defined(__FreeBSD_kernel__)
#include <endian.h>
#elif __FreeBSD__
#include <sys/endian.h>
#elif defined(__APPLE__) && defined(__MACH__)

#include <libkern/OSByteOrder.h>

#define htobe16(x) OSSwapHostToBigInt16(x)
#define htole16(x) OSSwapHostToLittleInt16(x)
#define be16toh(x) OSSwapBigToHostInt16(x)
#define le16toh(x) OSSwapLittleToHostInt16(x)

#define htobe32(x) OSSwapHostToBigInt32(x)
#define htole32(x) OSSwapHostToLittleInt32(x)
#define be32toh(x) OSSwapBigToHostInt32(x)
#define le32toh(x) OSSwapLittleToHostInt32(x)

#define htobe64(x) OSSwapHostToBigInt64(x)
#define htole64(x) OSSwapHostToLittleInt64(x)
#define be64toh(x) OSSwapBigToHostInt64(x)
#define le64toh(x) OSSwapLittleToHostInt64(x)

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

