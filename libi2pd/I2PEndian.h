/*
* Copyright (c) 2013-2020, The PurpleI2P Project
*
* This file is part of Purple i2pd project and licensed under BSD3
*
* See full license text in LICENSE file at top of project tree
*/

#ifndef I2PENDIAN_H__
#define I2PENDIAN_H__
#include <inttypes.h>
#include <string.h>

#if defined(__FreeBSD__) || defined(__NetBSD__)
#include <sys/endian.h>
#elif defined(__linux__) || defined(__FreeBSD_kernel__) || defined(__OpenBSD__) || defined(__GLIBC__)
#include <endian.h>
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
#define NEEDS_LOCAL_ENDIAN
#include <cstdint>
uint16_t htobe16(uint16_t int16);
uint32_t htobe32(uint32_t int32);
uint64_t htobe64(uint64_t int64);

uint16_t be16toh(uint16_t big16);
uint32_t be32toh(uint32_t big32);
uint64_t be64toh(uint64_t big64);

// assume LittleEndine
#define htole16
#define htole32
#define htole64
#define le16toh
#define le32toh
#define le64toh

#endif

inline uint16_t buf16toh(const void *buf)
{
	uint16_t b16;
	memcpy(&b16, buf, sizeof(uint16_t));
	return b16;
}

inline uint32_t buf32toh(const void *buf)
{
	uint32_t b32;
	memcpy(&b32, buf, sizeof(uint32_t));
	return b32;
}

inline uint64_t buf64toh(const void *buf)
{
	uint64_t b64;
	memcpy(&b64, buf, sizeof(uint64_t));
	return b64;
}

inline uint16_t bufbe16toh(const void *buf)
{
	return be16toh(buf16toh(buf));
}

inline uint32_t bufbe32toh(const void *buf)
{
	return be32toh(buf32toh(buf));
}

inline uint64_t bufbe64toh(const void *buf)
{
	return be64toh(buf64toh(buf));
}

inline void htobuf16(void *buf, uint16_t b16)
{
	memcpy(buf, &b16, sizeof(uint16_t));
}

inline void htobuf32(void *buf, uint32_t b32)
{
	memcpy(buf, &b32, sizeof(uint32_t));
}

inline void htobuf64(void *buf, uint64_t b64)
{
	memcpy(buf, &b64, sizeof(uint64_t));
}

inline void htobe16buf(void *buf, uint16_t big16)
{
	htobuf16(buf, htobe16(big16));
}

inline void htobe32buf(void *buf, uint32_t big32)
{
	htobuf32(buf, htobe32(big32));
}

inline void htobe64buf(void *buf, uint64_t big64)
{
	htobuf64(buf, htobe64(big64));
}

inline void htole16buf(void *buf, uint16_t big16)
{
	htobuf16(buf, htole16(big16));
}

inline void htole32buf(void *buf, uint32_t big32)
{
	htobuf32(buf, htole32(big32));
}

inline void htole64buf(void *buf, uint64_t big64)
{
	htobuf64(buf, htole64(big64));
}

inline uint16_t bufle16toh(const void *buf)
{
	return le16toh(buf16toh(buf));
}

inline uint32_t bufle32toh(const void *buf)
{
	return le32toh(buf32toh(buf));
}

inline uint64_t bufle64toh(const void *buf)
{
	return le64toh(buf64toh(buf));
}

#endif // I2PENDIAN_H__

