/*
* Copyright (c) 2013-2020, The PurpleI2P Project
*
* This file is part of Purple i2pd project and licensed under BSD3
*
* See full license text in LICENSE file at top of project tree
*/

#include "I2PEndian.h"

// http://habrahabr.ru/post/121811/
// http://codepad.org/2ycmkz2y

#include "LittleBigEndian.h"

#ifdef NEEDS_LOCAL_ENDIAN
uint16_t htobe16(uint16_t int16)
{
	BigEndian<uint16_t> u16(int16);
	return u16.raw_value;
}

uint32_t htobe32(uint32_t int32)
{
	BigEndian<uint32_t> u32(int32);
	return u32.raw_value;
}

uint64_t htobe64(uint64_t int64)
{
	BigEndian<uint64_t> u64(int64);
	return u64.raw_value;
}

uint16_t be16toh(uint16_t big16)
{
	LittleEndian<uint16_t> u16(big16);
	return u16.raw_value;
}

uint32_t be32toh(uint32_t big32)
{
	LittleEndian<uint32_t> u32(big32);
	return u32.raw_value;
}

uint64_t be64toh(uint64_t big64)
{
	LittleEndian<uint64_t> u64(big64);
	return u64.raw_value;
}
#endif

/* it can be used in Windows 8
#include <Winsock2.h>

uint16_t htobe16(uint16_t int16)
{
	return htons(int16);
}

uint32_t htobe32(uint32_t int32)
{
	return htonl(int32);
}

uint64_t htobe64(uint64_t int64)
{
	// http://msdn.microsoft.com/en-us/library/windows/desktop/jj710199%28v=vs.85%29.aspx
	//return htonll(int64);
	return 0;
}


uint16_t be16toh(uint16_t big16)
{
	return ntohs(big16);
}

uint32_t be32toh(uint32_t big32)
{
	return ntohl(big32);
}

uint64_t be64toh(uint64_t big64)
{
	// http://msdn.microsoft.com/en-us/library/windows/desktop/jj710199%28v=vs.85%29.aspx
	//return ntohll(big64);
	return 0;
}
*/