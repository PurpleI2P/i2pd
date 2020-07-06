/*
* Copyright (c) 2013-2020, The PurpleI2P Project
*
* This file is part of Purple i2pd project and licensed under BSD3
*
* See full license text in LICENSE file at top of project tree
*/

#ifndef BASE_H__
#define BASE_H__

#include <inttypes.h>
#include <string>
#include <iostream>

namespace i2p {
namespace data {
	size_t ByteStreamToBase64 (const uint8_t * InBuffer, size_t InCount, char * OutBuffer, size_t len);
	size_t Base64ToByteStream (const char * InBuffer, size_t InCount, uint8_t * OutBuffer, size_t len );
	const char * GetBase32SubstitutionTable ();
	const char * GetBase64SubstitutionTable ();

	size_t Base32ToByteStream (const char * inBuf, size_t len, uint8_t * outBuf, size_t outLen);
	size_t ByteStreamToBase32 (const uint8_t * InBuf, size_t len, char * outBuf, size_t outLen);

	/**
	 Compute the size for a buffer to contain encoded base64 given that the size of the input is input_size bytes
	*/
	size_t Base64EncodingBufferSize(const size_t input_size);

	std::string ToBase64Standard (const std::string& in); // using standard table, for Proxy-Authorization

} // data
} // i2p

#endif
