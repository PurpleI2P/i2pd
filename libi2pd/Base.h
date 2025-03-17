/*
* Copyright (c) 2013-2025, The PurpleI2P Project
*
* This file is part of Purple i2pd project and licensed under BSD3
*
* See full license text in LICENSE file at top of project tree
*/

#ifndef BASE_H__
#define BASE_H__

#include <inttypes.h>
#include <string>
#include <string_view>
#include <cstdlib>

namespace i2p 
{
namespace data 
{
	std::string ByteStreamToBase64 (const uint8_t * InBuffer, size_t InCount);
	size_t Base64ToByteStream (std::string_view base64Str, uint8_t * OutBuffer, size_t len);

	const char * GetBase32SubstitutionTable ();
	const char * GetBase64SubstitutionTable ();
	constexpr bool IsBase64 (char ch)
	{
		return (ch >= 'A' && ch <= 'Z') || (ch >= 'a' && ch <= 'z') || (ch >= '0' && ch <= '9') || ch == '-' || ch == '~';
	}	

	size_t Base32ToByteStream (std::string_view base32Str, uint8_t * outBuf, size_t outLen);
	std::string ByteStreamToBase32 (const uint8_t * inBuf, size_t len);	
	constexpr bool IsBase32 (char ch)
	{
		return (ch >= 'a' && ch <= 'z') || (ch >= '2' && ch <= '7');
	}	

	/**
	 * Compute the size for a buffer to contain encoded base64 given that the size of the input is input_size bytes
	 */
	inline size_t Base64EncodingBufferSize(size_t input_size)
	{
		auto d = std::div (input_size, 3);
		if (d.rem) d.quot++;
		return 4 * d.quot;
	}	

	std::string ToBase64Standard (std::string_view in); // using standard table, for Proxy-Authorization
	
} // data
} // i2p

#endif
