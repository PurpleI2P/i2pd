/*
* Copyright (c) 2013-2025, The PurpleI2P Project
*
* This file is part of Purple i2pd project and licensed under BSD3
*
* See full license text in LICENSE file at top of project tree
*/

#include <stdlib.h>
#include <string.h>

#include "Base.h"

namespace i2p
{
namespace data
{
	static constexpr char T32[32] =
	{
		'a', 'b', 'c', 'd', 'e', 'f', 'g', 'h',
		'i', 'j', 'k', 'l', 'm', 'n', 'o', 'p',
		'q', 'r', 's', 't', 'u', 'v', 'w', 'x',
		'y', 'z', '2', '3', '4', '5', '6', '7',
	};

	const char * GetBase32SubstitutionTable ()
	{
		return T32;
	}
	
	static void iT64Build(void);

	/*
	*
	* BASE64 Substitution Table
	* -------------------------
	*
	* Direct Substitution Table
	*/

	static constexpr char T64[64] =
	{
		'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H',
		'I', 'J', 'K', 'L', 'M', 'N', 'O', 'P',
		'Q', 'R', 'S', 'T', 'U', 'V', 'W', 'X',
		'Y', 'Z', 'a', 'b', 'c', 'd', 'e', 'f',
		'g', 'h', 'i', 'j', 'k', 'l', 'm', 'n',
		'o', 'p', 'q', 'r', 's', 't', 'u', 'v',
		'w', 'x', 'y', 'z', '0', '1', '2', '3',
		'4', '5', '6', '7', '8', '9', '-', '~'
	};

	const char * GetBase64SubstitutionTable ()
	{
		return T64;
	}
	
	/*
	* Reverse Substitution Table (built in run time)
	*/
	static char iT64[256];
	static int isFirstTime = 1;

	/*
	* Padding
	*/
	static constexpr char P64 = '=';

	/*
	*
	* ByteStreamToBase64
	* ------------------
	*
	* Converts binary encoded data to BASE64 format.
	*
	*/
	std::string ByteStreamToBase64 (// base64 encoded string 
		const uint8_t * InBuffer, 	// Input buffer, binary data 
	    size_t InCount 				// Number of bytes in the input buffer 
	)
	{
		unsigned char * ps;
		unsigned char   acc_1;
		unsigned char   acc_2;
		int             i;
		int             n;
		int             m;

		ps = (unsigned char *)InBuffer;
		n = InCount / 3;
		m = InCount % 3;
		size_t outCount = m ? (4 * (n + 1)) : (4 * n);

		std::string out;
		out.reserve (outCount);
		for ( i = 0; i < n; i++ )
		{
			acc_1 = *ps++;
			acc_2 = (acc_1 << 4) & 0x30;
			acc_1 >>= 2;                 // base64 digit #1 
			out.push_back (T64[acc_1]);
			acc_1 = *ps++;
			acc_2 |= acc_1 >> 4;         // base64 digit #2
			out.push_back (T64[acc_2]);
			acc_1 &= 0x0f;
			acc_1 <<= 2;
			acc_2 = *ps++;
			acc_1 |= acc_2 >> 6;         // base64 digit #3
			out.push_back (T64[acc_1]);
			acc_2 &= 0x3f;               // base64 digit #4
			out.push_back (T64[acc_2]);
		}
		if ( m == 1 )
		{
			acc_1 = *ps++;
			acc_2 = (acc_1 << 4) & 0x3f; // base64 digit #2
			acc_1 >>= 2;                 // base64 digit #1
			out.push_back (T64[acc_1]);
			out.push_back (T64[acc_2]);
			out.push_back (P64);
			out.push_back (P64);

		}
		else if ( m == 2 )
		{
			acc_1 = *ps++;
			acc_2 = (acc_1 << 4) & 0x3f;
			acc_1 >>= 2;                 // base64 digit #1
			out.push_back (T64[acc_1]);
			acc_1 = *ps++;
			acc_2 |= acc_1 >> 4;         // base64 digit #2
			out.push_back (T64[acc_2]);
			acc_1 &= 0x0f;
			acc_1 <<= 2;                 // base64 digit #3
			out.push_back (T64[acc_1]);
			out.push_back (P64);
		}

		return out;
	}	
	
	/*
	*
	* Base64ToByteStream
	* ------------------
	*
	* Converts BASE64 encoded string to binary format. If input buffer is
	* not properly padded, buffer of negative length is returned
	*
	*/
	size_t Base64ToByteStream (		// Number of output bytes 
		std::string_view base64Str,	// BASE64 encoded string  
	    uint8_t * OutBuffer, 		// output buffer length 
	    size_t len					// length of output buffer 
	)
	{
		unsigned char * pd;
		unsigned char   acc_1;
		unsigned char   acc_2;
		size_t          outCount;

		if (base64Str.empty () || base64Str[0] == P64) return 0;
		auto d = std::div (base64Str.length (), 4);
		if (!d.rem)
			outCount = 3 * d.quot;
		else
			return 0;

		if (isFirstTime) iT64Build();

		auto pos = base64Str.find_last_not_of (P64);
		if (pos == base64Str.npos) return 0;
		outCount -= (base64Str.length () - pos - 1);
		if (outCount > len) return 0;
		
		auto ps = base64Str.begin ();
		pd = OutBuffer;
		auto endOfOutBuffer = OutBuffer + outCount;
		for (int i = 0; i < d.quot; i++)
		{
			acc_1 = iT64[int(*ps++)];
			acc_2 = iT64[int(*ps++)];
			acc_1 <<= 2;
			acc_1 |= acc_2 >> 4;
			*pd++ = acc_1;
			if (pd >= endOfOutBuffer)
				break;

			acc_2 <<= 4;
			acc_1 = iT64[int(*ps++)];
			acc_2 |= acc_1 >> 2;
			*pd++ = acc_2;
			if (pd >= endOfOutBuffer)
				break;

			acc_2 = iT64[int(*ps++)];
			acc_2 |= acc_1 << 6;
			*pd++ = acc_2;
		}

		return outCount;
	}	
	
	std::string ToBase64Standard (std::string_view in)
	{
		auto str = ByteStreamToBase64 ((const uint8_t *)in.data (), in.length ());
		// replace '-' by '+' and '~' by '/'
		for (auto& ch: str)
			if (ch == '-')
				ch = '+';
			else if (ch == '~')
				ch = '/';
		return str;
	}

	/*
	*
	* iT64
	* ----
	* Reverse table builder. P64 character is replaced with 0
	*
	*
	*/

	static void iT64Build()
	{
		int i;
		isFirstTime = 0;
		for ( i = 0; i < 256; i++ ) iT64[i] = -1;
		for ( i = 0; i < 64; i++ ) iT64[(int)T64[i]] = i;
		iT64[(int)P64] = 0;
	}

	size_t Base32ToByteStream (std::string_view base32Str, uint8_t * outBuf, size_t outLen)
	{
		unsigned int tmp = 0, bits = 0;
		size_t ret = 0;
		for (auto ch: base32Str)
		{
			if (ch >= '2' && ch <= '7') // digit
				ch = (ch - '2') + 26; // 26 means a-z
			else if (ch >= 'a' && ch <= 'z')
				ch = ch - 'a'; // a = 0
			else
				return 0; // unexpected character

			tmp |= ch;
			bits += 5;
			if (bits >= 8)
			{
				if (ret >= outLen) return ret;
				outBuf[ret] = tmp >> (bits - 8);
				bits -= 8;
				ret++;
			}
			tmp <<= 5;
		}
		return ret;
	}	
	
	std::string ByteStreamToBase32 (const uint8_t * inBuf, size_t len)
	{
		std::string out;
		out.reserve ((len * 8 + 4) / 5);
		size_t pos = 1;
		unsigned int bits = 8, tmp = inBuf[0];
		while (bits > 0 || pos < len)
		{
			if (bits < 5)
			{
				if (pos < len)
				{
					tmp <<= 8;
					tmp |= inBuf[pos] & 0xFF;
					pos++;
					bits += 8;
				}
				else // last byte
				{
					tmp <<= (5 - bits);
					bits = 5;
				}
			}

			bits -= 5;
			int ind = (tmp >> bits) & 0x1F;
			out.push_back ((ind < 26) ? (ind + 'a') : ((ind - 26) + '2'));
		}
		return out;
	}	
}
}
