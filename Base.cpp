#include <stdlib.h>
#include "Log.h"
#include "Base.h"

namespace i2p
{
namespace data
{
	static void iT64Build(void);

	/*
	*
	* BASE64 Substitution Table
	* -------------------------
	*
	* Direct Substitution Table
	*/

	static char T64[64] = { 
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

	static char P64 = '='; 

	/*
	*
	* ByteStreamToBase64
	* ------------------
	*
	* Converts binary encoded data to BASE64 format.
	*
	*/

	size_t                                /* Number of bytes in the encoded buffer */
	ByteStreamToBase64 ( 
		    const uint8_t * InBuffer,           /* Input buffer, binary data */
		    size_t    InCount,              /* Number of bytes in the input buffer */ 
		    char  * OutBuffer,          /* output buffer */
		size_t len			   /* length of output buffer */	             
	)

	{
		unsigned char * ps;
		unsigned char * pd;
		unsigned char   acc_1;
		unsigned char   acc_2;
		int             i; 
		int             n; 
		int             m; 
		size_t outCount;

		ps = (unsigned char *)InBuffer;
		n = InCount/3;
		m = InCount%3;
		if (!m)
		     outCount = 4*n;
		else
		     outCount = 4*(n+1);
		if (outCount > len) return 0;
		pd = (unsigned char *)OutBuffer;
		for ( i = 0; i<n; i++ ){
		     acc_1 = *ps++;
		     acc_2 = (acc_1<<4)&0x30; 
		     acc_1 >>= 2;              /* base64 digit #1 */
		     *pd++ = T64[acc_1];
		     acc_1 = *ps++;
		     acc_2 |= acc_1 >> 4;      /* base64 digit #2 */
		     *pd++ = T64[acc_2];
		     acc_1 &= 0x0f;
		     acc_1 <<=2;
		     acc_2 = *ps++;
		     acc_1 |= acc_2>>6;        /* base64 digit #3 */
		     *pd++ = T64[acc_1];
		     acc_2 &= 0x3f;            /* base64 digit #4 */
		     *pd++ = T64[acc_2];
		} 
		if ( m == 1 ){
		     acc_1 = *ps++;
		     acc_2 = (acc_1<<4)&0x3f;  /* base64 digit #2 */
		     acc_1 >>= 2;              /* base64 digit #1 */
		     *pd++ = T64[acc_1];
		     *pd++ = T64[acc_2];
		     *pd++ = P64;
		     *pd++ = P64;

		}
		else if ( m == 2 ){
		     acc_1 = *ps++;
		     acc_2 = (acc_1<<4)&0x3f; 
		     acc_1 >>= 2;              /* base64 digit #1 */
		     *pd++ = T64[acc_1];
		     acc_1 = *ps++;
		     acc_2 |= acc_1 >> 4;      /* base64 digit #2 */
		     *pd++ = T64[acc_2];
		     acc_1 &= 0x0f;
		     acc_1 <<=2;               /* base64 digit #3 */
		     *pd++ = T64[acc_1];
		     *pd++ = P64;
		}
		
		return outCount;
	}

	/*
	*
	* Base64ToByteStream
	* ------------------
	*
	* Converts BASE64 encoded data to binary format. If input buffer is
	* not properly padded, buffer of negative length is returned
	*
	*/

	size_t                              /* Number of output bytes */
	Base64ToByteStream ( 
		      const char * InBuffer,           /* BASE64 encoded buffer */
		      size_t    InCount,          /* Number of input bytes */
		      uint8_t  * OutBuffer,	/* output buffer length */ 	
		  size_t len         	/* length of output buffer */
	)
	{
		unsigned char * ps;
		unsigned char * pd;
		unsigned char   acc_1;
		unsigned char   acc_2;
		int             i; 
		int             n; 
		int             m; 
		size_t outCount;

		if (isFirstTime) iT64Build();
		n = InCount/4;
		m = InCount%4;
		if (InCount && !m) 
		     outCount = 3*n;
		else {
		     outCount = 0;
		     return 0;
		}
		
		ps = (unsigned char *)(InBuffer + InCount - 1);
		while ( *ps-- == P64 ) outCount--;
		ps = (unsigned char *)InBuffer;
		
		if (outCount > len) return -1;
		pd = OutBuffer;
		auto endOfOutBuffer = OutBuffer + outCount;		
		for ( i = 0; i < n; i++ ){
		     acc_1 = iT64[*ps++];
		     acc_2 = iT64[*ps++];
		     acc_1 <<= 2;
		     acc_1 |= acc_2>>4;
		     *pd++  = acc_1;
			 if (pd >= endOfOutBuffer) break;

		     acc_2 <<= 4;
		     acc_1 = iT64[*ps++];
		     acc_2 |= acc_1 >> 2;
		     *pd++ = acc_2;
			  if (pd >= endOfOutBuffer) break;	

		     acc_2 = iT64[*ps++];
		     acc_2 |= acc_1 << 6;
		     *pd++ = acc_2;
		}

		return outCount;
	}

	size_t Base64EncodingBufferSize (const size_t input_size) 
	{
		auto d = div (input_size, 3);
		if (d.rem) d.quot++;
		return 4*d.quot;
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
		int  i;
		isFirstTime = 0;
		for ( i=0; i<256; i++ ) iT64[i] = -1;
		for ( i=0; i<64; i++ ) iT64[(int)T64[i]] = i;
		iT64[(int)P64] = 0;
	}

	size_t Base32ToByteStream (const char * inBuf, size_t len, uint8_t * outBuf, size_t outLen) 
	{
		int tmp = 0, bits = 0;
		size_t ret = 0;
		for (size_t i = 0; i < len; i++)
		{
			char ch = inBuf[i];	
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

	size_t ByteStreamToBase32 (const uint8_t * inBuf, size_t len, char * outBuf, size_t outLen)
	{
		size_t ret = 0, pos = 1;
		int bits = 8, tmp = inBuf[0];
		while (ret < outLen && (bits > 0 || pos < len))
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
			outBuf[ret] = (ind < 26) ? (ind + 'a') : ((ind - 26) + '2');
			ret++;
		}
		return ret;
	}

	GzipInflator::GzipInflator (): m_IsDirty (false)
	{
		memset (&m_Inflator, 0, sizeof (m_Inflator));
		inflateInit2 (&m_Inflator, MAX_WBITS + 16); // gzip
	}
	
	GzipInflator::~GzipInflator ()
	{
		inflateEnd (&m_Inflator);
	}	

	size_t GzipInflator::Inflate (const uint8_t * in, size_t inLen, uint8_t * out, size_t outLen)
	{
		if (m_IsDirty) inflateReset (&m_Inflator);
		m_IsDirty = true;
		m_Inflator.next_in = const_cast<uint8_t *>(in);
		m_Inflator.avail_in = inLen;
		m_Inflator.next_out = out;
		m_Inflator.avail_out = outLen;
		int err;
		if ((err = inflate (&m_Inflator, Z_NO_FLUSH)) == Z_STREAM_END)
			return outLen - m_Inflator.avail_out;	
		else
		{
			LogPrint (eLogError, "Decompression error ", err);
			return 0;
		}	
	}	

	bool GzipInflator::Inflate (const uint8_t * in, size_t inLen, std::ostream& s)
	{
		m_IsDirty = true;
		uint8_t * out = new uint8_t[GZIP_CHUNK_SIZE];
		m_Inflator.next_in = const_cast<uint8_t *>(in);
		m_Inflator.avail_in = inLen;	
		int ret;
		do
		{
			m_Inflator.next_out = out;
			m_Inflator.avail_out = GZIP_CHUNK_SIZE;
			ret = inflate (&m_Inflator, Z_NO_FLUSH);
			if (ret < 0)
			{
				LogPrint (eLogError, "Decompression error ", ret);
				inflateEnd (&m_Inflator);
				s.setstate(std::ios_base::failbit);
				break;
			}	
			else
				s.write ((char *)out, GZIP_CHUNK_SIZE - m_Inflator.avail_out);
		}
		while (!m_Inflator.avail_out); // more data to read
		delete[] out;
		return ret == Z_STREAM_END || ret < 0;
	}

	void GzipInflator::Inflate (std::istream& in, std::ostream& out)
	{
		uint8_t * buf = new uint8_t[GZIP_CHUNK_SIZE];
		while (!in.eof ())
		{
			in.read ((char *)buf, GZIP_CHUNK_SIZE);
			Inflate (buf, in.gcount (), out); 
		}	
		delete[] buf;
	}

	GzipDeflator::GzipDeflator (): m_IsDirty (false)
	{
		memset (&m_Deflator, 0, sizeof (m_Deflator));
		deflateInit2 (&m_Deflator, Z_DEFAULT_COMPRESSION, Z_DEFLATED, 15 + 16, 8, Z_DEFAULT_STRATEGY); // 15 + 16 sets gzip
	}
	
	GzipDeflator::~GzipDeflator ()
	{
		deflateEnd (&m_Deflator);
	}	

	void GzipDeflator::SetCompressionLevel (int level)
	{
		deflateParams (&m_Deflator, level, Z_DEFAULT_STRATEGY);
	}	
	
	size_t GzipDeflator::Deflate (const uint8_t * in, size_t inLen, uint8_t * out, size_t outLen)
	{
		if (m_IsDirty) deflateReset (&m_Deflator);
		m_IsDirty = true;
		m_Deflator.next_in = const_cast<uint8_t *>(in);
		m_Deflator.avail_in = inLen;
		m_Deflator.next_out = out;
		m_Deflator.avail_out = outLen;
		int err;
		if ((err = deflate (&m_Deflator, Z_FINISH)) == Z_STREAM_END) 
			return outLen - m_Deflator.avail_out;	
		else
		{
			LogPrint (eLogError, "Compression error ", err);
			return 0;
		}	
	}
}
}

