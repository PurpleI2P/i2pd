#ifndef BASE_H__
#define BASE_H__

#include <inttypes.h>
#include <string.h>
#include <string>
#include <zlib.h>
#include <iostream>
#include <sstream>

namespace i2p
{
namespace data
{
	size_t ByteStreamToBase64 (const uint8_t * InBuffer, size_t InCount, char * OutBuffer, size_t len);
	size_t Base64ToByteStream (const char * InBuffer, size_t InCount, uint8_t * OutBuffer, size_t len );
	const char * GetBase64SubstitutionTable ();	
	
	size_t Base32ToByteStream (const char * inBuf, size_t len, uint8_t * outBuf, size_t outLen);
	size_t ByteStreamToBase32 (const uint8_t * InBuf, size_t len, char * outBuf, size_t outLen);

  /**
     Compute the size for a buffer to contain encoded base64 given that the size of the input is input_size bytes
   */
  size_t Base64EncodingBufferSize(const size_t input_size);
  
	template<int sz>
	class Tag
	{
		public:

			Tag (const uint8_t * buf) { memcpy (m_Buf, buf, sz); };
			Tag (const Tag<sz>& ) = default;
#ifndef _WIN32 // FIXME!!! msvs 2013 can't compile it
			Tag (Tag<sz>&& ) = default;
#endif
			Tag () = default;
			
			Tag<sz>& operator= (const Tag<sz>& ) = default;
#ifndef _WIN32
			Tag<sz>& operator= (Tag<sz>&& ) = default;
#endif
			
			uint8_t * operator()() { return m_Buf; };
			const uint8_t * operator()() const { return m_Buf; };

			operator uint8_t * () { return m_Buf; };
			operator const uint8_t * () const { return m_Buf; };
			
			const uint64_t * GetLL () const { return ll; };

			bool operator== (const Tag<sz>& other) const { return !memcmp (m_Buf, other.m_Buf, sz); };
			bool operator< (const Tag<sz>& other) const { return memcmp (m_Buf, other.m_Buf, sz) < 0; };

			bool IsZero () const
			{
				for (int i = 0; i < sz/8; i++)
					if (ll[i]) return false;
				return true;
			}
			
			std::string ToBase64 () const
			{
				char str[sz*2];
				int l = i2p::data::ByteStreamToBase64 (m_Buf, sz, str, sz*2);
				str[l] = 0;
				return std::string (str);
			}

			std::string ToBase32 () const
			{
				char str[sz*2];
				int l = i2p::data::ByteStreamToBase32 (m_Buf, sz, str, sz*2);
				str[l] = 0;
				return std::string (str);
			}	

			void FromBase32 (const std::string& s)
			{
				i2p::data::Base32ToByteStream (s.c_str (), s.length (), m_Buf, sz);
			}

			void FromBase64 (const std::string& s)
			{
				i2p::data::Base64ToByteStream (s.c_str (), s.length (), m_Buf, sz);
			}

		private:

			union // 8 bytes alignment
			{	
				uint8_t m_Buf[sz];
				uint64_t ll[sz/8];
			};		
	};

	const size_t GZIP_CHUNK_SIZE = 16384;
	class GzipInflator
	{
		public:

			GzipInflator ();
			~GzipInflator ();

			size_t Inflate (const uint8_t * in, size_t inLen, uint8_t * out, size_t outLen);
			bool Inflate (const uint8_t * in, size_t inLen, std::ostream& s); 
			// return true when finshed or error, s failbit will be set in case of error
			void Inflate (std::stringstream& in, std::ostream& out); 			

		private:

			z_stream m_Inflator;
			bool m_IsDirty;
	};

	class GzipDeflator
	{
		public:

			GzipDeflator ();
			~GzipDeflator ();

			void SetCompressionLevel (int level);
			size_t Deflate (const uint8_t * in, size_t inLen, uint8_t * out, size_t outLen);
			
		private:

			z_stream m_Deflator;
			bool m_IsDirty;
	};
}
}

#endif
