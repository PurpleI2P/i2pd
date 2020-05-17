#ifndef GZIP_H__
#define GZIP_H__

#include <zlib.h>
#include <vector>

namespace i2p 
{
namespace data 
{
	class GzipInflator
	{
		public:

			GzipInflator ();
			~GzipInflator ();

			size_t Inflate (const uint8_t * in, size_t inLen, uint8_t * out, size_t outLen);
			/** @note @a os failbit will be set in case of error */
			void Inflate (const uint8_t * in, size_t inLen, std::ostream& os);
			void Inflate (std::istream& in, std::ostream& out);

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
			size_t Deflate (const std::vector<std::pair<const uint8_t *, size_t> >& bufs, uint8_t * out, size_t outLen);

		private:

			z_stream m_Deflator;
			bool m_IsDirty;
	};

	size_t GzipNoCompression (const uint8_t * in, uint16_t inLen, uint8_t * out, size_t outLen); // for < 64K
		
} // data
} // i2p

#endif /* GZIP_H__ */
