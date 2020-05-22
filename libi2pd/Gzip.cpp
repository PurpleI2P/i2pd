/*
* Copyright (c) 2013-2020, The PurpleI2P Project
*
* This file is part of Purple i2pd project and licensed under BSD3
*
* See full license text in LICENSE file at top of project tree
*/

#include <inttypes.h>
#include <string.h> /* memset */
#include <iostream>
#include "Log.h"
#include "I2PEndian.h"
#include "Gzip.h"

namespace i2p
{
namespace data
{
	const size_t GZIP_CHUNK_SIZE = 16384;

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
		if (inLen < 23) return 0;
		if (in[10] == 0x01) // non compressed
		{
			size_t len = bufle16toh (in + 11);
			if (len + 23 < inLen)
			{
				LogPrint (eLogError, "Gzip: Incorrect length");
				return 0;
			}
			if (len > outLen) len = outLen;
			memcpy (out, in + 15, len);
			return len;
		}
		else
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
			// else
			LogPrint (eLogError, "Gzip: Inflate error ", err);
			return 0;
		}
	}

	void GzipInflator::Inflate (const uint8_t * in, size_t inLen, std::ostream& os)
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
				inflateEnd (&m_Inflator);
				os.setstate(std::ios_base::failbit);
				break;
			}
			os.write ((char *)out, GZIP_CHUNK_SIZE - m_Inflator.avail_out);
		}
		while (!m_Inflator.avail_out); // more data to read
		delete[] out;
	}

	void GzipInflator::Inflate (std::istream& in, std::ostream& out)
	{
		uint8_t * buf = new uint8_t[GZIP_CHUNK_SIZE];
		while (!in.eof ())
		{
			in.read ((char *) buf, GZIP_CHUNK_SIZE);
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
		{
			out[9] = 0xff; // OS is always unknown
			return outLen - m_Deflator.avail_out;
		}
		// else
		LogPrint (eLogError, "Gzip: Deflate error ", err);
		return 0;
	}

	size_t GzipDeflator::Deflate (const std::vector<std::pair<const uint8_t *, size_t> >& bufs, uint8_t * out, size_t outLen)
	{
		if (m_IsDirty) deflateReset (&m_Deflator);
		m_IsDirty = true;
		size_t offset = 0;
		int err;
		for (const auto& it: bufs)
		{
			m_Deflator.next_in = const_cast<uint8_t *>(it.first);
			m_Deflator.avail_in = it.second;
			m_Deflator.next_out = out + offset;
			m_Deflator.avail_out = outLen - offset;
			auto flush = (it == bufs.back ()) ? Z_FINISH : Z_NO_FLUSH;
			err = deflate (&m_Deflator, flush);
			if (err)
			{
				if (flush && err == Z_STREAM_END)
				{
					out[9] = 0xff; // OS is always unknown
					return outLen - m_Deflator.avail_out;
				}
				break;
			}
			offset = outLen - m_Deflator.avail_out;
		}
		// else
		LogPrint (eLogError, "Gzip: Deflate error ", err);
		return 0;
	}

	size_t GzipNoCompression (const uint8_t * in, uint16_t inLen, uint8_t * out, size_t outLen)
	{
		static const uint8_t gzipHeader[11] = { 0x1f, 0x8b, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0xff, 0x01 };
		if (outLen < (size_t)inLen + 23) return 0;
		memcpy (out, gzipHeader, 11);
		htole16buf (out + 11, inLen);
		htole16buf (out + 13, 0xffff - inLen);
		memcpy (out + 15, in, inLen);
		htole32buf (out + inLen + 15, crc32 (0, in, inLen));
		htole32buf (out + inLen + 19, inLen);
		return inLen + 23;
	}

	size_t GzipNoCompression (const std::vector<std::pair<const uint8_t *, size_t> >& bufs, uint8_t * out, size_t outLen)
	{
		static const uint8_t gzipHeader[11] = { 0x1f, 0x8b, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0xff, 0x01 };
		memcpy (out, gzipHeader, 11);
		uint32_t crc = 0;
		size_t len = 0, len1;
		for (const auto& it: bufs)
		{
			len1 = len;
			len += it.second;
			if (outLen < len + 23) return 0;
			memcpy (out + 15 + len1, it.first, it.second);
			crc = crc32 (crc, it.first, it.second);
		}
		if (len > 0xffff) return 0;
		htole32buf (out + len + 15, crc);
		htole32buf (out + len + 19, len);
		htole16buf (out + 11, len);
		htole16buf (out + 13, 0xffff - len);
		return len + 23;
	}

} // data
} // i2p
