/*
* Copyright (c) 2013-2020, The PurpleI2P Project
*
* This file is part of Purple i2pd project and licensed under BSD3
*
* See full license text in LICENSE file at top of project tree
*/

#ifndef TAG_H__
#define TAG_H__

/*
* Copyright (c) 2013-2017, The PurpleI2P Project
*
* This file is part of Purple i2pd project and licensed under BSD3
*
* See full license text in LICENSE file at top of project tree
*/

#include <boost/static_assert.hpp>
#include <string.h>
#include <openssl/rand.h>
#include "Base.h"

namespace i2p {
namespace data {
	template<size_t sz>
	class Tag
	{
		BOOST_STATIC_ASSERT_MSG(sz % 8 == 0, "Tag size must be multiple of 8 bytes");

		public:

			Tag () = default;
			Tag (const uint8_t * buf) { memcpy (m_Buf, buf, sz); }

			bool operator== (const Tag& other) const { return !memcmp (m_Buf, other.m_Buf, sz); }
			bool operator!= (const Tag& other) const { return !(*this == other); }
			bool operator< (const Tag& other) const { return memcmp (m_Buf, other.m_Buf, sz) < 0; }

			uint8_t * operator()() { return m_Buf; }
			const uint8_t * operator()() const { return m_Buf; }

			operator uint8_t * () { return m_Buf; }
			operator const uint8_t * () const { return m_Buf; }

			const uint8_t * data() const { return m_Buf; }
			const uint64_t * GetLL () const { return ll; }

			bool IsZero () const
			{
				for (size_t i = 0; i < sz/8; ++i)
					if (ll[i]) return false;
				return true;
			}

			void Fill(uint8_t c)
			{
				memset(m_Buf, c, sz);
			}

			void Randomize()
			{
				RAND_bytes(m_Buf, sz);
			}

			std::string ToBase64 () const
			{
				char str[sz*2];
				size_t l = i2p::data::ByteStreamToBase64 (m_Buf, sz, str, sz*2);
				return std::string (str, str + l);
			}

			std::string ToBase32 () const
			{
				char str[sz*2];
				size_t l = i2p::data::ByteStreamToBase32 (m_Buf, sz, str, sz*2);
				return std::string (str, str + l);
			}

			size_t FromBase32 (const std::string& s)
			{
				return i2p::data::Base32ToByteStream (s.c_str (), s.length (), m_Buf, sz);
			}

			size_t FromBase64 (const std::string& s)
			{
				return i2p::data::Base64ToByteStream (s.c_str (), s.length (), m_Buf, sz);
			}

		private:

			union // 8 bytes aligned
			{
				uint8_t m_Buf[sz];
				uint64_t ll[sz/8];
			};
	};
} // data
} // i2p

namespace std
{
	// hash for std::unordered_map
	template<size_t sz> struct hash<i2p::data::Tag<sz> >
	{
		size_t operator()(const i2p::data::Tag<sz>& s) const
		{
			return s.GetLL ()[0];
		}
	};
}

#endif /* TAG_H__ */
