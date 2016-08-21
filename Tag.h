/*
* Copyright (c) 2013-2016, The PurpleI2P Project
*
* This file is part of Purple i2pd project and licensed under BSD3
*
* See full license text in LICENSE file at top of project tree
*/

#ifndef TAG_H__
#define TAG_H__

#include <string.h> /* memcpy */

#include "Base.h"

namespace i2p {
namespace data {
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

      /** fill with a value */
      void Fill(uint8_t c) {
        memset(m_Buf, c, sz);
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
} // data
} // i2p

#endif /* TAG_H__ */
