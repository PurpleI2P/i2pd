/*
* Copyright (c) 2013-2020, The PurpleI2P Project
*
* This file is part of Purple i2pd project and licensed under BSD3
*
* See full license text in LICENSE file at top of project tree
*/

#ifndef BLINDING_H__
#define BLINDING_H__

#include <inttypes.h>
#include <string>
#include <vector>
#include "Identity.h"

namespace i2p
{
namespace data
{
	class BlindedPublicKey // for encrypted LS2
	{
		public:

			BlindedPublicKey (std::shared_ptr<const IdentityEx> identity, bool clientAuth = false);
			BlindedPublicKey (const std::string& b33); // from b33 without .b32.i2p
			std::string ToB33 () const;

			const uint8_t * GetPublicKey () const { return m_PublicKey.data (); };
			size_t GetPublicKeyLen () const { return m_PublicKey.size (); };
			SigningKeyType GetSigType () const  { return m_SigType; };
			SigningKeyType GetBlindedSigType () const  { return m_BlindedSigType; };
			bool IsValid () const { return GetSigType (); }; // signature type 0 means invalid

			void GetSubcredential (const uint8_t * blinded, size_t len, uint8_t * subcredential) const; // 32 bytes
			size_t GetBlindedKey (const char * date, uint8_t * blindedKey) const; // date is 8 chars "YYYYMMDD", return public key length
			size_t BlindPrivateKey (const uint8_t * priv, const char * date, uint8_t * blindedPriv, uint8_t * blindedPub) const; // date is 8 chars "YYYYMMDD", return public key length
			i2p::data::IdentHash GetStoreHash (const char * date = nullptr) const; // date is 8 chars "YYYYMMDD", use current if null

		private:

			void GetCredential (uint8_t * credential) const; // 32 bytes
			void GenerateAlpha (const char * date, uint8_t * seed) const; // 64 bytes, date is 8 chars "YYYYMMDD"
			void H (const std::string& p, const std::vector<std::pair<const uint8_t *, size_t> >& bufs, uint8_t * hash) const;

		private:

			std::vector<uint8_t> m_PublicKey;
			i2p::data::SigningKeyType m_SigType, m_BlindedSigType;
			bool m_IsClientAuth = false;
	};
}
}

#endif
