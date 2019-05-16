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

			BlindedPublicKey (std::shared_ptr<const IdentityEx> identity);
			BlindedPublicKey (const std::string& b33); // from b33 without .b32.i2p			
			std::string ToB33 () const;

			const uint8_t * GetPublicKey () const { return m_PublicKey.data (); };
			size_t GetPublicKeyLen () const { return m_PublicKey.size (); };
			SigningKeyType GetSigType () const  { return m_SigType; };
			SigningKeyType GetBlindedSigType () const  { return m_BlindedSigType; };

			void GetSubcredential (const uint8_t * blinded, size_t len, uint8_t * subcredential) const; // 32 bytes
			void GetBlindedKey (const char * date, uint8_t * blindedKey) const; // blinded key 32 bytes, date is 8 chars "YYYYMMDD" 
			void BlindPrivateKey (const uint8_t * priv, const char * date, uint8_t * blindedPriv, uint8_t * blindedPub) const; // blinded key 32 bytes, date is 8 chars "YYYYMMDD" 
			i2p::data::IdentHash GetStoreHash (const char * date = nullptr) const; // date is 8 chars "YYYYMMDD", use current if null

		private:

			void GetCredential (uint8_t * credential) const; // 32 bytes
			void GenerateAlpha (const char * date, uint8_t * seed) const; // 64 bytes, date is 8 chars "YYYYMMDD" 
			void H (const std::string& p, const std::vector<std::pair<const uint8_t *, size_t> >& bufs, uint8_t * hash) const;

		private:

			std::vector<uint8_t> m_PublicKey;
			i2p::data::SigningKeyType m_SigType, m_BlindedSigType;
	};
}
}

#endif
