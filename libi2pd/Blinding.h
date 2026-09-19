/*
* Copyright (c) 2013-2026, The PurpleI2P Project
*
* This file is part of Purple i2pd project and licensed under BSD3
*
* See full license text in LICENSE file at top of project tree
*/

#ifndef BLINDING_H__
#define BLINDING_H__

#include <inttypes.h>
#include <string>
#include <string_view>
#include <array>
#include "Crypto.h"
#include "Identity.h"

namespace i2p
{
namespace data
{
	class BlindedPublicKey // for encrypted LS2
	{
		public:

			BlindedPublicKey (std::shared_ptr<const IdentityEx> identity, bool clientAuth = false);
			BlindedPublicKey (std::string_view b33); // from b33 without .b32.i2p
			std::string ToB33 () const;

			const uint8_t * GetPublicKey () const { return m_PublicKey.data (); };
			size_t GetPublicKeyLen () const { return m_PublicKey.size (); };
			SigningKeyType GetSigType () const { return m_SigType; };
			SigningKeyType GetBlindedSigType () const { return m_BlindedSigType; };
			bool IsValid () const; // signature type must be blindable

			void GetSubcredential (const uint8_t * blinded, size_t len, uint8_t * subcredential) const; // 32 bytes
			size_t GetBlindedKey (const char * date, uint8_t * blindedKey) const; // date is 8 chars "YYYYMMDD", return public key length
			size_t BlindPrivateKey (const uint8_t * priv, const char * date, uint8_t * blindedPriv, uint8_t * blindedPub) const; // date is 8 chars "YYYYMMDD", return public key length
			i2p::data::IdentHash GetStoreHash (const char * date = nullptr) const; // date is 8 chars "YYYYMMDD", use current if null

		private:

			void GetCredential (uint8_t * credential) const; // 32 bytes
			void GenerateAlpha (const char * date, uint8_t * seed) const; // 64 bytes, date is 8 chars "YYYYMMDD"
			void H (const std::string& p, const std::vector<std::pair<const uint8_t *, size_t> >& bufs, uint8_t * hash) const;

		private:

			std::array<uint8_t, i2p::crypto::EDDSA25519_PUBLIC_KEY_LENGTH> m_PublicKey;
			i2p::data::SigningKeyType m_SigType, m_BlindedSigType;
			bool m_IsClientAuth = false;
	};

	// signs the outer layer of an encrypted LeaseSet for one day
	class BlindedSigner: public i2p::crypto::Signer
	{
		public:

			BlindedSigner (std::shared_ptr<const i2p::crypto::Signer> signer, const uint8_t * blindedPublicKey,
				size_t blindedPublicKeyLen, const std::vector<uint8_t>& offlineSignature = {});

			// implements Signer
			void Sign (const uint8_t * buf, int len, uint8_t * signature) const override { m_Signer->Sign (buf, len, signature); };
			size_t GetSignatureLen () const override { return m_Signer->GetSignatureLen (); };

			const uint8_t * GetBlindedPublicKey () const { return m_BlindedPublicKey.data (); };
			size_t GetBlindedPublicKeyLen () const { return m_BlindedPublicKeyLen; };
			// goes into the LeaseSet, empty unless the destination's signing key is offline
			const std::vector<uint8_t>& GetOfflineSignature () const { return m_OfflineSignature; };

		private:

			std::shared_ptr<const i2p::crypto::Signer> m_Signer;
			std::array<uint8_t, i2p::crypto::EDDSA25519_PUBLIC_KEY_LENGTH> m_BlindedPublicKey;
			size_t m_BlindedPublicKeyLen;
			std::vector<uint8_t> m_OfflineSignature;
	};

	// the signing side of a blinded address, blinds the destination's own signing key
	class BlindedPrivateKey
	{
		public:

			static std::unique_ptr<BlindedPrivateKey> Create (const PrivateKeys& keys); // b33 offline keys, if the keys carry them

			BlindedPrivateKey (const PrivateKeys& keys);
			virtual ~BlindedPrivateKey ();

			const BlindedPublicKey& GetPublic () const { return m_Public; };
			IdentHash GetStoreHash (uint64_t timestamp) const;
			virtual std::unique_ptr<BlindedSigner> CreateSigner (uint64_t timestamp) const; // nullptr if that day can't be signed

		protected:

			BlindedPrivateKey (std::shared_ptr<const IdentityEx> identity); // the signing key is not here

		protected:

			BlindedPublicKey m_Public;

		private:

			std::vector<uint8_t> m_SigningPrivateKey;
	};

	// the destination's signing key is offline: a transient per day, authorized by the blinded key of that day
	class B33BlindedPrivateKey: public BlindedPrivateKey
	{
		public:

			B33BlindedPrivateKey (std::shared_ptr<const IdentityEx> identity, const B33OfflineKeys& offlineKeys);

			std::unique_ptr<BlindedSigner> CreateSigner (uint64_t timestamp) const override;

		private:

			std::shared_ptr<const OfflineSigner> GetKey (uint64_t timestamp) const;

		private:

			std::vector<std::shared_ptr<OfflineSigner> > m_Keys; // one per day, in the order they were generated
	};
}
}

#endif
