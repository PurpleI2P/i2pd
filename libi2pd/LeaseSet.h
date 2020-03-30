#ifndef LEASE_SET_H__
#define LEASE_SET_H__

#include <inttypes.h>
#include <string.h>
#include <vector>
#include <set>
#include <memory>
#include "Identity.h"
#include "Timestamp.h"
#include "I2PEndian.h"
#include "Blinding.h"

namespace i2p
{

namespace tunnel
{
	class InboundTunnel;
}

namespace data
{
	const int LEASE_ENDDATE_THRESHOLD = 51000; // in milliseconds
	struct Lease
	{
		IdentHash tunnelGateway;
		uint32_t tunnelID;
		uint64_t endDate; // 0 means invalid
		bool isUpdated; // transient
		/* return true if this lease expires within t millisecond + fudge factor */
		bool ExpiresWithin( const uint64_t t, const uint64_t fudge = 1000 ) const {
			auto expire = i2p::util::GetMillisecondsSinceEpoch ();
			if(fudge) expire += rand() % fudge;
			if (endDate < expire) return true;
			return (endDate - expire) < t;
		}
	};

	struct LeaseCmp
	{
		bool operator() (std::shared_ptr<const Lease> l1, std::shared_ptr<const Lease> l2) const
		{
			if (l1->tunnelID != l2->tunnelID)
				return l1->tunnelID < l2->tunnelID;
			else
				return l1->tunnelGateway < l2->tunnelGateway;
		};
	};

  typedef std::function<bool(const Lease & l)> LeaseInspectFunc;

	const size_t MAX_LS_BUFFER_SIZE = 3072;
	const size_t LEASE_SIZE = 44; // 32 + 4 + 8
	const size_t LEASE2_SIZE = 40; // 32 + 4 + 4	
	const uint8_t MAX_NUM_LEASES = 16;

	const uint8_t NETDB_STORE_TYPE_LEASESET = 1;
	class LeaseSet: public RoutingDestination
	{
		public:

			LeaseSet (const uint8_t * buf, size_t len, bool storeLeases = true);
			virtual ~LeaseSet () { delete[] m_EncryptionKey; delete[] m_Buffer; };
			virtual void Update (const uint8_t * buf, size_t len, bool verifySignature = true);
			bool IsNewer (const uint8_t * buf, size_t len) const;
			void PopulateLeases (); // from buffer

			const uint8_t * GetBuffer () const { return m_Buffer; };
			size_t GetBufferLen () const { return m_BufferLen; };
			bool IsValid () const { return m_IsValid; };
			const std::vector<std::shared_ptr<const Lease> > GetNonExpiredLeases (bool withThreshold = true) const;
      const std::vector<std::shared_ptr<const Lease> > GetNonExpiredLeasesExcluding (LeaseInspectFunc exclude, bool withThreshold = true)  const;
			bool HasExpiredLeases () const;
			bool IsExpired () const;
			bool IsEmpty () const { return m_Leases.empty (); };
			uint64_t GetExpirationTime () const { return m_ExpirationTime; };
			bool ExpiresSoon(const uint64_t dlt=1000 * 5, const uint64_t fudge = 0) const ;
			bool operator== (const LeaseSet& other) const
			{ return m_BufferLen == other.m_BufferLen && !memcmp (m_Buffer, other.m_Buffer, m_BufferLen); };
			virtual uint8_t GetStoreType () const { return NETDB_STORE_TYPE_LEASESET; };
			virtual uint32_t GetPublishedTimestamp () const { return 0; }; // should be set for LeaseSet2 only
			virtual std::shared_ptr<const i2p::crypto::Verifier> GetTransientVerifier () const { return nullptr; };		  
			virtual bool IsPublishedEncrypted () const { return false; };

			// implements RoutingDestination
			std::shared_ptr<const IdentityEx> GetIdentity () const { return m_Identity; };
			void Encrypt (const uint8_t * data, uint8_t * encrypted, BN_CTX * ctx) const;
			bool IsDestination () const { return true; };

		protected:

			void UpdateLeasesBegin ();
			void UpdateLeasesEnd ();
			void UpdateLease (const Lease& lease, uint64_t ts);

			// called from LeaseSet2
			LeaseSet (bool storeLeases);
			void SetBuffer (const uint8_t * buf, size_t len);
		  	void SetBufferLen (size_t len);
			void SetIdentity (std::shared_ptr<const IdentityEx> identity) { m_Identity = identity; };
			void SetExpirationTime (uint64_t t) { m_ExpirationTime = t; };
			void SetIsValid (bool isValid) { m_IsValid = isValid; };
			bool IsStoreLeases () const { return m_StoreLeases; };

		private:

			void ReadFromBuffer (bool readIdentity = true, bool verifySignature = true);
			virtual uint64_t ExtractTimestamp (const uint8_t * buf, size_t len) const; // returns max expiration time

		private:

			bool m_IsValid, m_StoreLeases; // we don't need to store leases for floodfill
			std::set<std::shared_ptr<Lease>, LeaseCmp> m_Leases;
			uint64_t m_ExpirationTime; // in milliseconds
			std::shared_ptr<const IdentityEx> m_Identity;
			uint8_t * m_EncryptionKey;
			uint8_t * m_Buffer;
			size_t m_BufferLen;
	};

	/**
			validate lease set buffer signature and extract expiration timestamp
			@returns true if the leaseset is well formed and signature is valid
	 */
	bool LeaseSetBufferValidate(const uint8_t * ptr, size_t sz, uint64_t & expires);

	const uint8_t NETDB_STORE_TYPE_STANDARD_LEASESET2 = 3;
	const uint8_t NETDB_STORE_TYPE_ENCRYPTED_LEASESET2 = 5;
	const uint8_t NETDB_STORE_TYPE_META_LEASESET2 = 7;

	const uint16_t LEASESET2_FLAG_OFFLINE_KEYS = 0x0001;
	const uint16_t LEASESET2_FLAG_UNPUBLISHED_LEASESET = 0x0002;	
	const uint16_t LEASESET2_FLAG_PUBLISHED_ENCRYPTED = 0x0004;

	class LeaseSet2: public LeaseSet
	{
		public:

			LeaseSet2 (uint8_t storeType, const uint8_t * buf, size_t len, bool storeLeases = true, CryptoKeyType preferredCrypto = CRYPTO_KEY_TYPE_ELGAMAL);
			LeaseSet2 (const uint8_t * buf, size_t len, std::shared_ptr<const BlindedPublicKey> key, const uint8_t * secret = nullptr, CryptoKeyType preferredCrypto = CRYPTO_KEY_TYPE_ELGAMAL); // store type 5, called from local netdb only
			uint8_t GetStoreType () const { return m_StoreType; };
			uint32_t GetPublishedTimestamp () const { return m_PublishedTimestamp; };
			bool IsPublic () const { return m_IsPublic; };
			bool IsPublishedEncrypted () const { return m_IsPublishedEncrypted; };
			std::shared_ptr<const i2p::crypto::Verifier> GetTransientVerifier () const { return m_TransientVerifier; };
			void Update (const uint8_t * buf, size_t len, bool verifySignature);

			// implements RoutingDestination
			void Encrypt (const uint8_t * data, uint8_t * encrypted, BN_CTX * ctx) const;
			CryptoKeyType GetEncryptionType () const { return m_EncryptionType; };

		private:

			void ReadFromBuffer (const uint8_t * buf, size_t len, bool readIdentity = true, bool verifySignature = true);
			void ReadFromBufferEncrypted (const uint8_t * buf, size_t len, std::shared_ptr<const BlindedPublicKey> key, const uint8_t * secret);
			size_t ReadStandardLS2TypeSpecificPart (const uint8_t * buf, size_t len);
			size_t ReadMetaLS2TypeSpecificPart (const uint8_t * buf, size_t len);

			template<typename Verifier>
			bool VerifySignature (Verifier& verifier, const uint8_t * buf, size_t len, size_t signatureOffset);

			uint64_t ExtractTimestamp (const uint8_t * buf, size_t len) const;
			size_t ExtractClientAuthData (const uint8_t * buf, size_t len, const uint8_t * secret, const uint8_t * subcredential, uint8_t * authCookie) const; // subcredential is subcredential + timestamp, return length of autData without flag

		private:

			uint8_t m_StoreType;  
			uint32_t m_PublishedTimestamp = 0;
			bool m_IsPublic = true, m_IsPublishedEncrypted = false;
			std::shared_ptr<i2p::crypto::Verifier> m_TransientVerifier;
			CryptoKeyType m_EncryptionType;
			std::shared_ptr<i2p::crypto::CryptoKeyEncryptor> m_Encryptor; // for standardLS2
	};

	// also called from Streaming.cpp 	
	template<typename Verifier>
	std::shared_ptr<i2p::crypto::Verifier> ProcessOfflineSignature (const Verifier& verifier, const uint8_t * buf, size_t len, size_t& offset)
	{
		if (offset + 6 >= len) return nullptr;
		const uint8_t * signedData = buf + offset;
		uint32_t expiresTimestamp = bufbe32toh (buf + offset); offset += 4; // expires timestamp
		if (expiresTimestamp < i2p::util::GetSecondsSinceEpoch ()) return nullptr;
		uint16_t keyType = bufbe16toh (buf + offset); offset += 2;
		std::shared_ptr<i2p::crypto::Verifier> transientVerifier (i2p::data::IdentityEx::CreateVerifier (keyType));
		if (!transientVerifier) return nullptr;
		auto keyLen = transientVerifier->GetPublicKeyLen ();
		if (offset + keyLen >= len) return nullptr;
		transientVerifier->SetPublicKey (buf + offset); offset += keyLen;
		if (offset + verifier->GetSignatureLen () >= len) return nullptr;
		if (!verifier->Verify (signedData, keyLen + 6, buf + offset)) return nullptr;
		offset += verifier->GetSignatureLen ();	
		return transientVerifier;
	}

//------------------------------------------------------------------------------------
	class LocalLeaseSet
	{
		public:

			LocalLeaseSet (std::shared_ptr<const IdentityEx> identity, const uint8_t * encryptionPublicKey, std::vector<std::shared_ptr<i2p::tunnel::InboundTunnel> > tunnels);
			LocalLeaseSet (std::shared_ptr<const IdentityEx> identity, const uint8_t * buf, size_t len);
			virtual ~LocalLeaseSet () { delete[] m_Buffer; };

			virtual uint8_t * GetBuffer () const { return m_Buffer; };
			uint8_t * GetSignature () { return GetBuffer () + GetBufferLen () - GetSignatureLen (); };
			virtual size_t GetBufferLen () const { return m_BufferLen; };
			size_t GetSignatureLen () const { return m_Identity->GetSignatureLen (); };
			uint8_t * GetLeases () { return m_Leases; };

			const IdentHash& GetIdentHash () const { return m_Identity->GetIdentHash (); };
			std::shared_ptr<const IdentityEx> GetIdentity () const { return m_Identity; };
			bool IsExpired () const;
			uint64_t GetExpirationTime () const { return m_ExpirationTime; };
			void SetExpirationTime (uint64_t expirationTime) { m_ExpirationTime = expirationTime; };
			bool operator== (const LeaseSet& other) const
			{ return GetBufferLen () == other.GetBufferLen () && !memcmp (GetBuffer (), other.GetBuffer (), GetBufferLen ()); };

			virtual uint8_t GetStoreType () const { return NETDB_STORE_TYPE_LEASESET; };
			virtual const IdentHash& GetStoreHash () const { return GetIdentHash (); }; // differ from ident hash for encrypted LeaseSet2
			virtual std::shared_ptr<const LocalLeaseSet> GetInnerLeaseSet () const { return nullptr; }; // non-null for encrypted LeaseSet2

		private:

			uint64_t m_ExpirationTime; // in milliseconds
			std::shared_ptr<const IdentityEx> m_Identity;
			uint8_t * m_Buffer, * m_Leases;
			size_t m_BufferLen;
	};

	class LocalLeaseSet2: public LocalLeaseSet
	{
		public:

			struct KeySection
			{
				uint16_t keyType, keyLen;
				const uint8_t * encryptionPublicKey;
			};	
			typedef std::vector<KeySection> KeySections;
			
			LocalLeaseSet2 (uint8_t storeType, const i2p::data::PrivateKeys& keys, 
				const KeySections& encryptionKeys, 
				std::vector<std::shared_ptr<i2p::tunnel::InboundTunnel> > tunnels, 
				bool isPublic, bool isPublishedEncrypted = false);
			LocalLeaseSet2 (uint8_t storeType, std::shared_ptr<const IdentityEx> identity, const uint8_t * buf, size_t len);	// from I2CP
		
			virtual ~LocalLeaseSet2 () { delete[] m_Buffer; };
			
			uint8_t * GetBuffer () const { return m_Buffer + 1; };
			size_t GetBufferLen () const { return m_BufferLen; };

			uint8_t GetStoreType () const { return m_Buffer[0]; };

		protected:

			LocalLeaseSet2 (std::shared_ptr<const IdentityEx> identity): LocalLeaseSet (identity, nullptr, 0), m_Buffer (nullptr), m_BufferLen(0) {}; // called from LocalEncryptedLeaseSet2

		protected:

			uint8_t * m_Buffer; // 1 byte store type + actual buffer
			size_t m_BufferLen;
	};


	const int ENCRYPTED_LEASESET_AUTH_TYPE_NONE = 0;
	const int ENCRYPTED_LEASESET_AUTH_TYPE_DH = 1;
	const int ENCRYPTED_LEASESET_AUTH_TYPE_PSK = 2;

	typedef i2p::data::Tag<32> AuthPublicKey;	

	class LocalEncryptedLeaseSet2: public LocalLeaseSet2
	{
		public:

			LocalEncryptedLeaseSet2 (std::shared_ptr<const LocalLeaseSet2> ls, const i2p::data::PrivateKeys& keys, int authType = ENCRYPTED_LEASESET_AUTH_TYPE_NONE, std::shared_ptr<std::vector<AuthPublicKey> > authKeys = nullptr); 

			LocalEncryptedLeaseSet2 (std::shared_ptr<const IdentityEx> identity, const uint8_t * buf, size_t len); // from I2CP

			const IdentHash& GetStoreHash () const { return m_StoreHash; };
			std::shared_ptr<const LocalLeaseSet> GetInnerLeaseSet () const { return m_InnerLeaseSet; };

		private:

			void CreateClientAuthData (const uint8_t * subcredential, int authType, std::shared_ptr<std::vector<AuthPublicKey> > authKeys, const uint8_t * authCookie, uint8_t * authData) const;

		private:

			IdentHash m_StoreHash;
			std::shared_ptr<const LocalLeaseSet2> m_InnerLeaseSet;
	};
}
}

#endif
