/*
* Copyright (c) 2013-2020, The PurpleI2P Project
*
* This file is part of Purple i2pd project and licensed under BSD3
*
* See full license text in LICENSE file at top of project tree
*/

#include <string.h>
#include "I2PEndian.h"
#include "Crypto.h"
#include "Log.h"
#include "Tag.h"
#include "Timestamp.h"
#include "NetDb.hpp"
#include "Tunnel.h"
#include "LeaseSet.h"

namespace i2p
{
namespace data
{
	LeaseSet::LeaseSet (bool storeLeases):
		m_IsValid (false), m_StoreLeases (storeLeases), m_ExpirationTime (0), m_EncryptionKey (nullptr),
		m_Buffer (nullptr), m_BufferLen (0)
	{
	}

	LeaseSet::LeaseSet (const uint8_t * buf, size_t len, bool storeLeases):
		m_IsValid (true), m_StoreLeases (storeLeases), m_ExpirationTime (0), m_EncryptionKey (nullptr)
	{
		m_Buffer = new uint8_t[len];
		memcpy (m_Buffer, buf, len);
		m_BufferLen = len;
		ReadFromBuffer ();
	}

	void LeaseSet::Update (const uint8_t * buf, size_t len, bool verifySignature)
	{
		if (len > m_BufferLen)
		{
			auto oldBuffer = m_Buffer;
			m_Buffer = new uint8_t[len];
			delete[] oldBuffer;
		}
		memcpy (m_Buffer, buf, len);
		m_BufferLen = len;
		ReadFromBuffer (false, verifySignature);
	}

	void LeaseSet::PopulateLeases ()
	{
		m_StoreLeases = true;
		ReadFromBuffer (false);
	}

	void LeaseSet::ReadFromBuffer (bool readIdentity, bool verifySignature)
	{
		if (readIdentity || !m_Identity)
			m_Identity = std::make_shared<IdentityEx>(m_Buffer, m_BufferLen);
		size_t size = m_Identity->GetFullLen ();
		if (size > m_BufferLen)
		{
			LogPrint (eLogError, "LeaseSet: identity length ", size, " exceeds buffer size ", m_BufferLen);
			m_IsValid = false;
			return;
		}
		if (m_StoreLeases)
		{
			if (!m_EncryptionKey) m_EncryptionKey = new uint8_t[256];
			memcpy (m_EncryptionKey, m_Buffer + size, 256);
		}
		size += 256; // encryption key
		size += m_Identity->GetSigningPublicKeyLen (); // unused signing key
		if (size + 1 > m_BufferLen)
		{
			LogPrint (eLogError, "LeaseSet: ", size, " exceeds buffer size ", m_BufferLen);
			m_IsValid = false;
			return;
		}	
		uint8_t num = m_Buffer[size];
		size++; // num
		LogPrint (eLogDebug, "LeaseSet: read num=", (int)num);
		if (!num || num > MAX_NUM_LEASES)
		{
			LogPrint (eLogError, "LeaseSet: incorrect number of leases", (int)num);
			m_IsValid = false;
			return;
		}
		if (size + num*LEASE_SIZE > m_BufferLen) 
		{	
			LogPrint (eLogError, "LeaseSet: ", size, " exceeds buffer size ", m_BufferLen);
			m_IsValid = false;
			return;
		}	
		
		UpdateLeasesBegin ();
		// process leases
		m_ExpirationTime = 0;
		auto ts = i2p::util::GetMillisecondsSinceEpoch ();
		const uint8_t * leases = m_Buffer + size;
		for (int i = 0; i < num; i++)
		{
			Lease lease;
			lease.tunnelGateway = leases;
			leases += 32; // gateway
			lease.tunnelID = bufbe32toh (leases);
			leases += 4; // tunnel ID
			lease.endDate = bufbe64toh (leases);
			leases += 8; // end date
			UpdateLease (lease, ts);
		}
		if (!m_ExpirationTime)
		{
			LogPrint (eLogWarning, "LeaseSet: all leases are expired. Dropped");
			m_IsValid = false;
			return;
		}
		m_ExpirationTime += LEASE_ENDDATE_THRESHOLD;
		UpdateLeasesEnd ();

		// verify
		if (verifySignature)
		{	
			auto signedSize = leases - m_Buffer;
			if (signedSize + m_Identity->GetSignatureLen () > m_BufferLen)
			{
				LogPrint (eLogError, "LeaseSet: Signature exceeds buffer size ", m_BufferLen);
				m_IsValid = false;
			}	
			else if (!m_Identity->Verify (m_Buffer, signedSize, leases))
			{
				LogPrint (eLogWarning, "LeaseSet: verification failed");
				m_IsValid = false;
			}
		}
	}

	void LeaseSet::UpdateLeasesBegin ()
	{
		// reset existing leases
		if (m_StoreLeases)
			for (auto& it: m_Leases)
				it->isUpdated = false;
		else
			m_Leases.clear ();
	}

	void LeaseSet::UpdateLeasesEnd ()
	{
		// delete old leases
		if (m_StoreLeases)
		{
			for (auto it = m_Leases.begin (); it != m_Leases.end ();)
			{
				if (!(*it)->isUpdated)
				{
					(*it)->endDate = 0; // somebody might still hold it
					m_Leases.erase (it++);
				}
				else
					++it;
			}
		}
	}

	void LeaseSet::UpdateLease (const Lease& lease, uint64_t ts)
	{
		if (ts < lease.endDate + LEASE_ENDDATE_THRESHOLD)
		{
			if (lease.endDate > m_ExpirationTime)
				m_ExpirationTime = lease.endDate;
			if (m_StoreLeases)
			{
				auto ret = m_Leases.insert (std::make_shared<Lease>(lease));
				if (!ret.second) (*ret.first)->endDate = lease.endDate; // update existing
				(*ret.first)->isUpdated = true;
			}
		}
		else
			LogPrint (eLogWarning, "LeaseSet: Lease is expired already");
	}

	uint64_t LeaseSet::ExtractExpirationTimestamp (const uint8_t * buf, size_t len) const
	{
		if (!m_Identity) return 0;
		size_t size = m_Identity->GetFullLen ();
		if (size > len) return 0;
		size += 256; // encryption key
		size += m_Identity->GetSigningPublicKeyLen (); // unused signing key
		if (size > len) return 0;
		uint8_t num = buf[size];
		size++; // num
		if (size + num*LEASE_SIZE > len) return 0;
		uint64_t timestamp= 0 ;
		for (int i = 0; i < num; i++)
		{
			size += 36; // gateway (32) + tunnelId(4)
			auto endDate = bufbe64toh (buf + size);
			size += 8; // end date
			if (!timestamp || endDate < timestamp)
				timestamp = endDate;
		}
		return timestamp;
	}

	bool LeaseSet::IsNewer (const uint8_t * buf, size_t len) const
	{
		return ExtractExpirationTimestamp (buf, len) > ExtractExpirationTimestamp (m_Buffer, m_BufferLen);
	}

	bool LeaseSet::ExpiresSoon(const uint64_t dlt, const uint64_t fudge) const
	{
		auto now = i2p::util::GetMillisecondsSinceEpoch ();
		if (fudge) now += rand() % fudge;
		if (now >= m_ExpirationTime) return true;
		return	m_ExpirationTime - now <= dlt;
	}

	const std::vector<std::shared_ptr<const Lease> > LeaseSet::GetNonExpiredLeases (bool withThreshold) const
	{
		return GetNonExpiredLeasesExcluding( [] (const Lease & l) -> bool { return false; }, withThreshold);
	}

	const std::vector<std::shared_ptr<const Lease> > LeaseSet::GetNonExpiredLeasesExcluding (LeaseInspectFunc exclude, bool withThreshold) const
	{
		auto ts = i2p::util::GetMillisecondsSinceEpoch ();
		std::vector<std::shared_ptr<const Lease> > leases;
		for (const auto& it: m_Leases)
		{
			auto endDate = it->endDate;
			if (withThreshold)
				endDate += LEASE_ENDDATE_THRESHOLD;
			else
				endDate -= LEASE_ENDDATE_THRESHOLD;
			if (ts < endDate && !exclude(*it))
				leases.push_back (it);
		}
		return leases;
	}

	bool LeaseSet::HasExpiredLeases () const
	{
		auto ts = i2p::util::GetMillisecondsSinceEpoch ();
		for (const auto& it: m_Leases)
			if (ts >= it->endDate) return true;
		return false;
	}

	bool LeaseSet::IsExpired () const
	{
		if (m_StoreLeases && IsEmpty ()) return true;
		auto ts = i2p::util::GetMillisecondsSinceEpoch ();
		return ts > m_ExpirationTime;
	}

	void LeaseSet::Encrypt (const uint8_t * data, uint8_t * encrypted, BN_CTX * ctx) const
	{
		if (!m_EncryptionKey) return;
		auto encryptor = m_Identity->CreateEncryptor (m_EncryptionKey);
		if (encryptor)
			encryptor->Encrypt (data, encrypted, ctx, true);
	}

	void LeaseSet::SetBuffer (const uint8_t * buf, size_t len)
	{
		if (m_Buffer) delete[] m_Buffer;
		m_Buffer = new uint8_t[len];
		m_BufferLen = len;
		memcpy (m_Buffer, buf, len);
	}

	void LeaseSet::SetBufferLen (size_t len)
	{
		if (len <= m_BufferLen) m_BufferLen = len;
		else
			LogPrint (eLogError, "LeaseSet2: actual buffer size ", len , " exceeds full buffer size ", m_BufferLen);
	}

	LeaseSet2::LeaseSet2 (uint8_t storeType, const uint8_t * buf, size_t len, bool storeLeases, CryptoKeyType preferredCrypto):
		LeaseSet (storeLeases), m_StoreType (storeType), m_EncryptionType (preferredCrypto)
	{
		SetBuffer (buf, len);
		if (storeType == NETDB_STORE_TYPE_ENCRYPTED_LEASESET2)
			ReadFromBufferEncrypted (buf, len, nullptr, nullptr);
		else
			ReadFromBuffer (buf, len);
	}

	LeaseSet2::LeaseSet2 (const uint8_t * buf, size_t len, std::shared_ptr<const BlindedPublicKey> key,
		const uint8_t * secret, CryptoKeyType preferredCrypto):
		LeaseSet (true), m_StoreType (NETDB_STORE_TYPE_ENCRYPTED_LEASESET2), m_EncryptionType (preferredCrypto)
	{
		ReadFromBufferEncrypted (buf, len, key, secret);
	}

	void LeaseSet2::Update (const uint8_t * buf, size_t len, bool verifySignature)
	{
		SetBuffer (buf, len);
		if (GetStoreType () != NETDB_STORE_TYPE_ENCRYPTED_LEASESET2)
			ReadFromBuffer (buf, len, false, verifySignature);
		// TODO: implement encrypted
	}

	bool LeaseSet2::IsNewer (const uint8_t * buf, size_t len) const
	{
		uint64_t expiration;
		return ExtractPublishedTimestamp (buf, len, expiration) > m_PublishedTimestamp;
	}

	void LeaseSet2::ReadFromBuffer (const uint8_t * buf, size_t len, bool readIdentity, bool verifySignature)
	{
		// standard LS2 header
		std::shared_ptr<const IdentityEx> identity;
		if (readIdentity)
		{
			identity = std::make_shared<IdentityEx>(buf, len);
			SetIdentity (identity);
		}
		else
			identity = GetIdentity ();
		size_t offset = identity->GetFullLen ();
		if (offset + 8 >= len) return;
		m_PublishedTimestamp = bufbe32toh (buf + offset); offset += 4; // published timestamp (seconds)
		uint16_t expires = bufbe16toh (buf + offset); offset += 2; // expires (seconds)
		SetExpirationTime ((m_PublishedTimestamp + expires)*1000LL); // in milliseconds
		uint16_t flags = bufbe16toh (buf + offset); offset += 2; // flags
		if (flags & LEASESET2_FLAG_OFFLINE_KEYS)
		{
			// transient key
			m_TransientVerifier = ProcessOfflineSignature (identity, buf, len, offset);
			if (!m_TransientVerifier)
			{
				LogPrint (eLogError, "LeaseSet2: offline signature failed");
				return;
			}
		}
		if (flags & LEASESET2_FLAG_UNPUBLISHED_LEASESET) m_IsPublic = false;
		if (flags & LEASESET2_FLAG_PUBLISHED_ENCRYPTED)
		{
			m_IsPublishedEncrypted = true;
			m_IsPublic = true;
		}
		// type specific part
		size_t s = 0;
		switch (m_StoreType)
		{
			case NETDB_STORE_TYPE_STANDARD_LEASESET2:
				s = ReadStandardLS2TypeSpecificPart (buf + offset, len - offset);
			break;
			case NETDB_STORE_TYPE_META_LEASESET2:
				s = ReadMetaLS2TypeSpecificPart (buf + offset, len - offset);
			break;
			default:
				LogPrint (eLogWarning, "LeaseSet2: Unexpected store type ", (int)m_StoreType);
		}
		if (!s) return;
		offset += s;
		if (verifySignature || m_TransientVerifier)
		{
			// verify signature
			bool verified = m_TransientVerifier ? VerifySignature (m_TransientVerifier, buf, len, offset) :
				VerifySignature (identity, buf, len, offset);
			SetIsValid (verified);
		}
		offset += m_TransientVerifier ? m_TransientVerifier->GetSignatureLen () : identity->GetSignatureLen ();
		SetBufferLen (offset);
	}

	template<typename Verifier>
	bool LeaseSet2::VerifySignature (Verifier& verifier, const uint8_t * buf, size_t len, size_t signatureOffset)
	{
		if (signatureOffset + verifier->GetSignatureLen () > len) return false;
		// we assume buf inside DatabaseStore message, so buf[-1] is valid memory
		// change it for signature verification, and restore back
		uint8_t c = buf[-1];
		const_cast<uint8_t *>(buf)[-1] = m_StoreType;
		bool verified = verifier->Verify (buf - 1, signatureOffset + 1, buf + signatureOffset);
		const_cast<uint8_t *>(buf)[-1] = c;
		if (!verified)
			LogPrint (eLogWarning, "LeaseSet2: verification failed");
		return verified;
	}

	size_t LeaseSet2::ReadStandardLS2TypeSpecificPart (const uint8_t * buf, size_t len)
	{
		size_t offset = 0;
		// properties
		uint16_t propertiesLen = bufbe16toh (buf + offset); offset += 2;
		offset += propertiesLen; // skip for now. TODO: implement properties
		if (offset + 1 >= len) return 0;
		// key sections
		CryptoKeyType preferredKeyType = m_EncryptionType;
		bool preferredKeyFound = false;
		int numKeySections = buf[offset]; offset++;
		for (int i = 0; i < numKeySections; i++)
		{
			uint16_t keyType = bufbe16toh (buf + offset); offset += 2; // encryption key type
			if (offset + 2 >= len) return 0;
			uint16_t encryptionKeyLen = bufbe16toh (buf + offset); offset += 2;
			if (offset + encryptionKeyLen >= len) return 0;
			if (IsStoreLeases () && !preferredKeyFound) // create encryptor with leases only
			{
				// we pick first valid key if preferred not found
				auto encryptor = i2p::data::IdentityEx::CreateEncryptor (keyType, buf + offset);
				if (encryptor && (!m_Encryptor || keyType == preferredKeyType))
				{
					m_Encryptor = encryptor; // TODO: atomic
					m_EncryptionType = keyType;
					if (keyType == preferredKeyType) preferredKeyFound = true;
				}
			}
			offset += encryptionKeyLen;
		}
		// leases
		if (offset + 1 >= len) return 0;
		int numLeases = buf[offset]; offset++;
		auto ts = i2p::util::GetMillisecondsSinceEpoch ();
		if (IsStoreLeases ())
		{
			UpdateLeasesBegin ();
			for (int i = 0; i < numLeases; i++)
			{
				if (offset + LEASE2_SIZE > len) return 0;
				Lease lease;
				lease.tunnelGateway = buf + offset; offset += 32; // gateway
				lease.tunnelID = bufbe32toh (buf + offset); offset += 4; // tunnel ID
				lease.endDate = bufbe32toh (buf + offset)*1000LL; offset += 4; // end date
				UpdateLease (lease, ts);
			}
			UpdateLeasesEnd ();
		}
		else
			offset += numLeases*LEASE2_SIZE; // 40 bytes per lease
		return offset;
	}

	size_t LeaseSet2::ReadMetaLS2TypeSpecificPart (const uint8_t * buf, size_t len)
	{
		size_t offset = 0;
		// properties
		uint16_t propertiesLen = bufbe16toh (buf + offset); offset += 2;
		offset += propertiesLen; // skip for now. TODO: implement properties
		// entries
		if (offset + 1 >= len) return 0;
		int numEntries = buf[offset]; offset++;
		for (int i = 0; i < numEntries; i++)
		{
			if (offset + 40 >= len) return 0;
			offset += 32; // hash
			offset += 3; // flags
			offset += 1; // cost
			offset += 4; // expires
		}
		// revocations
		if (offset + 1 >= len) return 0;
		int numRevocations = buf[offset]; offset++;
		for (int i = 0; i < numRevocations; i++)
		{
			if (offset + 32 > len) return 0;
			offset += 32; // hash
		}
		return offset;
	}

	void LeaseSet2::ReadFromBufferEncrypted (const uint8_t * buf, size_t len, std::shared_ptr<const BlindedPublicKey> key, const uint8_t * secret)
	{
		size_t offset = 0;
		// blinded key
		if (len < 2) return;
		const uint8_t * stA1 = buf + offset; // stA1 = blinded signature type, 2 bytes big endian
		uint16_t blindedKeyType = bufbe16toh (stA1); offset += 2;
		std::unique_ptr<i2p::crypto::Verifier> blindedVerifier (i2p::data::IdentityEx::CreateVerifier (blindedKeyType));
		if (!blindedVerifier) return;
		auto blindedKeyLen = blindedVerifier->GetPublicKeyLen ();
		if (offset + blindedKeyLen >= len) return;
		const uint8_t * blindedPublicKey = buf + offset;
		blindedVerifier->SetPublicKey (blindedPublicKey); offset += blindedKeyLen;
		// expiration
		if (offset + 8 >= len) return;
		const uint8_t * publishedTimestamp = buf + offset;
		m_PublishedTimestamp = bufbe32toh (publishedTimestamp); offset += 4; // published timestamp (seconds)
		uint16_t expires = bufbe16toh (buf + offset); offset += 2; // expires (seconds)
		SetExpirationTime ((m_PublishedTimestamp + expires)*1000LL); // in milliseconds
		uint16_t flags = bufbe16toh (buf + offset); offset += 2; // flags
		if (flags & LEASESET2_FLAG_OFFLINE_KEYS)
		{
			// transient key
			m_TransientVerifier = ProcessOfflineSignature (blindedVerifier, buf, len, offset);
			if (!m_TransientVerifier)
			{
				LogPrint (eLogError, "LeaseSet2: offline signature failed");
				return;
			}
		}
		// outer ciphertext
		if (offset + 2 > len) return;
		uint16_t lenOuterCiphertext = bufbe16toh (buf + offset); offset += 2;
		const uint8_t * outerCiphertext = buf + offset;
		offset += lenOuterCiphertext;
		// verify signature
		bool verified = m_TransientVerifier ? VerifySignature (m_TransientVerifier, buf, len, offset) :
			VerifySignature (blindedVerifier, buf, len, offset);
		SetIsValid (verified);
		// handle ciphertext
		if (verified && key && lenOuterCiphertext >= 32)
		{
			SetIsValid (false); // we must verify it again in Layer 2
			if (blindedKeyType == key->GetBlindedSigType ())
			{
				// verify blinding
				char date[9];
				i2p::util::GetDateString (m_PublishedTimestamp, date);
				std::vector<uint8_t> blinded (blindedKeyLen);
				key->GetBlindedKey (date, blinded.data ());
				if (memcmp (blindedPublicKey, blinded.data (), blindedKeyLen))
				{
					LogPrint (eLogError, "LeaseSet2: blinded public key doesn't match");
					return;
				}
			}
			else
			{
				LogPrint (eLogError, "LeaseSet2: Unexpected blinded key type ", blindedKeyType, " instead ", key->GetBlindedSigType ());
				return;
			}
			// outer key
			// outerInput = subcredential || publishedTimestamp
			uint8_t subcredential[36];
			key->GetSubcredential (blindedPublicKey, blindedKeyLen, subcredential);
			memcpy (subcredential + 32, publishedTimestamp, 4);
			// outerSalt = outerCiphertext[0:32]
			// keys = HKDF(outerSalt, outerInput, "ELS2_L1K", 44)
			uint8_t keys[64]; // 44 bytes actual data
			i2p::crypto::HKDF (outerCiphertext, subcredential, 36, "ELS2_L1K", keys);
			// decrypt Layer 1
			// outerKey = keys[0:31]
			// outerIV = keys[32:43]
			size_t lenOuterPlaintext = lenOuterCiphertext - 32;
			std::vector<uint8_t> outerPlainText (lenOuterPlaintext);
			i2p::crypto::ChaCha20 (outerCiphertext + 32, lenOuterPlaintext, keys, keys + 32, outerPlainText.data ());
			// inner key
			// innerInput = authCookie || subcredential || publishedTimestamp
			// innerSalt = innerCiphertext[0:32]
			// keys = HKDF(innerSalt, innerInput, "ELS2_L2K", 44)
			uint8_t innerInput[68];
			size_t authDataLen = ExtractClientAuthData (outerPlainText.data (), lenOuterPlaintext, secret, subcredential, innerInput);
			if (authDataLen > 0)
			{
				memcpy (innerInput + 32, subcredential, 36);
				i2p::crypto::HKDF (outerPlainText.data () + 1 + authDataLen, innerInput, 68, "ELS2_L2K", keys);
			}
			else
				// no authData presented, innerInput = subcredential || publishedTimestamp
				// skip 1 byte flags
				i2p::crypto::HKDF (outerPlainText.data () + 1, subcredential, 36, "ELS2_L2K", keys); // no authCookie
			// decrypt Layer 2
			// innerKey = keys[0:31]
			// innerIV = keys[32:43]
			size_t lenInnerPlaintext = lenOuterPlaintext - 32 - 1 - authDataLen;
			std::vector<uint8_t> innerPlainText (lenInnerPlaintext);
			i2p::crypto::ChaCha20 (outerPlainText.data () + 32 + 1 + authDataLen, lenInnerPlaintext, keys, keys + 32, innerPlainText.data ());
			if (innerPlainText[0] == NETDB_STORE_TYPE_STANDARD_LEASESET2 || innerPlainText[0] == NETDB_STORE_TYPE_META_LEASESET2)
			{
				// override store type and buffer
				m_StoreType = innerPlainText[0];
				SetBuffer (innerPlainText.data () + 1, lenInnerPlaintext - 1);
				// parse and verify Layer 2
				ReadFromBuffer (innerPlainText.data () + 1, lenInnerPlaintext - 1);
			}
			else
				LogPrint (eLogError, "LeaseSet2: unexpected LeaseSet type ", (int)innerPlainText[0], " inside encrypted LeaseSet");
		}
		else
		{
			// we set actual length of encrypted buffer
			offset += m_TransientVerifier ? m_TransientVerifier->GetSignatureLen () : blindedVerifier->GetSignatureLen ();
			SetBufferLen (offset);
		}
	}

	// helper for ExtractClientAuthData
	static inline bool GetAuthCookie (const uint8_t * authClients, int numClients, const uint8_t * okm, uint8_t * authCookie)
	{
		// try to find clientCookie_i  for clientID_i = okm[44:51]
		for (int i = 0; i < numClients; i++)
		{
			if (!memcmp (okm + 44, authClients + i*40, 8)) // clientID_i
			{
				// clientKey_i = okm[0:31]
				// clientIV_i = okm[32:43]
				i2p::crypto::ChaCha20 (authClients + i*40 + 8, 32, okm, okm + 32, authCookie); // clientCookie_i
				return true;
			}
		}
		return false;
	}

	size_t LeaseSet2::ExtractClientAuthData (const uint8_t * buf, size_t len, const uint8_t * secret, const uint8_t * subcredential, uint8_t * authCookie) const
	{
		size_t offset = 0;
		uint8_t flag = buf[offset]; offset++; // flag
		if (flag & 0x01) // client auth
		{
			if (!(flag & 0x0E)) // DH, bit 1-3 all zeroes
			{
				const uint8_t * ephemeralPublicKey = buf + offset; offset += 32; // ephemeralPublicKey
				uint16_t numClients = bufbe16toh (buf + offset); offset += 2; // clients
				const uint8_t * authClients = buf + offset; offset +=  numClients*40; // authClients
				if (offset > len)
				{
					LogPrint (eLogError, "LeaseSet2: Too many clients ", numClients, " in DH auth data");
					return 0;
				}
				// calculate authCookie
				if (secret)
				{
					i2p::crypto::X25519Keys ck (secret, nullptr); // derive cpk_i from csk_i
					uint8_t authInput[100];
					ck.Agree (ephemeralPublicKey, authInput); // sharedSecret is first 32 bytes of authInput
					memcpy (authInput + 32, ck.GetPublicKey (), 32); // cpk_i
					memcpy (authInput + 64, subcredential, 36);
					uint8_t okm[64]; // 52 actual data
					i2p::crypto::HKDF (ephemeralPublicKey, authInput, 100, "ELS2_XCA", okm);
					if (!GetAuthCookie (authClients, numClients, okm, authCookie))
						LogPrint (eLogError, "LeaseSet2: Client cookie DH not found");
				}
				else
					LogPrint (eLogError, "LeaseSet2: Can't calculate authCookie: csk_i is not provided");
			}
			else if (flag & 0x02) // PSK, bit 1 is set to 1
			{
				const uint8_t * authSalt = buf + offset; offset += 32; // authSalt
				uint16_t numClients = bufbe16toh (buf + offset); offset += 2; // clients
				const uint8_t * authClients = buf + offset; offset +=  numClients*40; // authClients
				if (offset > len)
				{
					LogPrint (eLogError, "LeaseSet2: Too many clients ", numClients, " in PSK auth data");
					return 0;
				}
				// calculate authCookie
				if (secret)
				{
					uint8_t authInput[68];
					memcpy (authInput, secret, 32);
					memcpy (authInput + 32, subcredential, 36);
					uint8_t okm[64]; // 52 actual data
					i2p::crypto::HKDF (authSalt, authInput, 68, "ELS2PSKA", okm);
					if (!GetAuthCookie (authClients, numClients, okm, authCookie))
						LogPrint (eLogError, "LeaseSet2: Client cookie PSK not found");
				}
				else
					LogPrint (eLogError, "LeaseSet2: Can't calculate authCookie: psk_i is not provided");
			}
			else
				LogPrint (eLogError, "LeaseSet2: unknown client auth type ", (int)flag);
		}
		return offset - 1;
	}

	void LeaseSet2::Encrypt (const uint8_t * data, uint8_t * encrypted, BN_CTX * ctx) const
	{
		auto encryptor = m_Encryptor; // TODO: atomic
		if (encryptor)
			encryptor->Encrypt (data, encrypted, ctx, true);
	}

	uint64_t LeaseSet2::ExtractExpirationTimestamp (const uint8_t * buf, size_t len) const
	{
		uint64_t expiration = 0;
		ExtractPublishedTimestamp (buf, len, expiration);
		return expiration;
	}

	uint64_t LeaseSet2::ExtractPublishedTimestamp (const uint8_t * buf, size_t len, uint64_t& expiration) const
	{
		if (len < 8) return 0;
		if (m_StoreType == NETDB_STORE_TYPE_ENCRYPTED_LEASESET2)
		{
			// encrypted LS2
			size_t offset = 0;
			uint16_t blindedKeyType = bufbe16toh (buf + offset); offset += 2;
			std::unique_ptr<i2p::crypto::Verifier> blindedVerifier (i2p::data::IdentityEx::CreateVerifier (blindedKeyType));
			if (!blindedVerifier) return 0 ;
			auto blindedKeyLen = blindedVerifier->GetPublicKeyLen ();
			if (offset + blindedKeyLen + 6 >= len) return 0;
			offset += blindedKeyLen;
			uint32_t timestamp = bufbe32toh (buf + offset); offset += 4;
			uint16_t expires = bufbe16toh (buf + offset); offset += 2;
			expiration = (timestamp + expires)* 1000LL;
			return timestamp;
		}
		else
		{
			auto identity = GetIdentity ();
			if (!identity) return 0;
			size_t offset = identity->GetFullLen ();
			if (offset + 6 >= len) return 0;
			uint32_t timestamp = bufbe32toh (buf + offset); offset += 4;
			uint16_t expires = bufbe16toh (buf + offset); offset += 2;
			expiration = (timestamp + expires)* 1000LL;
			return timestamp;
		}
	}

	LocalLeaseSet::LocalLeaseSet (std::shared_ptr<const IdentityEx> identity, const uint8_t * encryptionPublicKey, std::vector<std::shared_ptr<i2p::tunnel::InboundTunnel> > tunnels):
		m_ExpirationTime (0), m_Identity (identity)
	{
		int num = tunnels.size ();
		if (num > MAX_NUM_LEASES) num = MAX_NUM_LEASES;
		// identity
		auto signingKeyLen = m_Identity->GetSigningPublicKeyLen ();
		m_BufferLen = m_Identity->GetFullLen () + 256 + signingKeyLen + 1 + num*LEASE_SIZE + m_Identity->GetSignatureLen ();
		m_Buffer = new uint8_t[m_BufferLen];
		auto offset = m_Identity->ToBuffer (m_Buffer, m_BufferLen);
		memcpy (m_Buffer + offset, encryptionPublicKey, 256);
		offset += 256;
		memset (m_Buffer + offset, 0, signingKeyLen);
		offset += signingKeyLen;
		// num leases
		m_Buffer[offset] = num;
		offset++;
		// leases
		m_Leases = m_Buffer + offset;
		auto currentTime = i2p::util::GetMillisecondsSinceEpoch ();
		for (int i = 0; i < num; i++)
		{
			memcpy (m_Buffer + offset, tunnels[i]->GetNextIdentHash (), 32);
			offset += 32; // gateway id
			htobe32buf (m_Buffer + offset, tunnels[i]->GetNextTunnelID ());
			offset += 4; // tunnel id
			uint64_t ts = tunnels[i]->GetCreationTime () + i2p::tunnel::TUNNEL_EXPIRATION_TIMEOUT - i2p::tunnel::TUNNEL_EXPIRATION_THRESHOLD; // 1 minute before expiration
			ts *= 1000; // in milliseconds
			if (ts > m_ExpirationTime) m_ExpirationTime = ts;
			// make sure leaseset is newer than previous, but adding some time to expiration date
			ts += (currentTime - tunnels[i]->GetCreationTime ()*1000LL)*2/i2p::tunnel::TUNNEL_EXPIRATION_TIMEOUT; // up to 2 secs
			htobe64buf (m_Buffer + offset, ts);
			offset += 8; // end date
		}
		//  we don't sign it yet. must be signed later on
	}

	LocalLeaseSet::LocalLeaseSet (std::shared_ptr<const IdentityEx> identity, const uint8_t * buf, size_t len):
		m_ExpirationTime (0), m_Identity (identity)
	{
		if (buf)
		{
			m_BufferLen = len;
			m_Buffer = new uint8_t[m_BufferLen];
			memcpy (m_Buffer, buf, len);
		}
		else
		{
			m_Buffer = nullptr;
			m_BufferLen = 0;
		}
	}

	bool LocalLeaseSet::IsExpired () const
	{
		auto ts = i2p::util::GetMillisecondsSinceEpoch ();
		return ts > m_ExpirationTime;
	}

	bool LeaseSetBufferValidate(const uint8_t * ptr, size_t sz, uint64_t & expires)
	{
		IdentityEx ident(ptr, sz);
		size_t size = ident.GetFullLen ();
		if (size > sz)
		{
			LogPrint (eLogError, "LeaseSet: identity length ", size, " exceeds buffer size ", sz);
			return false;
		}
		// encryption key
		size += 256;
		// signing key (unused)
		size += ident.GetSigningPublicKeyLen ();
		uint8_t numLeases = ptr[size];
		++size;
		if (!numLeases || numLeases > MAX_NUM_LEASES)
		{
			LogPrint (eLogError, "LeaseSet: incorrect number of leases", (int)numLeases);
			return false;
		}
		const uint8_t * leases = ptr + size;
		expires = 0;
		/** find lease with the max expiration timestamp */
		for (int i = 0; i < numLeases; i++)
		{
			leases += 36; // gateway + tunnel ID
			uint64_t endDate = bufbe64toh (leases);
			leases += 8; // end date
			if(endDate > expires)
				expires = endDate;
		}
		return ident.Verify(ptr, leases - ptr, leases);
	}

	LocalLeaseSet2::LocalLeaseSet2 (uint8_t storeType, const i2p::data::PrivateKeys& keys,
		const KeySections& encryptionKeys, const std::vector<std::shared_ptr<i2p::tunnel::InboundTunnel> >& tunnels,
		bool isPublic, bool isPublishedEncrypted):
		LocalLeaseSet (keys.GetPublic (), nullptr, 0)
	{
		auto identity = keys.GetPublic ();
		// assume standard LS2
		int num = tunnels.size ();
		if (num > MAX_NUM_LEASES) num = MAX_NUM_LEASES;
		size_t keySectionsLen = 0;
		for (const auto& it: encryptionKeys)
			keySectionsLen += 2/*key type*/ + 2/*key len*/ + it.keyLen/*key*/;
		m_BufferLen = identity->GetFullLen () + 4/*published*/ + 2/*expires*/ + 2/*flag*/ + 2/*properties len*/ +
			1/*num keys*/ + keySectionsLen + 1/*num leases*/ + num*LEASE2_SIZE + keys.GetSignatureLen ();
		uint16_t flags = 0;
		if (keys.IsOfflineSignature ())
		{
			flags |= LEASESET2_FLAG_OFFLINE_KEYS;
			m_BufferLen += keys.GetOfflineSignature ().size ();
		}
		if (isPublishedEncrypted)
		{
			flags |= LEASESET2_FLAG_PUBLISHED_ENCRYPTED;
			isPublic = true;
		}
		if (!isPublic) flags |= LEASESET2_FLAG_UNPUBLISHED_LEASESET;

		m_Buffer = new uint8_t[m_BufferLen + 1];
		m_Buffer[0] = storeType;
		// LS2 header
		auto offset = identity->ToBuffer (m_Buffer + 1, m_BufferLen) + 1;
		auto timestamp = i2p::util::GetSecondsSinceEpoch ();
		htobe32buf (m_Buffer + offset, timestamp); offset += 4; // published timestamp (seconds)
		uint8_t * expiresBuf = m_Buffer + offset; offset += 2; // expires, fill later
		htobe16buf (m_Buffer + offset, flags); offset += 2; // flags
		if (keys.IsOfflineSignature ())
		{
			// offline signature
			const auto& offlineSignature = keys.GetOfflineSignature ();
			memcpy (m_Buffer + offset, offlineSignature.data (), offlineSignature.size ());
			offset += offlineSignature.size ();
		}
		htobe16buf (m_Buffer + offset, 0); offset += 2; // properties len
		// keys
		m_Buffer[offset] = encryptionKeys.size (); offset++; // 1 key
		for (const auto& it: encryptionKeys)
		{
			htobe16buf (m_Buffer + offset, it.keyType); offset += 2; // key type
			htobe16buf (m_Buffer + offset, it.keyLen); offset += 2; // key len
			memcpy (m_Buffer + offset, it.encryptionPublicKey, it.keyLen); offset += it.keyLen; // key
		}
		// leases
		uint32_t expirationTime = 0; // in seconds
		m_Buffer[offset] = num; offset++; // num leases
		for (int i = 0; i < num; i++)
		{
			memcpy (m_Buffer + offset, tunnels[i]->GetNextIdentHash (), 32);
			offset += 32; // gateway id
			htobe32buf (m_Buffer + offset, tunnels[i]->GetNextTunnelID ());
			offset += 4; // tunnel id
			auto ts = tunnels[i]->GetCreationTime () + i2p::tunnel::TUNNEL_EXPIRATION_TIMEOUT - i2p::tunnel::TUNNEL_EXPIRATION_THRESHOLD; // in seconds, 1 minute before expiration
			if (ts > expirationTime) expirationTime = ts;
			htobe32buf (m_Buffer + offset, ts);
			offset += 4; // end date
		}
		// update expiration
		if (expirationTime)
		{		
			SetExpirationTime (expirationTime*1000LL);
			auto expires = (int)expirationTime - timestamp;
			htobe16buf (expiresBuf, expires > 0 ? expires : 0);
		}	
		else
		{
			// no tunnels or withdraw
			SetExpirationTime (timestamp*1000LL);
			memset (expiresBuf, 0, 2); // expires immeditely
		}		
		// sign
		keys.Sign (m_Buffer, offset, m_Buffer + offset); // LS + leading store type
	}

	LocalLeaseSet2::LocalLeaseSet2 (uint8_t storeType, std::shared_ptr<const IdentityEx> identity, const uint8_t * buf, size_t len):
		LocalLeaseSet (identity, nullptr, 0)
	{
		m_BufferLen = len;
		m_Buffer = new uint8_t[m_BufferLen + 1];
		memcpy (m_Buffer + 1, buf, len);
		m_Buffer[0] = storeType;
	}

	LocalEncryptedLeaseSet2::LocalEncryptedLeaseSet2 (std::shared_ptr<const LocalLeaseSet2> ls, const i2p::data::PrivateKeys& keys,
		int authType, std::shared_ptr<std::vector<AuthPublicKey> > authKeys):
		LocalLeaseSet2 (ls->GetIdentity ()), m_InnerLeaseSet (ls)
	{
		size_t lenInnerPlaintext = ls->GetBufferLen () + 1, lenOuterPlaintext = lenInnerPlaintext + 32 + 1;
		uint8_t layer1Flags = 0;
		if (authKeys)
		{
			if (authType == ENCRYPTED_LEASESET_AUTH_TYPE_DH) layer1Flags |= 0x01; // DH, authentication scheme 0, auth bit 1
			else if (authType == ENCRYPTED_LEASESET_AUTH_TYPE_PSK) layer1Flags |= 0x03; // PSK, authentication scheme 1, auth bit 1
			if (layer1Flags)
				lenOuterPlaintext += 32 + 2 + authKeys->size ()*40; // auth data len
		}
		size_t lenOuterCiphertext = lenOuterPlaintext + 32;

		m_BufferLen = 2/*blinded sig type*/ + 32/*blinded pub key*/ + 4/*published*/ + 2/*expires*/ + 2/*flags*/ + 2/*lenOuterCiphertext*/ + lenOuterCiphertext + 64/*signature*/;
		m_Buffer = new uint8_t[m_BufferLen + 1];
		m_Buffer[0] = NETDB_STORE_TYPE_ENCRYPTED_LEASESET2;
		BlindedPublicKey blindedKey (ls->GetIdentity ());
		auto timestamp = i2p::util::GetSecondsSinceEpoch ();
		char date[9];
		i2p::util::GetDateString (timestamp, date);
		uint8_t blindedPriv[64], blindedPub[128]; // 64 and 128 max
		size_t publicKeyLen = blindedKey.BlindPrivateKey (keys.GetSigningPrivateKey (), date, blindedPriv, blindedPub);
		std::unique_ptr<i2p::crypto::Signer> blindedSigner (i2p::data::PrivateKeys::CreateSigner (blindedKey.GetBlindedSigType (), blindedPriv));
		auto offset = 1;
		htobe16buf (m_Buffer + offset, blindedKey.GetBlindedSigType ()); offset += 2; // Blinded Public Key Sig Type
		memcpy (m_Buffer + offset, blindedPub, publicKeyLen); offset += publicKeyLen; // Blinded Public Key
		htobe32buf (m_Buffer + offset, timestamp); offset += 4; // published timestamp (seconds)
		auto nextMidnight = (timestamp/86400LL + 1)*86400LL; // 86400 = 24*3600 seconds
		auto expirationTime = ls->GetExpirationTime ()/1000LL;
		if (expirationTime > nextMidnight) expirationTime = nextMidnight;
		SetExpirationTime (expirationTime*1000LL);
		htobe16buf (m_Buffer + offset, expirationTime > timestamp ? expirationTime - timestamp : 0); offset += 2; // expires
		uint16_t flags = 0;
		htobe16buf (m_Buffer + offset, flags); offset += 2; // flags
		htobe16buf (m_Buffer + offset, lenOuterCiphertext); offset += 2; // lenOuterCiphertext
		// outerChipherText
		// Layer 1
		uint8_t subcredential[36];
		blindedKey.GetSubcredential (blindedPub, 32, subcredential);
		htobe32buf (subcredential + 32, timestamp); // outerInput = subcredential || publishedTimestamp
		// keys = HKDF(outerSalt, outerInput, "ELS2_L1K", 44)
		uint8_t keys1[64]; // 44 bytes actual data
		RAND_bytes (m_Buffer + offset, 32); // outerSalt = CSRNG(32)
		i2p::crypto::HKDF (m_Buffer + offset, subcredential, 36, "ELS2_L1K", keys1);
		offset += 32; // outerSalt
		uint8_t * outerPlainText = m_Buffer + offset;
		m_Buffer[offset] = layer1Flags; offset++; // layer 1 flags
		// auth data
		uint8_t innerInput[68];	// authCookie || subcredential || publishedTimestamp
		if (layer1Flags)
		{
			RAND_bytes (innerInput, 32); // authCookie
			CreateClientAuthData (subcredential, authType, authKeys, innerInput, m_Buffer + offset);
			offset += 32 + 2 + authKeys->size ()*40; // auth clients
		}
		// Layer 2
		// keys = HKDF(outerSalt, outerInput, "ELS2_L2K", 44)
		uint8_t keys2[64]; // 44 bytes actual data
		RAND_bytes (m_Buffer + offset, 32); // innerSalt = CSRNG(32)
		if (layer1Flags)
		{
			memcpy (innerInput + 32, subcredential, 36); // + subcredential || publishedTimestamp
			i2p::crypto::HKDF (m_Buffer + offset, innerInput, 68, "ELS2_L2K", keys2);
		}
		else
			i2p::crypto::HKDF (m_Buffer + offset, subcredential, 36, "ELS2_L2K", keys2); // no authCookie
		offset += 32; // innerSalt
		m_Buffer[offset] = ls->GetStoreType ();
		memcpy (m_Buffer + offset + 1, ls->GetBuffer (), ls->GetBufferLen ());
		i2p::crypto::ChaCha20 (m_Buffer + offset, lenInnerPlaintext, keys2, keys2 + 32, m_Buffer + offset); // encrypt Layer 2
		offset += lenInnerPlaintext;
		i2p::crypto::ChaCha20 (outerPlainText, lenOuterPlaintext, keys1, keys1 + 32, outerPlainText); // encrypt Layer 1
		// signature
		blindedSigner->Sign (m_Buffer, offset, m_Buffer + offset);
		// store hash
		m_StoreHash = blindedKey.GetStoreHash (date);
	}

	LocalEncryptedLeaseSet2::LocalEncryptedLeaseSet2 (std::shared_ptr<const IdentityEx> identity, const uint8_t * buf, size_t len):
		LocalLeaseSet2 (NETDB_STORE_TYPE_ENCRYPTED_LEASESET2, identity, buf, len)
	{
		// fill inner LeaseSet2
		auto blindedKey = std::make_shared<BlindedPublicKey>(identity);
		i2p::data::LeaseSet2 ls (buf, len, blindedKey); // inner layer
		if (ls.IsValid ())
		{
			m_InnerLeaseSet = std::make_shared<LocalLeaseSet2>(ls.GetStoreType (), identity, ls.GetBuffer (), ls.GetBufferLen ());
			m_StoreHash = blindedKey->GetStoreHash ();
		}
		else
			LogPrint (eLogError, "LeaseSet2: couldn't extract inner layer");
	}

	void LocalEncryptedLeaseSet2::CreateClientAuthData (const uint8_t * subcredential, int authType, std::shared_ptr<std::vector<AuthPublicKey> > authKeys, const uint8_t * authCookie, uint8_t * authData) const
	{
		if (authType == ENCRYPTED_LEASESET_AUTH_TYPE_DH)
		{
			i2p::crypto::X25519Keys ek;
			ek.GenerateKeys (); // esk and epk
			memcpy (authData, ek.GetPublicKey (), 32); authData += 32; // epk
			htobe16buf (authData, authKeys->size ()); authData += 2; // num clients
			uint8_t authInput[100]; //  sharedSecret || cpk_i || subcredential || publishedTimestamp
			memcpy (authInput + 64, subcredential, 36);
			for (auto& it: *authKeys)
			{
				ek.Agree (it, authInput); // sharedSecret = DH(esk, cpk_i)
				memcpy (authInput + 32, it, 32);
				uint8_t okm[64]; // 52 actual data
				i2p::crypto::HKDF (ek.GetPublicKey (), authInput, 100, "ELS2_XCA", okm);
				memcpy (authData, okm + 44, 8); authData += 8; // clientID_i
				i2p::crypto::ChaCha20 (authCookie, 32, okm, okm + 32, authData); authData += 32; // clientCookie_i
			}
		}
		else // assume PSK
		{
			uint8_t authSalt[32];
			RAND_bytes (authSalt, 32);
			memcpy (authData, authSalt, 32); authData += 32; // authSalt
			htobe16buf (authData, authKeys->size ()); authData += 2; // num clients
			uint8_t authInput[68]; // authInput = psk_i || subcredential || publishedTimestamp
			memcpy (authInput + 32, subcredential, 36);
			for (auto& it: *authKeys)
			{
				memcpy (authInput, it, 32);
				uint8_t okm[64]; // 52 actual data
				i2p::crypto::HKDF (authSalt, authInput, 68, "ELS2PSKA", okm);
				memcpy (authData, okm + 44, 8); authData += 8; // clientID_i
				i2p::crypto::ChaCha20 (authCookie, 32, okm, okm + 32, authData); authData += 32; // clientCookie_i
			}
		}
	}
}
}
