/*
* Copyright (c) 2013-2020, The PurpleI2P Project
*
* This file is part of Purple i2pd project and licensed under BSD3
*
* See full license text in LICENSE file at top of project tree
*/

#ifndef ECIES_X25519_AEAD_RATCHET_SESSION_H__
#define ECIES_X25519_AEAD_RATCHET_SESSION_H__

#include <string.h>
#include <inttypes.h>
#include <functional>
#include <memory>
#include <vector>
#include <list>
#include <unordered_map>
#include "Identity.h"
#include "Crypto.h"
#include "Garlic.h"
#include "Tag.h"

namespace i2p
{
namespace garlic
{
	const int ECIESX25519_RESTART_TIMEOUT = 120; // number of second since session creation we can restart session after
	const int ECIESX25519_EXPIRATION_TIMEOUT = 480; // in seconds
	const int ECIESX25519_INACTIVITY_TIMEOUT = 90; // number of seconds we receive nothing and should restart if we can
	const int ECIESX25519_SEND_INACTIVITY_TIMEOUT = 5000; // number of milliseconds we can send empty(pyaload only) packet after 
	const int ECIESX25519_INCOMING_TAGS_EXPIRATION_TIMEOUT = 600; // in seconds
	const int ECIESX25519_PREVIOUS_TAGSET_EXPIRATION_TIMEOUT = 180; // 180
	const int ECIESX25519_TAGSET_MAX_NUM_TAGS = 4096; // number of tags we request new tagset after
	const int ECIESX25519_MIN_NUM_GENERATED_TAGS = 24;
	const int ECIESX25519_MAX_NUM_GENERATED_TAGS = 160;
	const int ECIESX25519_NSR_NUM_GENERATED_TAGS = 12;

	const size_t ECIESX25519_OPTIMAL_PAYLOAD_SIZE = 1912; // 1912 = 1956 /* to fit 2 tunnel messages */
	// - 16 /* I2NP header */ - 16 /* poly hash */ - 8 /* tag */ - 4 /* garlic length */

	class ECIESX25519AEADRatchetSession;
	class RatchetTagSet: public std::enable_shared_from_this<RatchetTagSet>
	{
		public:

			RatchetTagSet (std::shared_ptr<ECIESX25519AEADRatchetSession> session): m_Session (session) {};

			void DHInitialize (const uint8_t * rootKey, const uint8_t * k);
			void NextSessionTagRatchet ();
			uint64_t GetNextSessionTag ();
			const uint8_t * GetNextRootKey () const { return m_NextRootKey; };
			int GetNextIndex () const { return m_NextIndex; };
			void GetSymmKey (int index, uint8_t * key);
			void DeleteSymmKey (int index);

			std::shared_ptr<ECIESX25519AEADRatchetSession> GetSession () { return m_Session.lock (); };
			int GetTagSetID () const { return m_TagSetID; };
			void SetTagSetID (int tagsetID) { m_TagSetID = tagsetID; };
			void SetTrimBehind (int index) { if (index > m_TrimBehindIndex) m_TrimBehindIndex = index; }; 

			void Expire ();
			bool IsExpired (uint64_t ts) const { return m_ExpirationTimestamp && ts > m_ExpirationTimestamp; };
			virtual bool IsIndexExpired (int index) const { return m_Session.expired () || index < m_TrimBehindIndex; };

			virtual bool HandleNextMessage (uint8_t * buf, size_t len, int index);
			
		private:

			union
			{
				uint64_t ll[8];
				uint8_t buf[64];

				const uint8_t * GetSessTagCK () const { return buf; }; // sessTag_chainKey = keydata[0:31]
				const uint8_t * GetSessTagConstant () const { return buf + 32; }; // SESSTAG_CONSTANT = keydata[32:63]
				uint64_t GetTag () const { return ll[4]; }; // tag = keydata[32:39]

			} m_KeyData;
			uint8_t m_SessTagConstant[32], m_SymmKeyCK[32], m_CurrentSymmKeyCK[64], m_NextRootKey[32];
			int m_NextIndex, m_NextSymmKeyIndex, m_TrimBehindIndex = 0;
			std::unordered_map<int, i2p::data::Tag<32> > m_ItermediateSymmKeys;
			std::weak_ptr<ECIESX25519AEADRatchetSession> m_Session;
			int m_TagSetID = 0;
			uint64_t m_ExpirationTimestamp = 0;
	};

	class NSRatchetTagSet: public RatchetTagSet
	{
		public:
			
			NSRatchetTagSet (std::shared_ptr<ECIESX25519AEADRatchetSession> session):
				RatchetTagSet (session), m_DummySession (session) {};
			
		private:

			std::shared_ptr<ECIESX25519AEADRatchetSession> m_DummySession; // we need a strong pointer for NS
	};	

	class DatabaseLookupTagSet: public RatchetTagSet
	{
		public:

			DatabaseLookupTagSet (GarlicDestination * destination, const uint8_t * key);

			bool IsIndexExpired (int index) const { return false; };
			bool HandleNextMessage (uint8_t * buf, size_t len, int index);
			
		private:

			GarlicDestination * m_Destination;
			uint8_t m_Key[32];
	};	
	
	enum ECIESx25519BlockType
	{
		eECIESx25519BlkDateTime    = 0,
		eECIESx25519BlkSessionID   = 1,
		eECIESx25519BlkTermination = 4,
		eECIESx25519BlkOptions     = 5,
		eECIESx25519BlkNextKey     = 7,
		eECIESx25519BlkAck         = 8,
		eECIESx25519BlkAckRequest  = 9,
		eECIESx25519BlkGalicClove  = 11,
		eECIESx25519BlkPadding     = 254
	};

	const uint8_t ECIESX25519_NEXT_KEY_KEY_PRESENT_FLAG = 0x01;
	const uint8_t ECIESX25519_NEXT_KEY_REVERSE_KEY_FLAG = 0x02;
	const uint8_t ECIESX25519_NEXT_KEY_REQUEST_REVERSE_KEY_FLAG = 0x04;

	class ECIESX25519AEADRatchetSession: public GarlicRoutingSession, public std::enable_shared_from_this<ECIESX25519AEADRatchetSession>
	{
		enum SessionState
		{
			eSessionStateNew = 0,
			eSessionStateNewSessionReceived,
			eSessionStateNewSessionSent,
			eSessionStateNewSessionReplySent,
			eSessionStateEstablished
		};

		struct DHRatchet
		{
			int keyID = 0;
			std::shared_ptr<i2p::crypto::X25519Keys> key;
			uint8_t remote[32]; // last remote public key
			bool newKey = true;
		};

		public:

			ECIESX25519AEADRatchetSession (GarlicDestination * owner, bool attachLeaseSet);
			~ECIESX25519AEADRatchetSession ();

			bool HandleNextMessage (uint8_t * buf, size_t len, std::shared_ptr<RatchetTagSet> receiveTagset, int index = 0);
			std::shared_ptr<I2NPMessage> WrapSingleMessage (std::shared_ptr<const I2NPMessage> msg);

			const uint8_t * GetRemoteStaticKey () const { return m_RemoteStaticKey; }
			void SetRemoteStaticKey (const uint8_t * key) { memcpy (m_RemoteStaticKey, key, 32); }

			void SetDestination (const i2p::data::IdentHash& dest) // TODO:
			{
				if (!m_Destination) m_Destination.reset (new i2p::data::IdentHash (dest));
			}

			bool CheckExpired (uint64_t ts); // true is expired
			bool CanBeRestarted (uint64_t ts) const { return ts > m_SessionCreatedTimestamp + ECIESX25519_RESTART_TIMEOUT; }
			bool IsInactive (uint64_t ts) const { return ts > m_LastActivityTimestamp + ECIESX25519_INACTIVITY_TIMEOUT && CanBeRestarted (ts); }
			
			bool IsRatchets () const { return true; };
			uint64_t GetLastActivityTimestamp () const { return m_LastActivityTimestamp; };

		private:

			void ResetKeys ();
			void MixHash (const uint8_t * buf, size_t len);
			void CreateNonce (uint64_t seqn, uint8_t * nonce);
			bool GenerateEphemeralKeysAndEncode (uint8_t * buf); // buf is 32 bytes
			std::shared_ptr<RatchetTagSet> CreateNewSessionTagset ();

			bool HandleNewIncomingSession (const uint8_t * buf, size_t len);
			bool HandleNewOutgoingSessionReply (uint8_t * buf, size_t len);
			bool HandleExistingSessionMessage (uint8_t * buf, size_t len, std::shared_ptr<RatchetTagSet> receiveTagset, int index);
			void HandlePayload (const uint8_t * buf, size_t len, const std::shared_ptr<RatchetTagSet>& receiveTagset, int index);
			void HandleNextKey (const uint8_t * buf, size_t len, const std::shared_ptr<RatchetTagSet>& receiveTagset);

			bool NewOutgoingSessionMessage (const uint8_t * payload, size_t len, uint8_t * out, size_t outLen);
			bool NewSessionReplyMessage (const uint8_t * payload, size_t len, uint8_t * out, size_t outLen);
			bool NextNewSessionReplyMessage (const uint8_t * payload, size_t len, uint8_t * out, size_t outLen);
			bool NewExistingSessionMessage (const uint8_t * payload, size_t len, uint8_t * out, size_t outLen);

			std::vector<uint8_t> CreatePayload (std::shared_ptr<const I2NPMessage> msg, bool first);
			size_t CreateGarlicClove (std::shared_ptr<const I2NPMessage> msg, uint8_t * buf, size_t len);
			size_t CreateLeaseSetClove (std::shared_ptr<const i2p::data::LocalLeaseSet> ls, uint64_t ts, uint8_t * buf, size_t len);

			void GenerateMoreReceiveTags (std::shared_ptr<RatchetTagSet> receiveTagset, int numTags);
			void NewNextSendRatchet ();

		private:

			uint8_t m_H[32], m_CK[64] /* [chainkey, key] */, m_RemoteStaticKey[32];
			uint8_t m_Aepk[32]; // Alice's ephemeral keys, for incoming only
			uint8_t m_NSREncodedKey[32], m_NSRH[32], m_NSRKey[32]; // new session reply, for incoming only
			std::shared_ptr<i2p::crypto::X25519Keys> m_EphemeralKeys;
			SessionState m_State = eSessionStateNew;
			uint64_t m_SessionCreatedTimestamp = 0,  m_LastActivityTimestamp = 0, // incoming
				m_LastSentTimestamp = 0; // in milliseconds
			std::shared_ptr<RatchetTagSet> m_SendTagset, m_NSRSendTagset;
			std::unique_ptr<i2p::data::IdentHash> m_Destination;// TODO: might not need it
			std::list<std::pair<uint16_t, int> > m_AckRequests; // (tagsetid, index)
			bool m_SendReverseKey = false, m_SendForwardKey = false;
			std::unique_ptr<DHRatchet> m_NextReceiveRatchet, m_NextSendRatchet;
			uint8_t m_PaddingSizes[32], m_NextPaddingSize;
			
		public:

			// for HTTP only
			int GetState () const { return (int)m_State; }
			i2p::data::IdentHash GetDestination () const
			{
				return m_Destination ? *m_Destination : i2p::data::IdentHash ();
			}
	 };

	std::shared_ptr<I2NPMessage> WrapECIESX25519AEADRatchetMessage (std::shared_ptr<const I2NPMessage> msg, const uint8_t * key, uint64_t tag);
}
}

#endif
