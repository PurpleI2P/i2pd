/*
* Copyright (c) 2013-2020, The PurpleI2P Project
*
* This file is part of Purple i2pd project and licensed under BSD3
*
* See full license text in LICENSE file at top of project tree
*/

#ifndef GARLIC_H__
#define GARLIC_H__

#include <inttypes.h>
#include <unordered_map>
#include <list>
#include <string>
#include <thread>
#include <mutex>
#include <memory>
#include "Crypto.h"
#include "I2NPProtocol.h"
#include "LeaseSet.h"
#include "Queue.h"
#include "Identity.h"

namespace i2p
{
namespace tunnel
{
	class OutboundTunnel;
}

namespace garlic
{

	enum GarlicDeliveryType
	{
		eGarlicDeliveryTypeLocal = 0,
		eGarlicDeliveryTypeDestination = 1,
		eGarlicDeliveryTypeRouter = 2,
		eGarlicDeliveryTypeTunnel = 3
	};

	struct ElGamalBlock
	{
		uint8_t sessionKey[32];
		uint8_t preIV[32];
		uint8_t padding[158];
	};

	const int INCOMING_TAGS_EXPIRATION_TIMEOUT = 960; // 16 minutes
	const int OUTGOING_TAGS_EXPIRATION_TIMEOUT = 720; // 12 minutes
	const int OUTGOING_TAGS_CONFIRMATION_TIMEOUT = 10; // 10 seconds
	const int LEASET_CONFIRMATION_TIMEOUT = 4000; // in milliseconds
	const int ROUTING_PATH_EXPIRATION_TIMEOUT = 30; // 30 seconds
	const int ROUTING_PATH_MAX_NUM_TIMES_USED = 100; // how many times might be used

	struct SessionTag: public i2p::data::Tag<32>
	{
		SessionTag (const uint8_t * buf, uint32_t ts = 0): Tag<32>(buf), creationTime (ts) {};
		SessionTag () = default;
		SessionTag (const SessionTag& ) = default;
		SessionTag& operator= (const SessionTag& ) = default;
#ifndef _WIN32
		SessionTag (SessionTag&& ) = default;
		SessionTag& operator= (SessionTag&& ) = default;
#endif
		uint32_t creationTime; // seconds since epoch
	};

	// AESDecryption is associated with session tags and store key
	class AESDecryption: public i2p::crypto::CBCDecryption
	{
		public:

			AESDecryption (const uint8_t * key): m_Key (key)
			{
				SetKey (key);
			}
			const i2p::crypto::AESKey& GetKey () const { return m_Key; };

		private:

			i2p::crypto::AESKey m_Key;
	};

	struct GarlicRoutingPath
	{
		std::shared_ptr<i2p::tunnel::OutboundTunnel> outboundTunnel;
		std::shared_ptr<const i2p::data::Lease> remoteLease;
		int rtt; // RTT
		uint32_t updateTime; // seconds since epoch
		int numTimesUsed;
	};

	class GarlicDestination;
	class GarlicRoutingSession
	{
		protected:

			enum LeaseSetUpdateStatus
			{
				eLeaseSetUpToDate = 0,
				eLeaseSetUpdated,
				eLeaseSetSubmitted,
				eLeaseSetDoNotSend
			};

		public:

			GarlicRoutingSession (GarlicDestination * owner, bool attachLeaseSet);
			GarlicRoutingSession ();
			virtual ~GarlicRoutingSession ();
			virtual std::shared_ptr<I2NPMessage> WrapSingleMessage (std::shared_ptr<const I2NPMessage> msg) = 0;
			virtual bool CleanupUnconfirmedTags () { return false; }; // for I2CP, override in ElGamalAESSession
			virtual bool MessageConfirmed (uint32_t msgID);
			virtual bool IsRatchets () const { return false; };
			virtual bool IsReadyToSend () const { return true; };
			virtual bool IsTerminated () const { return !GetOwner (); }; 
			virtual uint64_t GetLastActivityTimestamp () const { return 0; }; // non-zero for rathets only

			void SetLeaseSetUpdated ()
			{
				if (m_LeaseSetUpdateStatus != eLeaseSetDoNotSend) m_LeaseSetUpdateStatus = eLeaseSetUpdated;
			};
			bool IsLeaseSetNonConfirmed () const { return m_LeaseSetUpdateStatus == eLeaseSetSubmitted; };
			bool IsLeaseSetUpdated () const { return m_LeaseSetUpdateStatus == eLeaseSetUpdated; };
			uint64_t GetLeaseSetSubmissionTime () const { return m_LeaseSetSubmissionTime; }
			void CleanupUnconfirmedLeaseSet (uint64_t ts);

			std::shared_ptr<GarlicRoutingPath> GetSharedRoutingPath ();
			void SetSharedRoutingPath (std::shared_ptr<GarlicRoutingPath> path);

			GarlicDestination * GetOwner () const { return m_Owner; }
			void SetOwner (GarlicDestination * owner) { m_Owner = owner; }

		protected:

			LeaseSetUpdateStatus GetLeaseSetUpdateStatus () const { return m_LeaseSetUpdateStatus; }
			void SetLeaseSetUpdateStatus (LeaseSetUpdateStatus status) { m_LeaseSetUpdateStatus = status; }
			uint32_t GetLeaseSetUpdateMsgID () const { return m_LeaseSetUpdateMsgID; }
			void SetLeaseSetUpdateMsgID (uint32_t msgID) { m_LeaseSetUpdateMsgID = msgID; }
			void SetLeaseSetSubmissionTime (uint64_t ts) { m_LeaseSetSubmissionTime = ts; }

			std::shared_ptr<I2NPMessage> CreateEncryptedDeliveryStatusMsg (uint32_t msgID);

		private:

			GarlicDestination * m_Owner;

			LeaseSetUpdateStatus m_LeaseSetUpdateStatus;
			uint32_t m_LeaseSetUpdateMsgID;
			uint64_t m_LeaseSetSubmissionTime; // in milliseconds

			std::shared_ptr<GarlicRoutingPath> m_SharedRoutingPath;

		public:

			// for HTTP only
			virtual size_t GetNumOutgoingTags () const { return 0; };
	};
	//using GarlicRoutingSessionPtr = std::shared_ptr<GarlicRoutingSession>;
	typedef std::shared_ptr<GarlicRoutingSession> GarlicRoutingSessionPtr; // TODO: replace to using after switch to 4.8

	class ElGamalAESSession: public GarlicRoutingSession,  public std::enable_shared_from_this<ElGamalAESSession>
	{
		struct UnconfirmedTags
		{
			UnconfirmedTags (int n): numTags (n), tagsCreationTime (0) { sessionTags = new SessionTag[numTags]; };
			~UnconfirmedTags () { delete[] sessionTags; };
			uint32_t msgID;
			int numTags;
			SessionTag * sessionTags;
			uint32_t tagsCreationTime;
		};

		public:

			ElGamalAESSession (GarlicDestination * owner, std::shared_ptr<const i2p::data::RoutingDestination> destination,
				int numTags, bool attachLeaseSet);
			ElGamalAESSession (const uint8_t * sessionKey, const SessionTag& sessionTag); // one time encryption
			~ElGamalAESSession () {};

			std::shared_ptr<I2NPMessage> WrapSingleMessage (std::shared_ptr<const I2NPMessage> msg);

			bool MessageConfirmed (uint32_t msgID);
			bool CleanupExpiredTags (); // returns true if something left
			bool CleanupUnconfirmedTags (); // returns true if something has been deleted

		private:

			size_t CreateAESBlock (uint8_t * buf, std::shared_ptr<const I2NPMessage> msg);
			size_t CreateGarlicPayload (uint8_t * payload, std::shared_ptr<const I2NPMessage> msg, UnconfirmedTags * newTags);
			size_t CreateGarlicClove (uint8_t * buf, std::shared_ptr<const I2NPMessage> msg, bool isDestination);
			size_t CreateDeliveryStatusClove (uint8_t * buf, uint32_t msgID);

			void TagsConfirmed (uint32_t msgID);
			UnconfirmedTags * GenerateSessionTags ();

		private:

			std::shared_ptr<const i2p::data::RoutingDestination> m_Destination;

			i2p::crypto::AESKey m_SessionKey;
			std::list<SessionTag> m_SessionTags;
			int m_NumTags;
			std::map<uint32_t, std::unique_ptr<UnconfirmedTags> > m_UnconfirmedTagsMsgs; // msgID->tags

			i2p::crypto::CBCEncryption m_Encryption;

		public:

			// for HTTP only
			size_t GetNumOutgoingTags () const { return m_SessionTags.size (); };
	};
	typedef std::shared_ptr<ElGamalAESSession> ElGamalAESSessionPtr;

	class ECIESX25519AEADRatchetSession;
	typedef std::shared_ptr<ECIESX25519AEADRatchetSession> ECIESX25519AEADRatchetSessionPtr;
	class ReceiveRatchetTagSet;
	typedef std::shared_ptr<ReceiveRatchetTagSet> ReceiveRatchetTagSetPtr;
	struct ECIESX25519AEADRatchetIndexTagset
	{
		int index;
		ReceiveRatchetTagSetPtr tagset;
	};

	class GarlicDestination: public i2p::data::LocalDestination
	{
		public:

			GarlicDestination ();
			~GarlicDestination ();

			void CleanUp ();
			void SetNumTags (int numTags) { m_NumTags = numTags; };
			int GetNumTags () const { return m_NumTags; };
			void SetNumRatchetInboundTags (int numTags) { m_NumRatchetInboundTags = numTags; };
			int GetNumRatchetInboundTags () const { return m_NumRatchetInboundTags; };
			std::shared_ptr<GarlicRoutingSession> GetRoutingSession (std::shared_ptr<const i2p::data::RoutingDestination> destination, bool attachLeaseSet);
			void CleanupExpiredTags ();
			void RemoveDeliveryStatusSession (uint32_t msgID);
			std::shared_ptr<I2NPMessage> WrapMessageForRouter (std::shared_ptr<const i2p::data::RouterInfo> router,
				std::shared_ptr<I2NPMessage> msg);

			void AddSessionKey (const uint8_t * key, const uint8_t * tag); // one tag
			void AddECIESx25519Key (const uint8_t * key, const uint8_t * tag); // one tag
			virtual bool SubmitSessionKey (const uint8_t * key, const uint8_t * tag); // from different thread
			void DeliveryStatusSent (GarlicRoutingSessionPtr session, uint32_t msgID);
			uint64_t AddECIESx25519SessionNextTag (ReceiveRatchetTagSetPtr tagset);
			void AddECIESx25519Session (const uint8_t * staticKey, ECIESX25519AEADRatchetSessionPtr session);
			void RemoveECIESx25519Session (const uint8_t * staticKey);
			void HandleECIESx25519GarlicClove (const uint8_t * buf, size_t len);

			virtual void ProcessGarlicMessage (std::shared_ptr<I2NPMessage> msg);
			virtual void ProcessDeliveryStatusMessage (std::shared_ptr<I2NPMessage> msg);
			virtual void SetLeaseSetUpdated ();

			virtual std::shared_ptr<const i2p::data::LocalLeaseSet> GetLeaseSet () = 0; // TODO
			virtual std::shared_ptr<i2p::tunnel::TunnelPool> GetTunnelPool () const = 0;

		protected:

			virtual void HandleI2NPMessage (const uint8_t * buf, size_t len) = 0; // called from clove only
			virtual bool HandleCloveI2NPMessage (I2NPMessageType typeID, const uint8_t * payload, size_t len) = 0;
			void HandleGarlicMessage (std::shared_ptr<I2NPMessage> msg);
			void HandleDeliveryStatusMessage (uint32_t msgID);

			void SaveTags ();
			void LoadTags ();

		private:

			void HandleAESBlock (uint8_t * buf, size_t len, std::shared_ptr<AESDecryption> decryption,
				std::shared_ptr<i2p::tunnel::InboundTunnel> from);
			void HandleGarlicPayload (uint8_t * buf, size_t len, std::shared_ptr<i2p::tunnel::InboundTunnel> from);

		private:

			BN_CTX * m_Ctx; // incoming
			// outgoing sessions
			int m_NumTags;
			std::mutex m_SessionsMutex;
			std::unordered_map<i2p::data::IdentHash, ElGamalAESSessionPtr> m_Sessions;
			std::unordered_map<i2p::data::Tag<32>, ECIESX25519AEADRatchetSessionPtr> m_ECIESx25519Sessions; // static key -> session
			// incoming
			int m_NumRatchetInboundTags;
			std::unordered_map<SessionTag, std::shared_ptr<AESDecryption>, std::hash<i2p::data::Tag<32> > > m_Tags;
			std::unordered_map<uint64_t, ECIESX25519AEADRatchetIndexTagset> m_ECIESx25519Tags; // session tag -> session
			ReceiveRatchetTagSetPtr m_LastTagset; // tagset last message came for
			// DeliveryStatus
			std::mutex m_DeliveryStatusSessionsMutex;
			std::unordered_map<uint32_t, GarlicRoutingSessionPtr> m_DeliveryStatusSessions; // msgID -> session

		public:

			// for HTTP only
			size_t GetNumIncomingTags () const { return m_Tags.size (); }
			size_t GetNumIncomingECIESx25519Tags () const { return m_ECIESx25519Tags.size (); }
			const decltype(m_Sessions)& GetSessions () const { return m_Sessions; };
			const decltype(m_ECIESx25519Sessions)& GetECIESx25519Sessions () const { return m_ECIESx25519Sessions; }
	};

	void CleanUpTagsFiles ();

}
}

#endif
