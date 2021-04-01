/*
* Copyright (c) 2013-2020, The PurpleI2P Project
*
* This file is part of Purple i2pd project and licensed under BSD3
*
* See full license text in LICENSE file at top of project tree
*/

#ifndef DESTINATION_H__
#define DESTINATION_H__

#include <string.h>
#include <thread>
#include <mutex>
#include <memory>
#include <map>
#include <set>
#include <string>
#include <functional>
#include <boost/asio.hpp>
#include "Identity.h"
#include "TunnelPool.h"
#include "Crypto.h"
#include "LeaseSet.h"
#include "Garlic.h"
#include "NetDb.hpp"
#include "Streaming.h"
#include "Datagram.h"
#include "util.h"

namespace i2p
{
namespace client
{
	const uint8_t PROTOCOL_TYPE_STREAMING = 6;
	const uint8_t PROTOCOL_TYPE_DATAGRAM = 17;
	const uint8_t PROTOCOL_TYPE_RAW = 18;
	const int PUBLISH_CONFIRMATION_TIMEOUT = 5; // in seconds
	const int PUBLISH_VERIFICATION_TIMEOUT = 10; // in seconds after successful publish
	const int PUBLISH_MIN_INTERVAL = 20; // in seconds
	const int PUBLISH_REGULAR_VERIFICATION_INTERNAL = 100; // in seconds periodically
	const int LEASESET_REQUEST_TIMEOUT = 5; // in seconds
	const int MAX_LEASESET_REQUEST_TIMEOUT = 40; // in seconds
	const int DESTINATION_CLEANUP_TIMEOUT = 3; // in minutes
	const unsigned int MAX_NUM_FLOODFILLS_PER_REQUEST = 7;

	// I2CP
	const char I2CP_PARAM_INBOUND_TUNNEL_LENGTH[] = "inbound.length";
	const int DEFAULT_INBOUND_TUNNEL_LENGTH = 3;
	const char I2CP_PARAM_OUTBOUND_TUNNEL_LENGTH[] = "outbound.length";
	const int DEFAULT_OUTBOUND_TUNNEL_LENGTH = 3;
	const char I2CP_PARAM_INBOUND_TUNNELS_QUANTITY[] = "inbound.quantity";
	const int DEFAULT_INBOUND_TUNNELS_QUANTITY = 5;
	const char I2CP_PARAM_OUTBOUND_TUNNELS_QUANTITY[] = "outbound.quantity";
	const int DEFAULT_OUTBOUND_TUNNELS_QUANTITY = 5;
	const char I2CP_PARAM_EXPLICIT_PEERS[] = "explicitPeers";
	const int STREAM_REQUEST_TIMEOUT = 60; //in seconds
	const char I2CP_PARAM_TAGS_TO_SEND[] = "crypto.tagsToSend";
	const int DEFAULT_TAGS_TO_SEND = 40;
	const char I2CP_PARAM_RATCHET_INBOUND_TAGS[] = "crypto.ratchet.inboundTags";
	const char I2CP_PARAM_RATCHET_OUTBOUND_TAGS[] = "crypto.ratchet.outboundTags"; // not used yet
	const char I2CP_PARAM_INBOUND_NICKNAME[] = "inbound.nickname";
	const char I2CP_PARAM_OUTBOUND_NICKNAME[] = "outbound.nickname";
	const char I2CP_PARAM_LEASESET_TYPE[] = "i2cp.leaseSetType";
	const int DEFAULT_LEASESET_TYPE = 1;
	const char I2CP_PARAM_LEASESET_ENCRYPTION_TYPE[] = "i2cp.leaseSetEncType";
	const char I2CP_PARAM_LEASESET_PRIV_KEY[] = "i2cp.leaseSetPrivKey"; // PSK decryption key, base64
	const char I2CP_PARAM_LEASESET_AUTH_TYPE[] = "i2cp.leaseSetAuthType";
	const char I2CP_PARAM_LEASESET_CLIENT_DH[] = "i2cp.leaseSetClient.dh"; // group of i2cp.leaseSetClient.dh.nnn
	const char I2CP_PARAM_LEASESET_CLIENT_PSK[] = "i2cp.leaseSetClient.psk"; // group of i2cp.leaseSetClient.psk.nnn

	// latency
	const char I2CP_PARAM_MIN_TUNNEL_LATENCY[] = "latency.min";
	const int DEFAULT_MIN_TUNNEL_LATENCY = 0;
	const char I2CP_PARAM_MAX_TUNNEL_LATENCY[] = "latency.max";
	const int DEFAULT_MAX_TUNNEL_LATENCY = 0;

	// streaming
	const char I2CP_PARAM_STREAMING_INITIAL_ACK_DELAY[] = "i2p.streaming.initialAckDelay";
	const int DEFAULT_INITIAL_ACK_DELAY = 200; // milliseconds
	const char I2CP_PARAM_STREAMING_ANSWER_PINGS[] = "i2p.streaming.answerPings";
	const int DEFAULT_ANSWER_PINGS = true; 

	typedef std::function<void (std::shared_ptr<i2p::stream::Stream> stream)> StreamRequestComplete;

	class LeaseSetDestination: public i2p::garlic::GarlicDestination,
		public std::enable_shared_from_this<LeaseSetDestination>
	{
		typedef std::function<void (std::shared_ptr<i2p::data::LeaseSet> leaseSet)> RequestComplete;
		// leaseSet = nullptr means not found
		struct LeaseSetRequest
		{
			LeaseSetRequest (boost::asio::io_service& service): requestTime (0), requestTimeoutTimer (service) {};
			std::set<i2p::data::IdentHash> excluded;
			uint64_t requestTime;
			boost::asio::deadline_timer requestTimeoutTimer;
			std::list<RequestComplete> requestComplete;
			std::shared_ptr<i2p::tunnel::OutboundTunnel> outboundTunnel;
			std::shared_ptr<i2p::tunnel::InboundTunnel> replyTunnel;
			std::shared_ptr<const i2p::data::BlindedPublicKey> requestedBlindedKey; // for encrypted LeaseSet2 only

			void Complete (std::shared_ptr<i2p::data::LeaseSet> ls)
			{
				for (auto& it: requestComplete) it (ls);
				requestComplete.clear ();
			}
		};

		public:

			LeaseSetDestination (boost::asio::io_service& service, bool isPublic, const std::map<std::string, std::string> * params = nullptr);
			~LeaseSetDestination ();
			const std::string& GetNickname () const { return m_Nickname; };
			boost::asio::io_service& GetService () { return m_Service; };

			virtual void Start ();
			virtual void Stop ();

			/** i2cp reconfigure */
			virtual bool Reconfigure(std::map<std::string, std::string> i2cpOpts);

			std::shared_ptr<i2p::tunnel::TunnelPool> GetTunnelPool () { return m_Pool; };
			bool IsReady () const { return m_LeaseSet && !m_LeaseSet->IsExpired () && m_Pool->GetOutboundTunnels ().size () > 0; };
			std::shared_ptr<i2p::data::LeaseSet> FindLeaseSet (const i2p::data::IdentHash& ident);
			bool RequestDestination (const i2p::data::IdentHash& dest, RequestComplete requestComplete = nullptr);
			bool RequestDestinationWithEncryptedLeaseSet (std::shared_ptr<const i2p::data::BlindedPublicKey> dest, RequestComplete requestComplete = nullptr);
			void CancelDestinationRequest (const i2p::data::IdentHash& dest, bool notify = true);
			void CancelDestinationRequestWithEncryptedLeaseSet (std::shared_ptr<const i2p::data::BlindedPublicKey> dest, bool notify = true);

			// implements GarlicDestination
			std::shared_ptr<const i2p::data::LocalLeaseSet> GetLeaseSet ();
			std::shared_ptr<i2p::tunnel::TunnelPool> GetTunnelPool () const { return m_Pool; }

			// override GarlicDestination
			bool SubmitSessionKey (const uint8_t * key, const uint8_t * tag);
			void ProcessGarlicMessage (std::shared_ptr<I2NPMessage> msg);
			void ProcessDeliveryStatusMessage (std::shared_ptr<I2NPMessage> msg);
			void SetLeaseSetUpdated ();

			bool IsPublic () const { return m_IsPublic; };

		protected:

			// implements GarlicDestination
			void HandleI2NPMessage (const uint8_t * buf, size_t len);
			bool HandleCloveI2NPMessage (I2NPMessageType typeID, const uint8_t * payload, size_t len);

			void SetLeaseSet (std::shared_ptr<const i2p::data::LocalLeaseSet> newLeaseSet);
			int GetLeaseSetType () const { return m_LeaseSetType; };
			void SetLeaseSetType (int leaseSetType) { m_LeaseSetType = leaseSetType; };
			int GetAuthType () const { return m_AuthType; };
			virtual void CleanupDestination () {}; // additional clean up in derived classes
			// I2CP
			virtual void HandleDataMessage (const uint8_t * buf, size_t len) = 0;
			virtual void CreateNewLeaseSet (const std::vector<std::shared_ptr<i2p::tunnel::InboundTunnel> >& tunnels) = 0;

		private:

			void UpdateLeaseSet ();
			std::shared_ptr<const i2p::data::LocalLeaseSet> GetLeaseSetMt ();
			void Publish ();
			void HandlePublishConfirmationTimer (const boost::system::error_code& ecode);
			void HandlePublishVerificationTimer (const boost::system::error_code& ecode);
			void HandlePublishDelayTimer (const boost::system::error_code& ecode);
			void HandleDatabaseStoreMessage (const uint8_t * buf, size_t len);
			void HandleDatabaseSearchReplyMessage (const uint8_t * buf, size_t len);
			void HandleDeliveryStatusMessage (uint32_t msgID);

			void RequestLeaseSet (const i2p::data::IdentHash& dest, RequestComplete requestComplete, std::shared_ptr<const i2p::data::BlindedPublicKey> requestedBlindedKey = nullptr);
			bool SendLeaseSetRequest (const i2p::data::IdentHash& dest, std::shared_ptr<const i2p::data::RouterInfo> nextFloodfill, std::shared_ptr<LeaseSetRequest> request);
			void HandleRequestTimoutTimer (const boost::system::error_code& ecode, const i2p::data::IdentHash& dest);
			void HandleCleanupTimer (const boost::system::error_code& ecode);
			void CleanupRemoteLeaseSets ();
			i2p::data::CryptoKeyType GetPreferredCryptoType () const;

		private:

			boost::asio::io_service& m_Service;
			mutable std::mutex m_RemoteLeaseSetsMutex;
			std::map<i2p::data::IdentHash, std::shared_ptr<i2p::data::LeaseSet> > m_RemoteLeaseSets;
			std::map<i2p::data::IdentHash, std::shared_ptr<LeaseSetRequest> > m_LeaseSetRequests;

			std::shared_ptr<i2p::tunnel::TunnelPool> m_Pool;
			std::mutex m_LeaseSetMutex;
			std::shared_ptr<const i2p::data::LocalLeaseSet> m_LeaseSet;
			bool m_IsPublic;
			uint32_t m_PublishReplyToken;
			uint64_t m_LastSubmissionTime; // in seconds
			std::set<i2p::data::IdentHash> m_ExcludedFloodfills; // for publishing

			boost::asio::deadline_timer m_PublishConfirmationTimer, m_PublishVerificationTimer,
				m_PublishDelayTimer, m_CleanupTimer;
			std::string m_Nickname;
			int m_LeaseSetType, m_AuthType;
			std::unique_ptr<i2p::data::Tag<32> > m_LeaseSetPrivKey; // non-null if presented

		public:

			// for HTTP only
			int GetNumRemoteLeaseSets () const { return m_RemoteLeaseSets.size (); };
			const decltype(m_RemoteLeaseSets)& GetLeaseSets () const { return m_RemoteLeaseSets; };
			bool IsEncryptedLeaseSet () const { return m_LeaseSetType == i2p::data::NETDB_STORE_TYPE_ENCRYPTED_LEASESET2; };
			bool IsPerClientAuth () const { return m_AuthType > 0; };
	};

	class ClientDestination: public LeaseSetDestination
	{
		struct EncryptionKey
		{
			uint8_t pub[256], priv[256];
			i2p::data::CryptoKeyType keyType;
			std::shared_ptr<i2p::crypto::CryptoKeyDecryptor> decryptor;

			EncryptionKey (i2p::data::CryptoKeyType t):keyType(t) { memset (pub, 0, 256); memset (priv, 0, 256);	};
			void GenerateKeys () { i2p::data::PrivateKeys::GenerateCryptoKeyPair (keyType, priv, pub); };
			void CreateDecryptor () { decryptor = i2p::data::PrivateKeys::CreateDecryptor (keyType, priv); };
		};

		public:

			ClientDestination (boost::asio::io_service& service, const i2p::data::PrivateKeys& keys,
				bool isPublic, const std::map<std::string, std::string> * params = nullptr);
			~ClientDestination ();

			void Start ();
			void Stop ();

			const i2p::data::PrivateKeys& GetPrivateKeys () const { return m_Keys; };
			void Sign (const uint8_t * buf, int len, uint8_t * signature) const { m_Keys.Sign (buf, len, signature); };

			// ref counter
			int Acquire () { return ++m_RefCounter; };
			int Release () { return --m_RefCounter; };
			int GetRefCounter () const { return m_RefCounter; };

			// streaming
			std::shared_ptr<i2p::stream::StreamingDestination> CreateStreamingDestination (int port, bool gzip = true); // additional
			std::shared_ptr<i2p::stream::StreamingDestination> GetStreamingDestination (int port = 0) const;
			// following methods operate with default streaming destination
			void CreateStream (StreamRequestComplete streamRequestComplete, const i2p::data::IdentHash& dest, int port = 0);
			void CreateStream (StreamRequestComplete streamRequestComplete, std::shared_ptr<const i2p::data::BlindedPublicKey> dest, int port = 0);
			std::shared_ptr<i2p::stream::Stream> CreateStream (std::shared_ptr<const i2p::data::LeaseSet> remote, int port = 0);
			void AcceptStreams (const i2p::stream::StreamingDestination::Acceptor& acceptor);
			void StopAcceptingStreams ();
			bool IsAcceptingStreams () const;
			void AcceptOnce (const i2p::stream::StreamingDestination::Acceptor& acceptor);
			int GetStreamingAckDelay () const { return m_StreamingAckDelay; }
			bool IsStreamingAnswerPings () const { return m_IsStreamingAnswerPings; }
			
			// datagram
			i2p::datagram::DatagramDestination * GetDatagramDestination () const { return m_DatagramDestination; };
			i2p::datagram::DatagramDestination * CreateDatagramDestination (bool gzip = true);

			// implements LocalDestination
			bool Decrypt (const uint8_t * encrypted, uint8_t * data, BN_CTX * ctx, i2p::data::CryptoKeyType preferredCrypto) const;
			std::shared_ptr<const i2p::data::IdentityEx> GetIdentity () const { return m_Keys.GetPublic (); };
			bool SupportsEncryptionType (i2p::data::CryptoKeyType keyType) const;
			const uint8_t * GetEncryptionPublicKey (i2p::data::CryptoKeyType keyType) const;

		protected:

			void CleanupDestination ();
			// I2CP
			void HandleDataMessage (const uint8_t * buf, size_t len);
			void CreateNewLeaseSet (const std::vector<std::shared_ptr<i2p::tunnel::InboundTunnel> >& tunnels);

		private:

			std::shared_ptr<ClientDestination> GetSharedFromThis () {
				return std::static_pointer_cast<ClientDestination>(shared_from_this ());
			}
			void PersistTemporaryKeys (EncryptionKey * keys, bool isSingleKey);
			void ReadAuthKey (const std::string& group, const std::map<std::string, std::string> * params);

		private:

			i2p::data::PrivateKeys m_Keys;
			std::unique_ptr<EncryptionKey> m_StandardEncryptionKey;
			std::unique_ptr<EncryptionKey> m_ECIESx25519EncryptionKey;

			int m_StreamingAckDelay;
			bool m_IsStreamingAnswerPings;
			std::shared_ptr<i2p::stream::StreamingDestination> m_StreamingDestination; // default
			std::map<uint16_t, std::shared_ptr<i2p::stream::StreamingDestination> > m_StreamingDestinationsByPorts;
			i2p::datagram::DatagramDestination * m_DatagramDestination;
			int m_RefCounter; // how many clients(tunnels) use this destination

			boost::asio::deadline_timer m_ReadyChecker;

			std::shared_ptr<std::vector<i2p::data::AuthPublicKey> > m_AuthKeys; // we don't need them for I2CP

		public:

			// for HTTP only
			std::vector<std::shared_ptr<const i2p::stream::Stream> > GetAllStreams () const;
			bool DeleteStream (uint32_t recvStreamID);
	};

	class RunnableClientDestination: private i2p::util::RunnableService, public ClientDestination
	{
		public:

			RunnableClientDestination (const i2p::data::PrivateKeys& keys, bool isPublic, const std::map<std::string, std::string> * params = nullptr);
			~RunnableClientDestination ();

			void Start ();
			void Stop ();
	};

}
}

#endif
