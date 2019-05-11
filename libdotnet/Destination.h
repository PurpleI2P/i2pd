#ifndef DESTINATION_H__
#define DESTINATION_H__

#include <thread>
#include <mutex>
#include <memory>
#include <map>
#include <set>
#include <string>
#include <functional>
#ifdef I2LUA
#include <future>
#endif
#include <boost/asio.hpp>
#include "Identity.h"
#include "TunnelPool.h"
#include "Crypto.h"
#include "LeaseSet.h"
#include "Garlic.h"
#include "NetDb.hpp"
#include "Streaming.h"
#include "Datagram.h"

namespace dotnet
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

	// DNCP
	const char DNCP_PARAM_INBOUND_TUNNEL_LENGTH[] = "inbound.length";
	const int DEFAULT_INBOUND_TUNNEL_LENGTH = 3;
	const char DNCP_PARAM_OUTBOUND_TUNNEL_LENGTH[] = "outbound.length";
	const int DEFAULT_OUTBOUND_TUNNEL_LENGTH = 3;
	const char DNCP_PARAM_INBOUND_TUNNELS_QUANTITY[] = "inbound.quantity";
	const int DEFAULT_INBOUND_TUNNELS_QUANTITY = 5;
	const char DNCP_PARAM_OUTBOUND_TUNNELS_QUANTITY[] = "outbound.quantity";
	const int DEFAULT_OUTBOUND_TUNNELS_QUANTITY = 5;
	const char DNCP_PARAM_EXPLICIT_PEERS[] = "explicitPeers";
	const int STREAM_REQUEST_TIMEOUT = 60; //in seconds
	const char DNCP_PARAM_TAGS_TO_SEND[] = "crypto.tagsToSend";
	const int DEFAULT_TAGS_TO_SEND = 40;
	const char DNCP_PARAM_INBOUND_NICKNAME[] = "inbound.nickname";
	const char DNCP_PARAM_OUTBOUND_NICKNAME[] = "outbound.nickname";
	const char DNCP_PARAM_LEASESET_TYPE[] = "dncp.leaseSetType";
	const int DEFAULT_LEASESET_TYPE = 1;		
	const char DNCP_PARAM_LEASESET_ENCRYPTION_TYPE[] = "dncp.leaseSetEncType";

	// latency
	const char DNCP_PARAM_MIN_TUNNEL_LATENCY[] = "latency.min";
	const int DEFAULT_MIN_TUNNEL_LATENCY = 0;
	const char DNCP_PARAM_MAX_TUNNEL_LATENCY[] = "latency.max";
	const int DEFAULT_MAX_TUNNEL_LATENCY = 0;

	// streaming
	const char DNCP_PARAM_STREAMING_INITIAL_ACK_DELAY[] = "dotnet.streaming.initialAckDelay";
	const int DEFAULT_INITIAL_ACK_DELAY = 200; // milliseconds

	typedef std::function<void (std::shared_ptr<dotnet::stream::Stream> stream)> StreamRequestComplete;

	class LeaseSetDestination: public dotnet::garlic::GarlicDestination,
		public std::enable_shared_from_this<LeaseSetDestination>
	{
		typedef std::function<void (std::shared_ptr<dotnet::data::LeaseSet> leaseSet)> RequestComplete;
		// leaseSet = nullptr means not found
		struct LeaseSetRequest
		{
			LeaseSetRequest (boost::asio::io_service& service): requestTime (0), requestTimeoutTimer (service) {};
			std::set<dotnet::data::IdentHash> excluded;
			uint64_t requestTime;
			boost::asio::deadline_timer requestTimeoutTimer;
			std::list<RequestComplete> requestComplete;
			std::shared_ptr<dotnet::tunnel::OutboundTunnel> outboundTunnel;
			std::shared_ptr<dotnet::tunnel::InboundTunnel> replyTunnel;
			std::shared_ptr<const dotnet::data::BlindedPublicKey> requestedBlindedKey; // for encrypted LeaseSet2 only

			void Complete (std::shared_ptr<dotnet::data::LeaseSet> ls)
			{
				for (auto& it: requestComplete) it (ls);
				requestComplete.clear ();
			}
		};


		public:

			LeaseSetDestination (bool isPublic, const std::map<std::string, std::string> * params = nullptr);
			~LeaseSetDestination ();
			const std::string& GetNickname () const { return m_Nickname; };

			virtual bool Start ();
			virtual bool Stop ();

			/** dncp reconfigure */
			virtual bool Reconfigure(std::map<std::string, std::string> dncpOpts);
		
			bool IsRunning () const { return m_IsRunning; };
			boost::asio::io_service& GetService () { return m_Service; };
			std::shared_ptr<dotnet::tunnel::TunnelPool> GetTunnelPool () { return m_Pool; };
			bool IsReady () const { return m_LeaseSet && !m_LeaseSet->IsExpired () && m_Pool->GetOutboundTunnels ().size () > 0; };
			std::shared_ptr<dotnet::data::LeaseSet> FindLeaseSet (const dotnet::data::IdentHash& ident);
			bool RequestDestination (const dotnet::data::IdentHash& dest, RequestComplete requestComplete = nullptr);
			bool RequestDestinationWithEncryptedLeaseSet (std::shared_ptr<const dotnet::data::BlindedPublicKey>  dest, RequestComplete requestComplete = nullptr); 
			void CancelDestinationRequest (const dotnet::data::IdentHash& dest, bool notify = true);
			void CancelDestinationRequestWithEncryptedLeaseSet (std::shared_ptr<const dotnet::data::BlindedPublicKey> dest, bool notify = true);

			// implements GarlicDestination
			std::shared_ptr<const dotnet::data::LocalLeaseSet> GetLeaseSet ();
			std::shared_ptr<dotnet::tunnel::TunnelPool> GetTunnelPool () const { return m_Pool; }
			void HandleDNNPMessage (const uint8_t * buf, size_t len, std::shared_ptr<dotnet::tunnel::InboundTunnel> from);

			// override GarlicDestination
			bool SubmitSessionKey (const uint8_t * key, const uint8_t * tag);
			void ProcessGarlicMessage (std::shared_ptr<DNNPMessage> msg);
			void ProcessDeliveryStatusMessage (std::shared_ptr<DNNPMessage> msg);
			void SetLeaseSetUpdated ();

		protected:

			void SetLeaseSet (std::shared_ptr<const dotnet::data::LocalLeaseSet> newLeaseSet);
			int GetLeaseSetType () const { return m_LeaseSetType; };
			void SetLeaseSetType (int leaseSetType) { m_LeaseSetType = leaseSetType; };
			virtual void CleanupDestination () {}; // additional clean up in derived classes
			// DNCP
			virtual void HandleDataMessage (const uint8_t * buf, size_t len) = 0;
			virtual void CreateNewLeaseSet (std::vector<std::shared_ptr<dotnet::tunnel::InboundTunnel> > tunnels) = 0;

		private:

			void Run ();
			void UpdateLeaseSet ();
			std::shared_ptr<const dotnet::data::LocalLeaseSet> GetLeaseSetMt ();
			void Publish ();
			void HandlePublishConfirmationTimer (const boost::system::error_code& ecode);
			void HandlePublishVerificationTimer (const boost::system::error_code& ecode);
			void HandlePublishDelayTimer (const boost::system::error_code& ecode);
			void HandleDatabaseStoreMessage (const uint8_t * buf, size_t len);
			void HandleDatabaseSearchReplyMessage (const uint8_t * buf, size_t len);
			void HandleDeliveryStatusMessage (std::shared_ptr<DNNPMessage> msg);

			void RequestLeaseSet (const dotnet::data::IdentHash& dest, RequestComplete requestComplete, std::shared_ptr<const dotnet::data::BlindedPublicKey> requestedBlindedKey = nullptr);
			bool SendLeaseSetRequest (const dotnet::data::IdentHash& dest, std::shared_ptr<const dotnet::data::RouterInfo>  nextFloodfill, std::shared_ptr<LeaseSetRequest> request);
			void HandleRequestTimoutTimer (const boost::system::error_code& ecode, const dotnet::data::IdentHash& dest);
			void HandleCleanupTimer (const boost::system::error_code& ecode);
			void CleanupRemoteLeaseSets ();

		private:

			volatile bool m_IsRunning;
			std::thread * m_Thread;
			boost::asio::io_service m_Service;
			mutable std::mutex m_RemoteLeaseSetsMutex;
			std::map<dotnet::data::IdentHash, std::shared_ptr<dotnet::data::LeaseSet> > m_RemoteLeaseSets;
			std::map<dotnet::data::IdentHash, std::shared_ptr<LeaseSetRequest> > m_LeaseSetRequests;

			std::shared_ptr<dotnet::tunnel::TunnelPool> m_Pool;
			std::mutex m_LeaseSetMutex;
			std::shared_ptr<const dotnet::data::LocalLeaseSet> m_LeaseSet;
			bool m_IsPublic;
			uint32_t m_PublishReplyToken;
			uint64_t m_LastSubmissionTime; // in seconds
			std::set<dotnet::data::IdentHash> m_ExcludedFloodfills; // for publishing

			boost::asio::deadline_timer m_PublishConfirmationTimer, m_PublishVerificationTimer,
				m_PublishDelayTimer, m_CleanupTimer;
			std::string m_Nickname;
			int m_LeaseSetType;

		public:

			// for HTTP only
			int GetNumRemoteLeaseSets () const { return m_RemoteLeaseSets.size (); };
			const decltype(m_RemoteLeaseSets)& GetLeaseSets () const { return m_RemoteLeaseSets; };
	};

	class ClientDestination: public LeaseSetDestination
	{
		public:
#ifdef I2LUA
			// type for informing that a client destination is ready
			typedef std::promise<std::shared_ptr<ClientDestination> > ReadyPromise;
			// informs promise with shared_from_this() when this destination is ready to use
			// if cancelled before ready, informs promise with nullptr
			void Ready(ReadyPromise & p);
#endif

			ClientDestination (const dotnet::data::PrivateKeys& keys, bool isPublic, const std::map<std::string, std::string> * params = nullptr);
			~ClientDestination ();

			virtual bool Start ();
			virtual bool Stop ();

			const dotnet::data::PrivateKeys& GetPrivateKeys () const { return m_Keys; };
			void Sign (const uint8_t * buf, int len, uint8_t * signature) const { m_Keys.Sign (buf, len, signature); };

			// ref counter
			int Acquire () { return ++m_RefCounter; };
			int Release () { return --m_RefCounter; };
			int GetRefCounter () const { return m_RefCounter; };

			// streaming
			std::shared_ptr<dotnet::stream::StreamingDestination> CreateStreamingDestination (int port, bool gzip = true); // additional
			std::shared_ptr<dotnet::stream::StreamingDestination> GetStreamingDestination (int port = 0) const;
			// following methods operate with default streaming destination
			void CreateStream (StreamRequestComplete streamRequestComplete, const dotnet::data::IdentHash& dest, int port = 0);
			void CreateStream (StreamRequestComplete streamRequestComplete, std::shared_ptr<const dotnet::data::BlindedPublicKey> dest, int port = 0);
			std::shared_ptr<dotnet::stream::Stream> CreateStream (std::shared_ptr<const dotnet::data::LeaseSet> remote, int port = 0);
			void AcceptStreams (const dotnet::stream::StreamingDestination::Acceptor& acceptor);
			void StopAcceptingStreams ();
			bool IsAcceptingStreams () const;
			void AcceptOnce (const dotnet::stream::StreamingDestination::Acceptor& acceptor);
			int GetStreamingAckDelay () const { return m_StreamingAckDelay; }

			// datagram
      dotnet::datagram::DatagramDestination * GetDatagramDestination () const { return m_DatagramDestination; };
      dotnet::datagram::DatagramDestination * CreateDatagramDestination ();

			// implements LocalDestination
			bool Decrypt (const uint8_t * encrypted, uint8_t * data, BN_CTX * ctx) const;
			std::shared_ptr<const dotnet::data::IdentityEx> GetIdentity () const { return m_Keys.GetPublic (); };

		protected:

			void CleanupDestination ();
			// DNCP
			void HandleDataMessage (const uint8_t * buf, size_t len);
			void CreateNewLeaseSet (std::vector<std::shared_ptr<dotnet::tunnel::InboundTunnel> > tunnels);

		private:

			std::shared_ptr<ClientDestination> GetSharedFromThis ()
			{ return std::static_pointer_cast<ClientDestination>(shared_from_this ()); }
			void PersistTemporaryKeys ();
#ifdef I2LUA
			void ScheduleCheckForReady(ReadyPromise * p);
			void HandleCheckForReady(const boost::system::error_code & ecode, ReadyPromise * p);
#endif
		private:

			dotnet::data::PrivateKeys m_Keys;
			uint8_t m_EncryptionPublicKey[256], m_EncryptionPrivateKey[256];
			dotnet::data::CryptoKeyType m_EncryptionKeyType;
			std::shared_ptr<dotnet::crypto::CryptoKeyDecryptor> m_Decryptor;

			int m_StreamingAckDelay;
			std::shared_ptr<dotnet::stream::StreamingDestination> m_StreamingDestination; // default
			std::map<uint16_t, std::shared_ptr<dotnet::stream::StreamingDestination> > m_StreamingDestinationsByPorts;
			dotnet::datagram::DatagramDestination * m_DatagramDestination;
			int m_RefCounter; // how many clients(tunnels) use this destination

			boost::asio::deadline_timer m_ReadyChecker;

		public:

			// for HTTP only
			std::vector<std::shared_ptr<const dotnet::stream::Stream> > GetAllStreams () const;
	};
}
}

#endif
