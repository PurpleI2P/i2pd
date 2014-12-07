#ifndef DESTINATION_H__
#define DESTINATION_H__

#include <thread>
#include <mutex>
#include <memory>
#include <map>
#include <string>
#include "Identity.h"
#include "TunnelPool.h"
#include "CryptoConst.h"
#include "LeaseSet.h"
#include "Garlic.h"
#include "Streaming.h"
#include "Datagram.h"

namespace i2p
{
namespace client
{
	const uint8_t PROTOCOL_TYPE_STREAMING = 6;
	const uint8_t PROTOCOL_TYPE_DATAGRAM = 17;
	const uint8_t PROTOCOL_TYPE_RAW = 18;	
	const int PUBLISH_CONFIRMATION_TIMEOUT = 5; // in seconds

	// I2CP
	const char I2CP_PARAM_INBOUND_TUNNEL_LENGTH[] = "inbound.length";
	const int DEFAULT_INBOUND_TUNNEL_LENGTH = 3;
	const char I2CP_PARAM_OUTBOUND_TUNNEL_LENGTH[] = "outbound.length";
	const int DEFAULT_OUTBOUND_TUNNEL_LENGTH = 3;
	
	class ClientDestination: public i2p::garlic::GarlicDestination
	{
		public:

			ClientDestination (const i2p::data::PrivateKeys& keys, bool isPublic, const std::map<std::string, std::string> * params = nullptr);
			~ClientDestination ();	

			virtual void Start ();
			virtual void Stop ();
			bool IsRunning () const { return m_IsRunning; };
			boost::asio::io_service * GetService () { return m_Service; };
			i2p::tunnel::TunnelPool * GetTunnelPool () { return m_Pool; }; 
			bool IsReady () const { return m_LeaseSet && m_LeaseSet->HasNonExpiredLeases (); };
			const i2p::data::LeaseSet * FindLeaseSet (const i2p::data::IdentHash& ident);

			// streaming
			i2p::stream::StreamingDestination * GetStreamingDestination () const { return m_StreamingDestination; };
			std::shared_ptr<i2p::stream::Stream> CreateStream (const i2p::data::LeaseSet& remote, int port = 0);
			void AcceptStreams (const i2p::stream::StreamingDestination::Acceptor& acceptor);
			void StopAcceptingStreams ();
			bool IsAcceptingStreams () const;

			// datagram
			i2p::datagram::DatagramDestination * GetDatagramDestination () const { return m_DatagramDestination; };
			i2p::datagram::DatagramDestination * CreateDatagramDestination ();

			// implements LocalDestination
			const i2p::data::PrivateKeys& GetPrivateKeys () const { return m_Keys; };
			const uint8_t * GetEncryptionPrivateKey () const { return m_EncryptionPrivateKey; };
			const uint8_t * GetEncryptionPublicKey () const { return m_EncryptionPublicKey; };
			
			// implements GarlicDestination
			const i2p::data::LeaseSet * GetLeaseSet ();
			void HandleI2NPMessage (const uint8_t * buf, size_t len, i2p::tunnel::InboundTunnel * from);

			// override GarlicDestination
			void ProcessGarlicMessage (I2NPMessage * msg);
			void ProcessDeliveryStatusMessage (I2NPMessage * msg);	
			void SetLeaseSetUpdated ();

			// I2CP
			void HandleDataMessage (const uint8_t * buf, size_t len);

		private:
				
			void Run ();			
			void UpdateLeaseSet ();
			void Publish ();
			void HandlePublishConfirmationTimer (const boost::system::error_code& ecode);
			void HandleDatabaseStoreMessage (const uint8_t * buf, size_t len);	
			void HandleDeliveryStatusMessage (I2NPMessage * msg);		

		private:

			bool m_IsRunning;
			std::thread * m_Thread;	
			boost::asio::io_service * m_Service;
			boost::asio::io_service::work * m_Work;
			i2p::data::PrivateKeys m_Keys;
			uint8_t m_EncryptionPublicKey[256], m_EncryptionPrivateKey[256];
			std::map<i2p::data::IdentHash, i2p::data::LeaseSet *> m_RemoteLeaseSets;

			i2p::tunnel::TunnelPool * m_Pool;
			i2p::data::LeaseSet * m_LeaseSet;
			bool m_IsPublic;
			uint32_t m_PublishReplyToken;
			std::set<i2p::data::IdentHash> m_ExcludedFloodfills; // for publishing
			
			i2p::stream::StreamingDestination * m_StreamingDestination;
			i2p::datagram::DatagramDestination * m_DatagramDestination;
	
			boost::asio::deadline_timer * m_PublishConfirmationTimer;

		public:
			
			// for HTTP only
			int GetNumRemoteLeaseSets () const { return m_RemoteLeaseSets.size (); };
	};	
}	
}	

#endif
