#ifndef DESTINATION_H__
#define DESTINATION_H__

#include <thread>
#include <mutex>
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

	class ClientDestination: public i2p::garlic::GarlicDestination
	{
		public:

			ClientDestination (bool isPublic, i2p::data::SigningKeyType sigType);
			ClientDestination (const std::string& fullPath, bool isPublic);
			ClientDestination (const i2p::data::PrivateKeys& keys, bool isPublic);
			~ClientDestination ();	

			virtual void Start ();
			virtual void Stop ();
			bool IsRunning () const { return m_IsRunning; };
			boost::asio::io_service * GetService () { return m_Service; };
			i2p::tunnel::TunnelPool * GetTunnelPool () { return m_Pool; }; 
			bool IsReady () const { return m_LeaseSet && m_LeaseSet->HasNonExpiredLeases (); };

			void ResetCurrentOutboundTunnel () { m_CurrentOutboundTunnel = nullptr; };
			const i2p::data::LeaseSet * FindLeaseSet (const i2p::data::IdentHash& ident);
			void SendTunnelDataMsgs (const std::vector<i2p::tunnel::TunnelMessageBlock>& msgs);

			// streaming
			i2p::stream::StreamingDestination * GetStreamingDestination () const { return m_StreamingDestination; };
			i2p::stream::Stream * CreateStream (const i2p::data::LeaseSet& remote, int port = 0);
			void AcceptStreams (const std::function<void (i2p::stream::Stream *)>& acceptor);
			void StopAcceptingStreams ();
			bool IsAcceptingStreams () const;

			// datagram
			i2p::datagram::DatagramDestination * GetDatagramDestination () const { return m_DatagramDestination; };
			void CreateDatagramDestination ();

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
			void HandleDatabaseStoreMessage (const uint8_t * buf, size_t len);			

		private:

			bool m_IsRunning;
			std::thread * m_Thread;	
			boost::asio::io_service * m_Service;
			boost::asio::io_service::work * m_Work;
			i2p::data::PrivateKeys m_Keys;
			uint8_t m_EncryptionPublicKey[256], m_EncryptionPrivateKey[256];
			std::map<i2p::data::IdentHash, i2p::data::LeaseSet *> m_RemoteLeaseSets;

			i2p::tunnel::TunnelPool * m_Pool;
			i2p::tunnel::OutboundTunnel * m_CurrentOutboundTunnel;
			i2p::data::LeaseSet * m_LeaseSet;
			bool m_IsPublic;
		
			i2p::stream::StreamingDestination * m_StreamingDestination;
			i2p::datagram::DatagramDestination * m_DatagramDestination;
	
		public:
			
			// for HTTP only
			int GetNumRemoteLeaseSets () const { return m_RemoteLeaseSets.size (); };
	};	
}	
}	

#endif
