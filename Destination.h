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

namespace i2p
{
namespace client
{
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
			I2NPMessage * CreateDataMessage (const uint8_t * payload, size_t len);

		protected:

			virtual void HandleNextPacket (i2p::stream::Packet * packet) = 0; // TODO	

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
		
		public:
			
			// for HTTP only
			int GetNumRemoteLeaseSets () const { return m_RemoteLeaseSets.size (); };
	};	
}

namespace stream
{
	class StreamingDestination: public i2p::client::ClientDestination 
	{
		public:

			StreamingDestination (bool isPublic, i2p::data::SigningKeyType sigType):
				ClientDestination (isPublic, sigType) {};
			StreamingDestination (const std::string& fullPath, bool isPublic):
				ClientDestination (fullPath, isPublic) {};
			StreamingDestination (const i2p::data::PrivateKeys& keys, bool isPublic):
				ClientDestination (keys, isPublic) {};
			~StreamingDestination () {};	

			void Start ();
			void Stop ();

			Stream * CreateNewOutgoingStream (const i2p::data::LeaseSet& remote);
			void DeleteStream (Stream * stream);			
			void SetAcceptor (const std::function<void (Stream *)>& acceptor) { m_Acceptor = acceptor; };
			void ResetAcceptor () { m_Acceptor = nullptr; };
			bool IsAcceptorSet () const { return m_Acceptor != nullptr; };	

			// ClientDestination
			void HandleNextPacket (Packet * packet);

		private:		
	
			Stream * CreateNewIncomingStream ();

		private:

			std::mutex m_StreamsMutex;
			std::map<uint32_t, Stream *> m_Streams;
			std::function<void (Stream *)> m_Acceptor;
			
		public:

			// for HTTP only
			const decltype(m_Streams)& GetStreams () const { return m_Streams; };
	};		
}		
}	

#endif
