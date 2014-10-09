#ifndef DESTINATION_H__
#define DESTINATION_H__

#include <thread>
#include <mutex>
#include "Identity.h"
#include "TunnelPool.h"
#include "CryptoConst.h"
#include "NetDb.h"
#include "Garlic.h"
#include "Streaming.h"

namespace i2p
{
namespace stream
{
	class StreamingDestination: public i2p::garlic::GarlicDestination 
	{
		public:

			StreamingDestination (bool isPublic);
			StreamingDestination (const std::string& fullPath, bool isPublic);
			StreamingDestination (const i2p::data::PrivateKeys& keys, bool isPublic);
			~StreamingDestination ();	

			void Start ();
			void Stop ();

			i2p::tunnel::TunnelPool * GetTunnelPool () const  { return m_Pool; };			

			Stream * CreateNewOutgoingStream (const i2p::data::LeaseSet& remote);
			void DeleteStream (Stream * stream);			
			void SetAcceptor (const std::function<void (Stream *)>& acceptor) { m_Acceptor = acceptor; };
			void ResetAcceptor () { m_Acceptor = nullptr; };
			bool IsAcceptorSet () const { return m_Acceptor != nullptr; };	
			void HandleNextPacket (Packet * packet);
			void SendTunnelDataMsgs (const std::vector<i2p::tunnel::TunnelMessageBlock>& msgs);
			void ResetCurrentOutboundTunnel () { m_CurrentOutboundTunnel = nullptr; };
			// I2CP
			void HandleDataMessage (const uint8_t * buf, size_t len);
			I2NPMessage * CreateDataMessage (const uint8_t * payload, size_t len);

			// implements LocalDestination
			const i2p::data::PrivateKeys& GetPrivateKeys () const { return m_Keys; };
			const uint8_t * GetEncryptionPrivateKey () const { return m_EncryptionPrivateKey; };
			const uint8_t * GetEncryptionPublicKey () const { return m_EncryptionPublicKey; };

			// implements GarlicDestination
			const i2p::data::LeaseSet * GetLeaseSet ();

			// override GarlicDestination
			void ProcessGarlicMessage (I2NPMessage * msg);
			void ProcessDeliveryStatusMessage (I2NPMessage * msg);	
			void SetLeaseSetUpdated ();

		private:		
	
			void Run ();
			Stream * CreateNewIncomingStream ();
			void UpdateLeaseSet ();

		private:

			bool m_IsRunning;
			std::thread * m_Thread;	
			boost::asio::io_service m_Service;
			boost::asio::io_service::work m_Work;

			std::mutex m_StreamsMutex;
			std::map<uint32_t, Stream *> m_Streams;
			i2p::data::PrivateKeys m_Keys;
			uint8_t m_EncryptionPublicKey[256], m_EncryptionPrivateKey[256];
			
			i2p::tunnel::TunnelPool * m_Pool;
			i2p::tunnel::OutboundTunnel * m_CurrentOutboundTunnel;
			i2p::data::LeaseSet * m_LeaseSet;
			bool m_IsPublic;			

			std::function<void (Stream *)> m_Acceptor;
	};	

	class StreamingDestinations
	{
		public:

			StreamingDestinations (): m_SharedLocalDestination (nullptr) {};
			~StreamingDestinations () {};

			void Start ();
			void Stop ();

			Stream * CreateClientStream (const i2p::data::LeaseSet& remote);
			void DeleteStream (Stream * stream);
			StreamingDestination * GetSharedLocalDestination () const { return m_SharedLocalDestination; };
			StreamingDestination * CreateNewLocalDestination (bool isPublic);
			StreamingDestination * CreateNewLocalDestination (const i2p::data::PrivateKeys& keys, bool isPublic);
			void DeleteLocalDestination (StreamingDestination * destination);
			StreamingDestination * FindLocalDestination (const i2p::data::IdentHash& destination) const;		
			StreamingDestination * LoadLocalDestination (const std::string& filename, bool isPublic);

		private:	

			void LoadLocalDestinations ();
			
		private:

			std::mutex m_DestinationsMutex;
			std::map<i2p::data::IdentHash, StreamingDestination *> m_Destinations;
			StreamingDestination * m_SharedLocalDestination;	

		public:
			// for HTTP
			const decltype(m_Destinations)& GetDestinations () const { return m_Destinations; };
	};	

	
	Stream * CreateStream (const i2p::data::LeaseSet& remote);
	void DeleteStream (Stream * stream);
	void StartStreaming ();
	void StopStreaming ();
	StreamingDestination * GetSharedLocalDestination ();
	StreamingDestination * CreateNewLocalDestination (bool isPublic = true);
	StreamingDestination * CreateNewLocalDestination (const i2p::data::PrivateKeys& keys, bool isPublic = true);	
	void DeleteLocalDestination (StreamingDestination * destination);
	StreamingDestination * FindLocalDestination (const i2p::data::IdentHash& destination);	
	StreamingDestination * LoadLocalDestination (const std::string& filename, bool isPublic);
	// for HTTP
	const StreamingDestinations& GetLocalDestinations ();	
}		
}	

#endif
