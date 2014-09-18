#ifndef NTCP_SESSION_H__
#define NTCP_SESSION_H__

#include <inttypes.h>
#include <list>
#include <boost/asio.hpp>
#include <cryptopp/modes.h>
#include <cryptopp/aes.h>
#include <cryptopp/adler32.h>
#include "aes.h"
#include "Identity.h"
#include "RouterInfo.h"
#include "I2NPProtocol.h"

namespace i2p
{
namespace ntcp
{

#pragma pack(1)
	struct NTCPPhase1
	{
		uint8_t pubKey[256];
		uint8_t HXxorHI[32];
	};	
	
	struct NTCPPhase2
	{
		uint8_t pubKey[256];
		struct
		{
			uint8_t hxy[32];
			uint32_t timestamp;
			uint8_t filler[12];
		} encrypted;	
	};	

	struct NTCPPhase3
	{
		uint16_t size;
		i2p::data::Identity ident;
		uint32_t timestamp; 
		uint8_t padding[15];
		uint8_t signature[40];
	};


	struct NTCPPhase4
	{
		uint8_t signature[40];
		uint8_t padding[8];
	};

	struct SignedData // used for signature in Phase3 and Phase4
	{
		uint8_t x[256];
		uint8_t y[256];
		uint8_t ident[32];
		uint32_t tsA;
		uint32_t tsB;
	};	
	
#pragma pack()	

	const size_t NTCP_MAX_MESSAGE_SIZE = 16384; 
	const size_t NTCP_BUFFER_SIZE = 1040; // fits one tunnel message (1028)
	const int NTCP_TERMINATION_TIMEOUT = 120; // 2 minutes
	class NTCPSession
	{
		public:

			NTCPSession (boost::asio::io_service& service, i2p::data::RouterInfo& in_RemoteRouterInfo);
			virtual ~NTCPSession ();

			boost::asio::ip::tcp::socket& GetSocket () { return m_Socket; };
			bool IsEstablished () const { return m_IsEstablished; };
			i2p::data::RouterInfo& GetRemoteRouterInfo () { return m_RemoteRouterInfo; };
			
			void ClientLogin ();
			void ServerLogin ();
			void SendI2NPMessage (I2NPMessage * msg);

			size_t GetNumSentBytes () const { return m_NumSentBytes; };
			size_t GetNumReceivedBytes () const { return m_NumReceivedBytes; };
			
		protected:

			void Terminate ();
			virtual void Connected ();
			void SendTimeSyncMessage ();
			void SetIsEstablished (bool isEstablished) { m_IsEstablished = isEstablished; }
			
		private:

			void CreateAESKey (uint8_t * pubKey, uint8_t * aesKey);
				
			// client
			void SendPhase3 ();
			void HandlePhase1Sent (const boost::system::error_code& ecode,  std::size_t bytes_transferred);
			void HandlePhase2Received (const boost::system::error_code& ecode, std::size_t bytes_transferred);
			void HandlePhase3Sent (const boost::system::error_code& ecode, std::size_t bytes_transferred, uint32_t tsA);
			void HandlePhase4Received (const boost::system::error_code& ecode, std::size_t bytes_transferred, uint32_t tsA);

			//server
			void SendPhase2 ();
			void SendPhase4 (uint32_t tsB);
			void HandlePhase1Received (const boost::system::error_code& ecode, std::size_t bytes_transferred);
			void HandlePhase2Sent (const boost::system::error_code& ecode, std::size_t bytes_transferred, uint32_t tsB);
			void HandlePhase3Received (const boost::system::error_code& ecode, std::size_t bytes_transferred, uint32_t tsB);
			void HandlePhase4Sent (const boost::system::error_code& ecode,  std::size_t bytes_transferred);
			
			// common
			void Receive ();
			void HandleReceived (const boost::system::error_code& ecode, std::size_t bytes_transferred);
			bool DecryptNextBlock (const uint8_t * encrypted);	
		
			void Send (i2p::I2NPMessage * msg);
			void HandleSent (const boost::system::error_code& ecode, std::size_t bytes_transferred, i2p::I2NPMessage * msg);


			// timer
			void ScheduleTermination ();
			void HandleTerminationTimer (const boost::system::error_code& ecode);
			
		private:

			boost::asio::ip::tcp::socket m_Socket;
			boost::asio::deadline_timer m_TerminationTimer;
			bool m_IsEstablished;
			i2p::data::DHKeysPair * m_DHKeysPair; // X - for client and Y - for server
			
			i2p::crypto::CBCDecryption m_Decryption;
			i2p::crypto::CBCEncryption m_Encryption;
			CryptoPP::Adler32 m_Adler;
			
			i2p::data::RouterInfo& m_RemoteRouterInfo;

			struct Establisher
			{	
				NTCPPhase1 phase1;
				NTCPPhase2 phase2;
				NTCPPhase3 phase3;
				NTCPPhase4 phase4;
			} * m_Establisher;	
			
			uint8_t m_ReceiveBuffer[NTCP_BUFFER_SIZE + 16], m_TimeSyncBuffer[16];
			int m_ReceiveBufferOffset; 

			i2p::I2NPMessage * m_NextMessage;
			std::list<i2p::I2NPMessage *> m_DelayedMessages;
			size_t m_NextMessageOffset;

			size_t m_NumSentBytes, m_NumReceivedBytes;
	};	

	class NTCPClient: public NTCPSession
	{
		public:

			NTCPClient (boost::asio::io_service& service, const boost::asio::ip::address& address, int port, i2p::data::RouterInfo& in_RouterInfo);

		private:

			void Connect ();
			void HandleConnect (const boost::system::error_code& ecode);
			
		private:

			boost::asio::ip::tcp::endpoint m_Endpoint;
	};	

	class NTCPServerConnection: public NTCPSession
	{
		public:

			NTCPServerConnection (boost::asio::io_service& service): 
				NTCPSession (service, m_DummyRemoteRouterInfo) {};
			
		protected:

			virtual void Connected ();
			
		private:	

			i2p::data::RouterInfo m_DummyRemoteRouterInfo;
	};	
}	
}	

#endif
