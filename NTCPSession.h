#ifndef NTCP_SESSION_H__
#define NTCP_SESSION_H__

#include <inttypes.h>
#include <list>
#include <boost/asio.hpp>
#include <cryptopp/modes.h>
#include <cryptopp/aes.h>
#include <cryptopp/adler32.h>
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

	const int TERMINATION_TIMEOUT = 150; // 2.5 minutes
	class NTCPSession
	{
		public:

			NTCPSession (boost::asio::io_service& service, i2p::data::RouterInfo& in_RemoteRouterInfo);
			virtual ~NTCPSession () {};

			boost::asio::ip::tcp::socket& GetSocket () { return m_Socket; };
			bool IsEstablished () const { return m_IsEstablished; };
			i2p::data::RouterInfo& GetRemoteRouterInfo () { return m_RemoteRouterInfo; };
			
			void ClientLogin ();
			void ServerLogin ();
			void SendI2NPMessage (I2NPMessage * msg);
			
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
			void DecryptNextBlock (const uint8_t * encrypted);	
		
			void Send (i2p::I2NPMessage * msg);
			void HandleSent (const boost::system::error_code& ecode, std::size_t bytes_transferred, i2p::I2NPMessage * msg);


			// timer
			void ScheduleTermination ();
			void HandleTerminationTimer (const boost::system::error_code& ecode);
			
		private:

			boost::asio::ip::tcp::socket m_Socket;
			boost::asio::deadline_timer m_TerminationTimer;
			bool m_IsEstablished;
			
			CryptoPP::CBC_Mode<CryptoPP::AES>::Decryption m_Decryption;
			CryptoPP::CBC_Mode<CryptoPP::AES>::Encryption m_Encryption;
			CryptoPP::Adler32 m_Adler;
			
			i2p::data::RouterInfo& m_RemoteRouterInfo;
			
			NTCPPhase1 m_Phase1;
			NTCPPhase2 m_Phase2;
			NTCPPhase3 m_Phase3;
			NTCPPhase4 m_Phase4;
			
			uint8_t m_ReceiveBuffer[i2p::NTCP_MAX_MESSAGE_SIZE*2], m_TimeSyncBuffer[16];
			int m_ReceiveBufferOffset; 

			i2p::I2NPMessage * m_NextMessage;
			std::list<i2p::I2NPMessage *> m_DelayedMessages;
			size_t m_NextMessageOffset;
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
