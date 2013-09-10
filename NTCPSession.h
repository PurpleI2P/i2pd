#ifndef NTCP_SESSION_H__
#define NTCP_SESSION_H__

#include <inttypes.h>
#include <boost/asio.hpp>
#include <cryptopp/modes.h>
#include <cryptopp/aes.h>
#include <cryptopp/adler32.h>
#include "RouterInfo.h"

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
		i2p::data::RouterIdentity ident;
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

	const int NTCP_MAX_MESSAGE_SIZE = 16384; 
	class NTCPSession
	{
		public:

			NTCPSession (boost::asio::ip::tcp::socket& s, const i2p::data::RouterInfo * in_RemoteRouterInfo = 0);
			virtual ~NTCPSession () {};

			bool IsEstablished () const { return m_IsEstablished; };
			const i2p::data::RouterInfo& GetRemoteRouterInfo () const { return m_RemoteRouterInfo; };
			
			void ClientLogin ();
			void ServerLogin ();
			void SendMessage (uint8_t * buf, int len);
			void Terminate ();
			
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
			void DecryptReceived (uint8_t * encrypted, int len); // len is multiple of 16
			void HandleNextMessage (uint8_t * buf, int len, int dataSize);

			void Send (const uint8_t * buf, int len, bool zeroSize = false);
			void HandleSent (const boost::system::error_code& ecode, std::size_t bytes_transferred);

			void SendTimeSyncMessage ();
			
		private:

			boost::asio::ip::tcp::socket& m_Socket;
			bool m_IsEstablished;
			
			CryptoPP::CBC_Mode<CryptoPP::AES>::Decryption m_Decryption;
			CryptoPP::CBC_Mode<CryptoPP::AES>::Encryption m_Encryption;
			CryptoPP::Adler32 m_Adler;
			
			i2p::data::RouterInfo m_RemoteRouterInfo;
			
			NTCPPhase1 m_Phase1;
			NTCPPhase2 m_Phase2;
			NTCPPhase3 m_Phase3;
			NTCPPhase4 m_Phase4;
			
			uint8_t m_ReceiveBuffer[NTCP_MAX_MESSAGE_SIZE*2], m_SendBuffer[NTCP_MAX_MESSAGE_SIZE];
			int m_ReceiveBufferOffset; 

			uint8_t m_DecryptedBuffer[NTCP_MAX_MESSAGE_SIZE*2];
			int m_DecryptedBufferOffset; 
	};	

	class NTCPClient: public NTCPSession
	{
		public:

			NTCPClient (boost::asio::io_service& service, const char * address, int port, const i2p::data::RouterInfo& in_RouterInfo);

		private:

			void Connect ();
			void HandleConnect (const boost::system::error_code& ecode);
			
		private:

			boost::asio::ip::tcp::socket m_Socket;	
			boost::asio::ip::tcp::endpoint m_Endpoint;
	};	

	class NTCPServerConnection: public NTCPSession
	{
		public:

			NTCPServerConnection (boost::asio::io_service& service);
			boost::asio::ip::tcp::socket& GetSocket () { return m_Socket; };
			
		private:

			boost::asio::ip::tcp::socket m_Socket;	
	};	
}	
}	

#endif
