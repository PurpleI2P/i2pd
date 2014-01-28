#ifndef SSU_H__
#define SSU_H__

#include <inttypes.h>
#include <map>
#include <boost/asio.hpp>
#include <cryptopp/modes.h>
#include <cryptopp/aes.h>
#include "I2PEndian.h"
#include "RouterInfo.h"

namespace i2p
{
namespace ssu
{
#pragma pack(1)
	struct SSUHeader
	{
		uint8_t mac[16];
		uint8_t iv[16];
		uint8_t flag;
		uint32_t time;	
	};
#pragma pack()

	const int SSU_MTU = 1484;

	// payload types (4 bits)
	const uint8_t PAYLOAD_TYPE_SESSION_REQUEST = 0;
	const uint8_t PAYLOAD_TYPE_SESSION_CREATED = 1;
	const uint8_t PAYLOAD_TYPE_SESSION_CONFIRMED = 2;
	const uint8_t PAYLOAD_TYPE_RELAY_REQUEST = 3;
	const uint8_t PAYLOAD_TYPE_RELAY_RESPONSE = 4;
	const uint8_t PAYLOAD_TYPE_RELAY_INTRO = 5;
	const uint8_t PAYLOAD_TYPE_DATA = 6;
	const uint8_t PAYLOAD_TYPE_TEST = 7;

	enum SessionState
	{
		eSessionStateUnknown,
		eSessionStateRequestSent, 
		eSessionStateRequestReceived,
		eSessionStateCreatedSent,
		eSessionStateCreatedReceived,
		eSessionStateConfirmedSent,
		eSessionStateConfirmedReceived,
		eSessionStateEstablised
	};		

	class SSUServer;
	class SSUSession
	{
		public:

			SSUSession (SSUServer * server, const boost::asio::ip::udp::endpoint& remoteEndpoint,
				i2p::data::RouterInfo * router = nullptr);
			void ProcessNextMessage (uint8_t * buf, size_t len);		

		private:

			void ProcessSessionRequest (uint8_t * buf, size_t len);

			void Encrypt (uint8_t * buf, size_t len, uint8_t * aesKey, uint8_t * iv, uint8_t * macKey);
			void Decrypt (uint8_t * buf, size_t len, uint8_t * aesKey);			
			bool Validate (uint8_t * buf, size_t len, uint8_t * macKey);			

		private:
			
			SSUServer * m_Server;
			boost::asio::ip::udp::endpoint m_RemoteEndpoint;
			SessionState m_State;	
			CryptoPP::CBC_Mode<CryptoPP::AES>::Encryption m_Encryption;	
			CryptoPP::CBC_Mode<CryptoPP::AES>::Decryption m_Decryption;			
	};

	class SSUServer
	{
		public:

			SSUServer (boost::asio::io_service& service, int port);
			~SSUServer ();
			void Start ();
			void Stop ();
			SSUSession * GetSession (i2p::data::RouterInfo * router);
			
			void Send (uint8_t * buf, size_t len, const boost::asio::ip::udp::endpoint& to);

		private:

			void Receive ();
			void HandleReceivedFrom (const boost::system::error_code& ecode, std::size_t bytes_transferred);

		private:
			
			boost::asio::ip::udp::socket m_Socket;
			boost::asio::ip::udp::endpoint m_SenderEndpoint;
			uint8_t m_ReceiveBuffer[2*SSU_MTU];
			std::map<boost::asio::ip::udp::endpoint, SSUSession *> m_Sessions;
	};
}
}

#endif

