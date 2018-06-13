#ifndef NTCP2_H__
#define NTCP2_H__

#include <inttypes.h>
#include <memory>
#include <thread>
#include <boost/asio.hpp>
#include "RouterInfo.h"
#include "TransportSession.h"

namespace i2p
{
namespace transport
{
	class NTCP2Server;
	class NTCP2Session: public TransportSession, public std::enable_shared_from_this<NTCP2Session>
	{
		public:

			NTCP2Session (NTCP2Server& server, std::shared_ptr<const i2p::data::RouterInfo> in_RemoteRouter = nullptr); 
			~NTCP2Session ();
			void Terminate ();
			void Done ();

			boost::asio::ip::tcp::socket& GetSocket () { return m_Socket; };

			void ClientLogin (); // Alice 
			void SendI2NPMessages (const std::vector<std::shared_ptr<I2NPMessage> >& msgs) {}; // TODO

		private:

			void KeyDerivationFunction1 (const uint8_t * rs, const uint8_t * pub, uint8_t * derived); // for SessionRequest
			void KeyDerivationFunction2 (const uint8_t * pub, const uint8_t * sessionRequest, size_t sessionRequestLen, uint8_t * derived); // for SessionCreate

			void CreateEphemeralKey (uint8_t * pub);
			void SendSessionRequest ();

			void HandleSessionRequestSent (const boost::system::error_code& ecode, std::size_t bytes_transferred);
			void HandleSessionCreatedReceived (const boost::system::error_code& ecode, std::size_t bytes_transferred);

		private:

			NTCP2Server& m_Server;
			boost::asio::ip::tcp::socket m_Socket;
			bool m_IsEstablished, m_IsTerminated;

			uint8_t m_ExpandedPrivateKey[64]; // x25519 ephemeral key
			uint8_t m_RemoteStaticKey[32], m_IV[16], m_H[32] /*h*/, m_CK[33] /*ck*/;
			uint8_t * m_SessionRequestBuffer, * m_SessionCreatedBuffer;
			size_t m_SessionRequestBufferLen;
	};

	class NTCP2Server
	{
		public:

			NTCP2Server ();
			~NTCP2Server ();

			void Start ();
			void Stop ();

			boost::asio::io_service& GetService () { return m_Service; };
		
			void Connect(const boost::asio::ip::address & address, uint16_t port, std::shared_ptr<NTCP2Session> conn);

		private:

			void Run ();
			void HandleConnect (const boost::system::error_code& ecode, std::shared_ptr<NTCP2Session> conn);		

		private:

			bool m_IsRunning;
			std::thread * m_Thread;
			boost::asio::io_service m_Service;
			boost::asio::io_service::work m_Work;
	};
}
}

#endif
