#ifndef NTCP2_H__
#define NTCP2_H__

#include <inttypes.h>
#include <memory>
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

			NTCP2Session (NTCP2Server& server, std::shared_ptr<const i2p::data::RouterInfo> in_RemoteRouter = nullptr); // TODO
			~NTCP2Session ();

			boost::asio::ip::tcp::socket& GetSocket () { return m_Socket; };

			void ClientLogin (); // Alice 

		private:

			bool KeyDerivationFunction (const uint8_t * rs, const uint8_t * pub, uint8_t * derived);
			void CreateEphemeralKey (uint8_t * pub);
			void SendSessionRequest ();

			void HandleSessionRequestSent (const boost::system::error_code& ecode, std::size_t bytes_transferred);

		private:

			NTCP2Server& m_Server;
			boost::asio::ip::tcp::socket m_Socket;
			uint8_t m_ExpandedPrivateKey[64]; // x25519 ephemeral key
			uint8_t m_RemoteStaticKey[32], m_RemoteIV[16];
			uint8_t * m_SessionRequestBuffer;
	};

	class NTCP2Server
	{
		public:

			NTCP2Server () {};
			~NTCP2Server () {} ;
			boost::asio::io_service& GetService () { return m_Service; };
			
		private:

			boost::asio::io_service m_Service;
	};
}
}

#endif
