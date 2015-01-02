#ifndef I2PTUNNEL_H__
#define I2PTUNNEL_H__

#include <inttypes.h>
#include <string>
#include <set>
#include <memory>
#include <boost/asio.hpp>
#include "Identity.h"
#include "Destination.h"
#include "Streaming.h"

namespace i2p
{
namespace client
{
	const size_t I2P_TUNNEL_CONNECTION_BUFFER_SIZE = 8192;
	const int I2P_TUNNEL_CONNECTION_MAX_IDLE = 3600; // in seconds	
	const int I2P_TUNNEL_DESTINATION_REQUEST_TIMEOUT = 10; // in seconds
	const i2p::data::SigningKeyType I2P_TUNNEL_DEFAULT_KEY_TYPE = i2p::data::SIGNING_KEY_TYPE_ECDSA_SHA256_P256;

	class I2PTunnel;
	class I2PTunnelConnection: public std::enable_shared_from_this<I2PTunnelConnection>
	{
		public:

			I2PTunnelConnection (I2PTunnel * owner, boost::asio::ip::tcp::socket * socket,
				const i2p::data::LeaseSet * leaseSet); // to I2P
			I2PTunnelConnection (I2PTunnel * owner, std::shared_ptr<i2p::stream::Stream> stream,  boost::asio::ip::tcp::socket * socket, 
				const boost::asio::ip::tcp::endpoint& target, bool quiet = true); // from I2P
			~I2PTunnelConnection ();

			void I2PConnect (const uint8_t * msg = nullptr, size_t len = 0);
			void Connect ();
			
		private:

			void Terminate ();	

			void Receive ();
			void HandleReceived (const boost::system::error_code& ecode, std::size_t bytes_transferred);	
			void HandleWrite (const boost::system::error_code& ecode);	

			void StreamReceive ();
			void HandleStreamReceive (const boost::system::error_code& ecode, std::size_t bytes_transferred);
			void HandleConnect (const boost::system::error_code& ecode);

		private:

			uint8_t m_Buffer[I2P_TUNNEL_CONNECTION_BUFFER_SIZE], m_StreamBuffer[I2P_TUNNEL_CONNECTION_BUFFER_SIZE];
			boost::asio::ip::tcp::socket * m_Socket;
			std::shared_ptr<i2p::stream::Stream> m_Stream;
			I2PTunnel * m_Owner;
			boost::asio::ip::tcp::endpoint m_RemoteEndpoint;
			bool m_IsQuiet; // don't send destination
	};	

	class I2PTunnel
	{
		public:

			I2PTunnel (ClientDestination * localDestination  = nullptr);
			virtual ~I2PTunnel () { ClearConnections (); }; 

			void AddConnection (std::shared_ptr<I2PTunnelConnection> conn);
			void RemoveConnection (std::shared_ptr<I2PTunnelConnection> conn);	
			void ClearConnections ();
			ClientDestination * GetLocalDestination () { return m_LocalDestination; };
			void SetLocalDestination (ClientDestination * dest) { m_LocalDestination = dest; }; 			

			boost::asio::io_service& GetService () { return m_LocalDestination->GetService (); };
			
		private:

			ClientDestination * m_LocalDestination;
			std::set<std::shared_ptr<I2PTunnelConnection> > m_Connections;
	};	
	
	class I2PClientTunnel: public I2PTunnel
	{
		public:

			I2PClientTunnel (const std::string& destination, int port, ClientDestination * localDestination = nullptr);
			~I2PClientTunnel ();				
	
			void Start ();
			void Stop ();

		private:

			void Accept ();
			void HandleAccept (const boost::system::error_code& ecode, boost::asio::ip::tcp::socket * socket);
			void HandleLeaseSetRequestComplete (bool success, boost::asio::ip::tcp::socket * socket);
			void CreateConnection (boost::asio::ip::tcp::socket * socket);				

		private:

			boost::asio::ip::tcp::acceptor m_Acceptor;
			boost::asio::deadline_timer m_Timer;
			std::string m_Destination;
			const i2p::data::IdentHash * m_DestinationIdentHash;
			const i2p::data::LeaseSet * m_RemoteLeaseSet;
	};	

	class I2PServerTunnel: public I2PTunnel
	{
		public:

			I2PServerTunnel (const std::string& address, int port, ClientDestination * localDestination);	

			void Start ();
			void Stop ();

		private:

			void Accept ();
			void HandleAccept (std::shared_ptr<i2p::stream::Stream> stream);

		private:

			boost::asio::ip::tcp::endpoint m_Endpoint;		
	};
}		
}	

#endif
