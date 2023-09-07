/*
* Copyright (c) 2013-2023, The PurpleI2P Project
*
* This file is part of Purple i2pd project and licensed under BSD3
*
* See full license text in LICENSE file at top of project tree
*/

#ifndef I2PTUNNEL_H__
#define I2PTUNNEL_H__

#include <inttypes.h>
#include <string>
#include <set>
#include <tuple>
#include <memory>
#include <sstream>
#include <boost/asio.hpp>
#include <boost/asio/ssl.hpp>
#include "Identity.h"
#include "Destination.h"
#include "Streaming.h"
#include "I2PService.h"
#include "AddressBook.h"

namespace i2p
{
namespace client
{
	const size_t I2P_TUNNEL_CONNECTION_BUFFER_SIZE = 65536;
	const int I2P_TUNNEL_CONNECTION_MAX_IDLE = 3600; // in seconds
	const int I2P_TUNNEL_DESTINATION_REQUEST_TIMEOUT = 10; // in seconds
	// for HTTP tunnels
	const char X_I2P_DEST_HASH[] = "X-I2P-DestHash"; // hash in base64
	const char X_I2P_DEST_B64[] = "X-I2P-DestB64"; // full address in base64
	const char X_I2P_DEST_B32[] = "X-I2P-DestB32"; // .b32.i2p address
	const int I2P_TUNNEL_HTTP_MAX_HEADER_SIZE = 8192;

	class I2PTunnelConnection: public I2PServiceHandler, public std::enable_shared_from_this<I2PTunnelConnection>
	{
		public:

			I2PTunnelConnection (I2PService * owner, std::shared_ptr<boost::asio::ip::tcp::socket> socket,
				std::shared_ptr<const i2p::data::LeaseSet> leaseSet, uint16_t port = 0); // to I2P
			I2PTunnelConnection (I2PService * owner, std::shared_ptr<boost::asio::ip::tcp::socket> socket,
				std::shared_ptr<i2p::stream::Stream> stream); // to I2P using simplified API
			I2PTunnelConnection (I2PService * owner, std::shared_ptr<i2p::stream::Stream> stream,
				const boost::asio::ip::tcp::endpoint& target, bool quiet = true,
			    std::shared_ptr<boost::asio::ssl::context> sslCtx = nullptr); // from I2P
			~I2PTunnelConnection ();
			void I2PConnect (const uint8_t * msg = nullptr, size_t len = 0);
			void Connect (bool isUniqueLocal = true);
			void Connect (const boost::asio::ip::address& localAddress);

		protected:

			void Terminate ();

			void Receive ();
			void StreamReceive ();
			virtual void Write (const uint8_t * buf, size_t len); // can be overloaded
			virtual void WriteToStream (const uint8_t * buf, size_t len); // can be overloaded

			std::shared_ptr<boost::asio::ip::tcp::socket> GetSocket () const { return m_Socket; };
			std::shared_ptr<boost::asio::ssl::stream<boost::asio::ip::tcp::socket&> > GetSSL () const { return m_SSL; };

		private:

			void HandleConnect (const boost::system::error_code& ecode);
			void HandleHandshake (const boost::system::error_code& ecode);
			void Established ();
			void HandleReceive (const boost::system::error_code& ecode, std::size_t bytes_transferred);
			void HandleWrite (const boost::system::error_code& ecode);
			void HandleStreamReceive (const boost::system::error_code& ecode, std::size_t bytes_transferred);

		private:

			uint8_t m_Buffer[I2P_TUNNEL_CONNECTION_BUFFER_SIZE], m_StreamBuffer[I2P_TUNNEL_CONNECTION_BUFFER_SIZE];
			std::shared_ptr<boost::asio::ip::tcp::socket> m_Socket;
			std::shared_ptr<boost::asio::ssl::stream<boost::asio::ip::tcp::socket&> > m_SSL;
			std::shared_ptr<i2p::stream::Stream> m_Stream;
			boost::asio::ip::tcp::endpoint m_RemoteEndpoint;
			bool m_IsQuiet; // don't send destination
	};

	class I2PClientTunnelConnectionHTTP: public I2PTunnelConnection
	{
		public:

			I2PClientTunnelConnectionHTTP (I2PService * owner, std::shared_ptr<boost::asio::ip::tcp::socket> socket,
				std::shared_ptr<i2p::stream::Stream> stream):
				I2PTunnelConnection (owner, socket, stream), m_HeaderSent (false),
				m_ConnectionSent (false), m_ProxyConnectionSent (false) {};

		protected:

			void Write (const uint8_t * buf, size_t len);

		private:

			std::stringstream m_InHeader, m_OutHeader;
			bool m_HeaderSent, m_ConnectionSent, m_ProxyConnectionSent;
	};

	class I2PServerTunnelConnectionHTTP: public I2PTunnelConnection
	{
		public:

			I2PServerTunnelConnectionHTTP (I2PService * owner, std::shared_ptr<i2p::stream::Stream> stream,
				const boost::asio::ip::tcp::endpoint& target, const std::string& host,
			    std::shared_ptr<boost::asio::ssl::context> sslCtx = nullptr);

		protected:

			void Write (const uint8_t * buf, size_t len);
			void WriteToStream (const uint8_t * buf, size_t len);

		private:

			std::string m_Host;
			std::stringstream m_InHeader, m_OutHeader;
			bool m_HeaderSent, m_ResponseHeaderSent;
			std::shared_ptr<const i2p::data::IdentityEx> m_From;
	};

	class I2PTunnelConnectionIRC: public I2PTunnelConnection
	{
		public:

			I2PTunnelConnectionIRC (I2PService * owner, std::shared_ptr<i2p::stream::Stream> stream,
				const boost::asio::ip::tcp::endpoint& target, const std::string& m_WebircPass,
			    std::shared_ptr<boost::asio::ssl::context> sslCtx = nullptr);

		protected:

			void Write (const uint8_t * buf, size_t len);

		private:

			std::shared_ptr<const i2p::data::IdentityEx> m_From;
			std::stringstream m_OutPacket, m_InPacket;
			bool m_NeedsWebIrc;
			std::string m_WebircPass;
	};


	class I2PClientTunnel: public TCPIPAcceptor
	{
		protected:

			// Implements TCPIPAcceptor
			std::shared_ptr<I2PServiceHandler> CreateHandler(std::shared_ptr<boost::asio::ip::tcp::socket> socket);

		public:

			I2PClientTunnel (const std::string& name, const std::string& destination,
				const std::string& address, uint16_t port, std::shared_ptr<ClientDestination> localDestination, uint16_t destinationPort = 0);
			~I2PClientTunnel () {}

			void Start ();
			void Stop ();

			const char* GetName() { return m_Name.c_str (); }
			void SetKeepAliveInterval (uint32_t keepAliveInterval);

		private:

			std::shared_ptr<const Address> GetAddress ();

			void ScheduleKeepAliveTimer ();
			void HandleKeepAliveTimer (const boost::system::error_code& ecode);

		private:

			std::string m_Name, m_Destination;
			std::shared_ptr<const Address> m_Address;
			uint16_t m_DestinationPort;
			uint32_t m_KeepAliveInterval;
			std::unique_ptr<boost::asio::deadline_timer> m_KeepAliveTimer;
	};

	class I2PServerTunnel: public I2PService
	{
		public:

			I2PServerTunnel (const std::string& name, const std::string& address, uint16_t port,
				std::shared_ptr<ClientDestination> localDestination, uint16_t inport = 0, bool gzip = true);

			void Start ();
			void Stop ();

			void SetAccessList (const std::set<i2p::data::IdentHash>& accessList);

			void SetUniqueLocal (bool isUniqueLocal) { m_IsUniqueLocal = isUniqueLocal; }
			bool IsUniqueLocal () const { return m_IsUniqueLocal; }

			void SetSSL (bool ssl);
			std::shared_ptr<boost::asio::ssl::context> GetSSLCtx () const { return m_SSLCtx; };

			void SetLocalAddress (const std::string& localAddress);

			const std::string& GetAddress() const { return m_Address; }
			uint16_t GetPort () const { return m_Port; };
			uint16_t GetLocalPort () const { return m_PortDestination->GetLocalPort (); };
			const boost::asio::ip::tcp::endpoint& GetEndpoint () const { return m_Endpoint; }

			const char* GetName() { return m_Name.c_str (); }

		private:

			void HandleResolve (const boost::system::error_code& ecode, boost::asio::ip::tcp::resolver::iterator it,
				std::shared_ptr<boost::asio::ip::tcp::resolver> resolver);

			void Accept ();
			void HandleAccept (std::shared_ptr<i2p::stream::Stream> stream);
			virtual std::shared_ptr<I2PTunnelConnection> CreateI2PConnection (std::shared_ptr<i2p::stream::Stream> stream);

		private:

			bool m_IsUniqueLocal;
			std::string m_Name, m_Address;
			uint16_t m_Port;
			boost::asio::ip::tcp::endpoint m_Endpoint;
			std::shared_ptr<i2p::stream::StreamingDestination> m_PortDestination;
			std::set<i2p::data::IdentHash> m_AccessList;
			bool m_IsAccessList;
			std::unique_ptr<boost::asio::ip::address> m_LocalAddress;
			std::shared_ptr<boost::asio::ssl::context> m_SSLCtx;
	};

	class I2PServerTunnelHTTP: public I2PServerTunnel
	{
		public:

			I2PServerTunnelHTTP (const std::string& name, const std::string& address, uint16_t port,
				std::shared_ptr<ClientDestination> localDestination, const std::string& host,
				uint16_t inport = 0, bool gzip = true);

		private:

			std::shared_ptr<I2PTunnelConnection> CreateI2PConnection (std::shared_ptr<i2p::stream::Stream> stream);

		private:

			std::string m_Host;
	};

	class I2PServerTunnelIRC: public I2PServerTunnel
	{
		public:

			I2PServerTunnelIRC (const std::string& name, const std::string& address, uint16_t port,
				std::shared_ptr<ClientDestination> localDestination, const std::string& webircpass,
				uint16_t inport = 0, bool gzip = true);

		private:

			std::shared_ptr<I2PTunnelConnection> CreateI2PConnection (std::shared_ptr<i2p::stream::Stream> stream);

		private:

			std::string m_WebircPass;
	};

	boost::asio::ip::address GetLoopbackAddressFor(const i2p::data::IdentHash & addr);
}
}

#endif
