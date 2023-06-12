/*
* Copyright (c) 2013-2023, The PurpleI2P Project
*
* This file is part of Purple i2pd project and licensed under BSD3
*
* See full license text in LICENSE file at top of project tree
*/

#include <cassert>
#include <boost/algorithm/string.hpp>
#include "Base.h"
#include "Log.h"
#include "Destination.h"
#include "ClientContext.h"
#include "I2PTunnel.h"
#include "util.h"

namespace i2p
{
namespace client
{

	/** set standard socket options */
	static void I2PTunnelSetSocketOptions (std::shared_ptr<boost::asio::ip::tcp::socket> socket)
	{
		if (socket && socket->is_open())
		{
			boost::asio::socket_base::receive_buffer_size option(I2P_TUNNEL_CONNECTION_BUFFER_SIZE);
			socket->set_option(option);
		}
	}

	I2PTunnelConnection::I2PTunnelConnection (I2PService * owner, std::shared_ptr<boost::asio::ip::tcp::socket> socket,
		std::shared_ptr<const i2p::data::LeaseSet> leaseSet, uint16_t port):
		I2PServiceHandler(owner), m_Socket (socket), m_RemoteEndpoint (socket->remote_endpoint ()),
		m_IsQuiet (true)
	{
		m_Stream = GetOwner()->GetLocalDestination ()->CreateStream (leaseSet, port);
	}

	I2PTunnelConnection::I2PTunnelConnection (I2PService * owner,
		std::shared_ptr<boost::asio::ip::tcp::socket> socket, std::shared_ptr<i2p::stream::Stream> stream):
		I2PServiceHandler(owner), m_Socket (socket), m_Stream (stream),
		m_RemoteEndpoint (socket->remote_endpoint ()), m_IsQuiet (true)
	{
	}

	I2PTunnelConnection::I2PTunnelConnection (I2PService * owner, std::shared_ptr<i2p::stream::Stream> stream,
		const boost::asio::ip::tcp::endpoint& target, bool quiet,
	    std::shared_ptr<boost::asio::ssl::context> sslCtx):
		I2PServiceHandler(owner), m_Stream (stream), m_RemoteEndpoint (target), m_IsQuiet (quiet)
	{
		m_Socket = std::make_shared<boost::asio::ip::tcp::socket> (owner->GetService ());
		if (sslCtx)
			m_SSL = std::make_shared<boost::asio::ssl::stream<boost::asio::ip::tcp::socket&> > (*m_Socket, *sslCtx);
	}

	I2PTunnelConnection::~I2PTunnelConnection ()
	{
	}

	void I2PTunnelConnection::I2PConnect (const uint8_t * msg, size_t len)
	{
		if (m_Stream)
		{
			if (msg)
				m_Stream->Send (msg, len); // connect and send
			else
				m_Stream->Send (m_Buffer, 0); // connect
		}
		StreamReceive ();
		Receive ();
	}

	boost::asio::ip::address GetLoopbackAddressFor(const i2p::data::IdentHash & addr)
	{
		boost::asio::ip::address_v4::bytes_type bytes;
		const uint8_t * ident = addr;
		bytes[0] = 127;
		memcpy (bytes.data ()+1, ident, 3);
		boost::asio::ip::address ourIP = boost::asio::ip::address_v4 (bytes);
		return ourIP;
	}

#ifdef __linux__
	static void MapToLoopback(std::shared_ptr<boost::asio::ip::tcp::socket> sock, const i2p::data::IdentHash & addr)
	{
		if (sock)
		{
			// bind to 127.x.x.x address
			// where x.x.x are first three bytes from ident
			auto ourIP = GetLoopbackAddressFor(addr);
			boost::system::error_code ec;
			sock->bind (boost::asio::ip::tcp::endpoint (ourIP, 0), ec);
			if (ec)
				LogPrint (eLogError, "I2PTunnel: Can't bind ourIP to ", ourIP.to_string (), ": ", ec.message ());
		}
	}
#endif

	void I2PTunnelConnection::Connect (bool isUniqueLocal)
	{
		if (m_Socket)
		{
			I2PTunnelSetSocketOptions (m_Socket);
#ifdef __linux__
			if (isUniqueLocal && m_RemoteEndpoint.address ().is_v4 () &&
				m_RemoteEndpoint.address ().to_v4 ().to_bytes ()[0] == 127)
			{
				m_Socket->open (boost::asio::ip::tcp::v4 ());
				auto ident = m_Stream->GetRemoteIdentity()->GetIdentHash();
				MapToLoopback(m_Socket, ident);
			}
#endif
			m_Socket->async_connect (m_RemoteEndpoint, std::bind (&I2PTunnelConnection::HandleConnect,
				shared_from_this (), std::placeholders::_1));
		}
	}

	void I2PTunnelConnection::Connect (const boost::asio::ip::address& localAddress)
	{
		if (m_Socket)
		{
			if (m_RemoteEndpoint.address().is_v6 ())
				m_Socket->open (boost::asio::ip::tcp::v6 ());
			else
				m_Socket->open (boost::asio::ip::tcp::v4 ());
			boost::system::error_code ec;
			m_Socket->bind (boost::asio::ip::tcp::endpoint (localAddress, 0), ec);
			if (ec)
				LogPrint (eLogError, "I2PTunnel: Can't bind to ", localAddress.to_string (), ": ", ec.message ());
		}
		Connect (false);
	}

	void I2PTunnelConnection::Terminate ()
	{
		if (Kill()) return;
		if (m_SSL) m_SSL = nullptr;
		if (m_Stream)
		{
			m_Stream->Close ();
			m_Stream.reset ();
		}
		boost::system::error_code ec;
		m_Socket->shutdown(boost::asio::ip::tcp::socket::shutdown_send, ec); // avoid RST
		m_Socket->close ();

		Done(shared_from_this ());
	}

	void I2PTunnelConnection::Receive ()
	{
		if (m_SSL)
			m_SSL->async_read_some (boost::asio::buffer(m_Buffer, I2P_TUNNEL_CONNECTION_BUFFER_SIZE),
				std::bind(&I2PTunnelConnection::HandleReceive, shared_from_this (),
				std::placeholders::_1, std::placeholders::_2));
		else
			m_Socket->async_read_some (boost::asio::buffer(m_Buffer, I2P_TUNNEL_CONNECTION_BUFFER_SIZE),
				std::bind(&I2PTunnelConnection::HandleReceive, shared_from_this (),
				std::placeholders::_1, std::placeholders::_2));
	}

	void I2PTunnelConnection::HandleReceive (const boost::system::error_code& ecode, std::size_t bytes_transferred)
	{
		if (ecode)
		{
			if (ecode != boost::asio::error::operation_aborted)
			{
				LogPrint (eLogError, "I2PTunnel: Read error: ", ecode.message ());
				Terminate ();
			}
		}
		else
			WriteToStream (m_Buffer, bytes_transferred);
	}

	void I2PTunnelConnection::WriteToStream (const uint8_t * buf, size_t len)
	{
		if (m_Stream)
		{
			auto s = shared_from_this ();
			m_Stream->AsyncSend (buf, len,
				[s](const boost::system::error_code& ecode)
				{
					if (!ecode)
						s->Receive ();
					else
						s->Terminate ();
				});
			}
	}

	void I2PTunnelConnection::HandleWrite (const boost::system::error_code& ecode)
	{
		if (ecode)
		{
			LogPrint (eLogError, "I2PTunnel: Write error: ", ecode.message ());
			if (ecode != boost::asio::error::operation_aborted)
				Terminate ();
		}
		else
			StreamReceive ();
	}

	void I2PTunnelConnection::StreamReceive ()
	{
		if (m_Stream)
		{
			if (m_Stream->GetStatus () == i2p::stream::eStreamStatusNew ||
				m_Stream->GetStatus () == i2p::stream::eStreamStatusOpen) // regular
			{
				m_Stream->AsyncReceive (boost::asio::buffer (m_StreamBuffer, I2P_TUNNEL_CONNECTION_BUFFER_SIZE),
					std::bind (&I2PTunnelConnection::HandleStreamReceive, shared_from_this (),
					std::placeholders::_1, std::placeholders::_2),
					I2P_TUNNEL_CONNECTION_MAX_IDLE);
			}
			else // closed by peer
			{
				// get remaining data
				auto len = m_Stream->ReadSome (m_StreamBuffer, I2P_TUNNEL_CONNECTION_BUFFER_SIZE);
				if (len > 0) // still some data
					Write (m_StreamBuffer, len);
				else // no more data
					Terminate ();
			}
		}
	}

	void I2PTunnelConnection::HandleStreamReceive (const boost::system::error_code& ecode, std::size_t bytes_transferred)
	{
		if (ecode)
		{
			if (ecode != boost::asio::error::operation_aborted)
			{
				LogPrint (eLogError, "I2PTunnel: Stream read error: ", ecode.message ());
				if (bytes_transferred > 0)
					Write (m_StreamBuffer, bytes_transferred); // postpone termination
				else if (ecode == boost::asio::error::timed_out && m_Stream && m_Stream->IsOpen ())
					StreamReceive ();
				else
					Terminate ();
			}
			else
				Terminate ();
		}
		else
			Write (m_StreamBuffer, bytes_transferred);
	}

	void I2PTunnelConnection::Write (const uint8_t * buf, size_t len)
	{
		if (m_SSL)
			boost::asio::async_write (*m_SSL, boost::asio::buffer (buf, len), boost::asio::transfer_all (),
				std::bind (&I2PTunnelConnection::HandleWrite, shared_from_this (), std::placeholders::_1));
		else
			boost::asio::async_write (*m_Socket, boost::asio::buffer (buf, len), boost::asio::transfer_all (),
				std::bind (&I2PTunnelConnection::HandleWrite, shared_from_this (), std::placeholders::_1));
	}

	void I2PTunnelConnection::HandleConnect (const boost::system::error_code& ecode)
	{
		if (ecode)
		{
			LogPrint (eLogError, "I2PTunnel: Connect error: ", ecode.message ());
			Terminate ();
		}
		else
		{
			LogPrint (eLogDebug, "I2PTunnel: Connected");
			if (m_SSL)
				m_SSL->async_handshake (boost::asio::ssl::stream_base::client,
					std::bind (&I2PTunnelConnection::HandleHandshake, shared_from_this (), std::placeholders::_1));
			else
				Established ();
		}
	}

	void I2PTunnelConnection::HandleHandshake (const boost::system::error_code& ecode)
	{
		if (ecode)
		{
			LogPrint (eLogError, "I2PTunnel: Handshake error: ", ecode.message ());
			Terminate ();
		}
		else
		{
			LogPrint (eLogDebug, "I2PTunnel: SSL connected");
			Established ();
		}
	}

	void I2PTunnelConnection::Established ()
	{
		if (m_IsQuiet)
			StreamReceive ();
		else
		{
			// send destination first like received from I2P
			std::string dest = m_Stream->GetRemoteIdentity ()->ToBase64 ();
			dest += "\n";
			if(sizeof(m_StreamBuffer) >= dest.size()) {
				memcpy (m_StreamBuffer, dest.c_str (), dest.size ());
			}
			HandleStreamReceive (boost::system::error_code (), dest.size ());
		}
		Receive ();
	}

	void I2PClientTunnelConnectionHTTP::Write (const uint8_t * buf, size_t len)
	{
		if (m_HeaderSent)
			I2PTunnelConnection::Write (buf, len);
		else
		{
			m_InHeader.clear ();
			m_InHeader.write ((const char *)buf, len);
			std::string line;
			bool endOfHeader = false;
			while (!endOfHeader)
			{
				std::getline(m_InHeader, line);
				if (!m_InHeader.fail ())
				{
					if (line == "\r") endOfHeader = true;
					else
					{
						if (!m_ConnectionSent && !line.compare(0, 10, "Connection"))
						{
							/* close connection, if not Connection: (U|u)pgrade (for websocket) */
							auto x = line.find("pgrade");
							if (x != std::string::npos && std::tolower(line[x - 1]) == 'u')
								m_OutHeader << line << "\r\n";
							else
								m_OutHeader << "Connection: close\r\n";

							m_ConnectionSent = true;
						}
						else if (!m_ProxyConnectionSent && !line.compare(0, 16, "Proxy-Connection"))
						{
							m_OutHeader << "Proxy-Connection: close\r\n";
							m_ProxyConnectionSent = true;
						}
						else
						m_OutHeader << line << "\n";
					}
				}
				else
				{
					// insert incomplete line back
					m_InHeader.clear ();
					m_InHeader << line;
					break;
				}
			}

			if (endOfHeader)
			{
				if (!m_ConnectionSent) m_OutHeader << "Connection: close\r\n";
				if (!m_ProxyConnectionSent) m_OutHeader << "Proxy-Connection: close\r\n";
				m_OutHeader << "\r\n"; // end of header
				m_OutHeader << m_InHeader.str ().substr (m_InHeader.tellg ()); // data right after header
				m_InHeader.str ("");
				m_HeaderSent = true;
				I2PTunnelConnection::Write ((uint8_t *)m_OutHeader.str ().c_str (), m_OutHeader.str ().length ());
			}
			else if (m_OutHeader.tellp () < I2P_TUNNEL_HTTP_MAX_HEADER_SIZE)
				StreamReceive (); // read more header
			else
			{
				LogPrint (eLogError, "I2PTunnel: HTTP header exceeds max size ", I2P_TUNNEL_HTTP_MAX_HEADER_SIZE);
				Terminate ();
			}
		}
	}

	I2PServerTunnelConnectionHTTP::I2PServerTunnelConnectionHTTP (I2PService * owner, std::shared_ptr<i2p::stream::Stream> stream,
		const boost::asio::ip::tcp::endpoint& target, const std::string& host,
	    std::shared_ptr<boost::asio::ssl::context> sslCtx):
		I2PTunnelConnection (owner, stream, target, true, sslCtx), m_Host (host),
		m_HeaderSent (false), m_ResponseHeaderSent (false), m_From (stream->GetRemoteIdentity ())
	{
		if (sslCtx)
			SSL_set_tlsext_host_name(GetSSL ()->native_handle(), host.c_str ());
	}

	void I2PServerTunnelConnectionHTTP::Write (const uint8_t * buf, size_t len)
	{
		if (m_HeaderSent)
			I2PTunnelConnection::Write (buf, len);
		else
		{
			m_InHeader.clear ();
			m_InHeader.write ((const char *)buf, len);
			std::string line;
			bool endOfHeader = false, connection = false;
			while (!endOfHeader)
			{
				std::getline(m_InHeader, line);
				if (m_InHeader.fail ()) break;
				if (!m_InHeader.eof ())
				{
					if (line == "\r") endOfHeader = true;
					else
					{
						// strip up some headers
						static const std::vector<std::string> excluded // list of excluded headers
						{
							"Keep-Alive:", "X-I2P"
						};
						bool matched = false;
						for (const auto& it: excluded)
							if (boost::iequals (line.substr (0, it.length ()), it))
							{
								matched = true;
								break;
							}
						if (matched) continue;

						// replace some headers
						if (!m_Host.empty () && boost::iequals (line.substr (0, 5), "Host:"))
							m_OutHeader << "Host: " << m_Host << "\r\n"; // override host
						else if (boost::iequals (line.substr (0, 11), "Connection:"))
						{
							auto x = line.find("pgrade");
							if (x != std::string::npos && x && std::tolower(line[x - 1]) != 'u') // upgrade or Upgrade
								m_OutHeader << line << "\n";
							else
								m_OutHeader << "Connection: close\r\n";
							connection = true;
						}
						else // forward as is
							m_OutHeader << line << "\n";
					}
				}
				else
				{
					// insert incomplete line back
					m_InHeader.clear ();
					m_InHeader << line;
					break;
				}
			}

			if (endOfHeader)
			{
				// add Connection if not presented
				if (!connection)
					m_OutHeader << "Connection: close\r\n";
				// add X-I2P fields
				if (m_From)
				{
					m_OutHeader << X_I2P_DEST_B32 << ": " << context.GetAddressBook ().ToAddress(m_From->GetIdentHash ()) << "\r\n";
					m_OutHeader << X_I2P_DEST_HASH << ": " << m_From->GetIdentHash ().ToBase64 () << "\r\n";
					m_OutHeader << X_I2P_DEST_B64 << ": " << m_From->ToBase64 () << "\r\n";
				}

				m_OutHeader << "\r\n"; // end of header
				m_OutHeader << m_InHeader.str ().substr (m_InHeader.tellg ()); // data right after header
				m_InHeader.str ("");
				m_From = nullptr;
				m_HeaderSent = true;
				I2PTunnelConnection::Write ((uint8_t *)m_OutHeader.str ().c_str (), m_OutHeader.str ().length ());
			}
			else if (m_OutHeader.tellp () < I2P_TUNNEL_HTTP_MAX_HEADER_SIZE)
				StreamReceive (); // read more header
			else
			{
				LogPrint (eLogError, "I2PTunnel: HTTP header exceeds max size ", I2P_TUNNEL_HTTP_MAX_HEADER_SIZE);
				Terminate ();
			}
		}
	}

	void I2PServerTunnelConnectionHTTP::WriteToStream (const uint8_t * buf, size_t len)
	{
		if (m_ResponseHeaderSent)
			I2PTunnelConnection::WriteToStream (buf, len);
		else
		{
			m_InHeader.clear ();
			if (m_InHeader.str ().empty ()) m_OutHeader.str (""); // start of response
			m_InHeader.write ((const char *)buf, len);
			std::string line;
			bool endOfHeader = false;
			while (!endOfHeader)
			{
				std::getline(m_InHeader, line);
				if (m_InHeader.fail ()) break;
				if (!m_InHeader.eof ())
				{
					if (line == "\r") endOfHeader = true;
					else
					{
						static const std::vector<std::string> excluded // list of excluded headers
						{
							"Server:", "Date:", "X-Runtime:", "X-Powered-By:", "Proxy"
						};
						bool matched = false;
						for (const auto& it: excluded)
							if (!line.compare(0, it.length (), it))
							{
								matched = true;
								break;
							}
						if (!matched)
							m_OutHeader << line << "\n";
					}
				}
				else
				{
					// insert incomplete line back
					m_InHeader.clear ();
					m_InHeader << line;
					break;
				}
			}

			if (endOfHeader)
			{
				m_OutHeader << "\r\n"; // end of header
				m_OutHeader << m_InHeader.str ().substr (m_InHeader.tellg ()); // data right after header
				m_InHeader.str ("");
				m_ResponseHeaderSent = true;
				I2PTunnelConnection::WriteToStream ((uint8_t *)m_OutHeader.str ().c_str (), m_OutHeader.str ().length ());
				m_OutHeader.str ("");
			}
			else
				Receive ();
		}
	}

	I2PTunnelConnectionIRC::I2PTunnelConnectionIRC (I2PService * owner, std::shared_ptr<i2p::stream::Stream> stream,
		const boost::asio::ip::tcp::endpoint& target, const std::string& webircpass,
	    std::shared_ptr<boost::asio::ssl::context> sslCtx):
		I2PTunnelConnection (owner, stream, target, true, sslCtx), m_From (stream->GetRemoteIdentity ()),
		m_NeedsWebIrc (webircpass.length() ? true : false), m_WebircPass (webircpass)
	{
	}

	void I2PTunnelConnectionIRC::Write (const uint8_t * buf, size_t len)
	{
		m_OutPacket.str ("");
		if (m_NeedsWebIrc)
		{
			m_NeedsWebIrc = false;
			m_OutPacket << "WEBIRC " << m_WebircPass << " cgiirc " << context.GetAddressBook ().ToAddress (m_From->GetIdentHash ())
				<< " " << GetSocket ()->local_endpoint ().address () << std::endl;
		}

		m_InPacket.clear ();
		m_InPacket.write ((const char *)buf, len);

		while (!m_InPacket.eof () && !m_InPacket.fail ())
		{
			std::string line;
			std::getline (m_InPacket, line);
			if (line.length () == 0 && m_InPacket.eof ())
				m_InPacket.str ("");
			auto pos = line.find ("USER");
			if (!pos) // start of line
			{
				pos = line.find (" ");
				pos++;
				pos = line.find (" ", pos);
				pos++;
				auto nextpos = line.find (" ", pos);
				m_OutPacket << line.substr (0, pos);
				m_OutPacket << context.GetAddressBook ().ToAddress (m_From->GetIdentHash ());
				m_OutPacket << line.substr (nextpos) << '\n';
			}
			else
				m_OutPacket << line << '\n';
		}
		I2PTunnelConnection::Write ((uint8_t *)m_OutPacket.str ().c_str (), m_OutPacket.str ().length ());
	}


	/* This handler tries to establish a connection with the desired server and dies if it fails to do so */
	class I2PClientTunnelHandler: public I2PServiceHandler, public std::enable_shared_from_this<I2PClientTunnelHandler>
	{
		public:
			I2PClientTunnelHandler (I2PClientTunnel * parent, std::shared_ptr<const Address> address,
				uint16_t destinationPort, std::shared_ptr<boost::asio::ip::tcp::socket> socket):
				I2PServiceHandler(parent), m_Address(address),
				m_DestinationPort (destinationPort), m_Socket(socket) {};
			void Handle();
			void Terminate();
		private:
			void HandleStreamRequestComplete (std::shared_ptr<i2p::stream::Stream> stream);
			std::shared_ptr<const Address> m_Address;
			uint16_t m_DestinationPort;
			std::shared_ptr<boost::asio::ip::tcp::socket> m_Socket;
	};

	void I2PClientTunnelHandler::Handle()
	{
		GetOwner()->CreateStream (
			std::bind (&I2PClientTunnelHandler::HandleStreamRequestComplete, shared_from_this(), std::placeholders::_1),
			m_Address, m_DestinationPort);
	}

	void I2PClientTunnelHandler::HandleStreamRequestComplete (std::shared_ptr<i2p::stream::Stream> stream)
	{
		if (stream)
		{
			if (Kill()) return;
			LogPrint (eLogDebug, "I2PTunnel: New connection");
			auto connection = std::make_shared<I2PTunnelConnection>(GetOwner(), m_Socket, stream);
			GetOwner()->AddHandler (connection);
			connection->I2PConnect ();
			Done(shared_from_this());
		}
		else
		{
			LogPrint (eLogError, "I2PTunnel: Client Tunnel Issue when creating the stream, check the previous warnings for more info.");
			Terminate();
		}
	}

	void I2PClientTunnelHandler::Terminate()
	{
		if (Kill()) return;
		if (m_Socket)
		{
			m_Socket->close();
			m_Socket = nullptr;
		}
		Done(shared_from_this());
	}

	I2PClientTunnel::I2PClientTunnel (const std::string& name, const std::string& destination,
		const std::string& address, uint16_t port, std::shared_ptr<ClientDestination> localDestination, uint16_t destinationPort):
		TCPIPAcceptor (address, port, localDestination), m_Name (name), m_Destination (destination),
		m_DestinationPort (destinationPort), m_KeepAliveInterval (0)
	{
	}

	void I2PClientTunnel::Start ()
	{
		TCPIPAcceptor::Start ();
		GetAddress ();
		if (m_KeepAliveInterval)
			ScheduleKeepAliveTimer ();
	}

	void I2PClientTunnel::Stop ()
	{
		TCPIPAcceptor::Stop();
		m_Address = nullptr;
		if (m_KeepAliveTimer) m_KeepAliveTimer->cancel ();
	}

	void I2PClientTunnel::SetKeepAliveInterval (uint32_t keepAliveInterval)
	{
		m_KeepAliveInterval = keepAliveInterval;
		if (m_KeepAliveInterval)
			m_KeepAliveTimer.reset (new boost::asio::deadline_timer (GetLocalDestination ()->GetService ()));
	}

	/* HACK: maybe we should create a caching IdentHash provider in AddressBook */
	std::shared_ptr<const Address> I2PClientTunnel::GetAddress ()
	{
		if (!m_Address)
		{
			m_Address = i2p::client::context.GetAddressBook ().GetAddress (m_Destination);
			if (!m_Address)
				LogPrint (eLogWarning, "I2PTunnel: Remote destination ", m_Destination, " not found");
		}
		return m_Address;
	}

	std::shared_ptr<I2PServiceHandler> I2PClientTunnel::CreateHandler(std::shared_ptr<boost::asio::ip::tcp::socket> socket)
	{
		auto address = GetAddress ();
		if (address)
			return std::make_shared<I2PClientTunnelHandler>(this, address, m_DestinationPort, socket);
		else
			return nullptr;
	}

	void I2PClientTunnel::ScheduleKeepAliveTimer ()
	{
		if (m_KeepAliveTimer)
		{
			m_KeepAliveTimer->expires_from_now (boost::posix_time::seconds (m_KeepAliveInterval));
			m_KeepAliveTimer->async_wait (std::bind (&I2PClientTunnel::HandleKeepAliveTimer,
				this, std::placeholders::_1));
		}
	}

	void I2PClientTunnel::HandleKeepAliveTimer (const boost::system::error_code& ecode)
	{
		if (ecode != boost::asio::error::operation_aborted)
		{
			if (m_Address && m_Address->IsValid ())
			{
				if (m_Address->IsIdentHash ())
					GetLocalDestination ()->SendPing (m_Address->identHash);
				else
					GetLocalDestination ()->SendPing (m_Address->blindedPublicKey);
			}
			ScheduleKeepAliveTimer ();
		}
	}

	I2PServerTunnel::I2PServerTunnel (const std::string& name, const std::string& address,
		uint16_t port, std::shared_ptr<ClientDestination> localDestination, uint16_t inport, bool gzip):
		I2PService (localDestination), m_IsUniqueLocal(true), m_Name (name), m_Address (address), m_Port (port), m_IsAccessList (false)
	{
		m_PortDestination = localDestination->GetStreamingDestination (inport);
		if (!m_PortDestination) // default destination
			m_PortDestination = localDestination->CreateStreamingDestination (inport, gzip);
	}

	void I2PServerTunnel::Start ()
	{
		m_Endpoint.port (m_Port);
		boost::system::error_code ec;
		auto addr = boost::asio::ip::address::from_string (m_Address, ec);
		if (!ec)
		{
			m_Endpoint.address (addr);
			Accept ();
		}
		else
		{
			auto resolver = std::make_shared<boost::asio::ip::tcp::resolver>(GetService ());
			resolver->async_resolve (boost::asio::ip::tcp::resolver::query (m_Address, ""),
				std::bind (&I2PServerTunnel::HandleResolve, this,
					std::placeholders::_1, std::placeholders::_2, resolver));
		}
	}

	void I2PServerTunnel::Stop ()
	{
		if (m_PortDestination)
			m_PortDestination->ResetAcceptor ();
		auto localDestination = GetLocalDestination ();
		if (localDestination)
			localDestination->StopAcceptingStreams ();

		ClearHandlers ();
	}

	void I2PServerTunnel::HandleResolve (const boost::system::error_code& ecode, boost::asio::ip::tcp::resolver::iterator it,
		std::shared_ptr<boost::asio::ip::tcp::resolver> resolver)
	{
		if (!ecode)
		{
			bool found = false;
			boost::asio::ip::tcp::endpoint ep;
			if (m_LocalAddress)
			{
				boost::asio::ip::tcp::resolver::iterator end;
				while (it != end)
				{
					ep = *it;
					if (!ep.address ().is_unspecified ())
					{
						if (ep.address ().is_v4 ())
						{
							if (m_LocalAddress->is_v4 ()) found = true;
						}
						else if (ep.address ().is_v6 ())
						{
							if (i2p::util::net::IsYggdrasilAddress (ep.address ()))
							{
								if (i2p::util::net::IsYggdrasilAddress (*m_LocalAddress))
									found = true;
							}
							else if (m_LocalAddress->is_v6 ())
								found = true;
						}
					}
					if (found) break;
					it++;
				}
			}
			else
			{
				found = true;
				ep = *it; // first available
			}
			if (!found)
			{
				LogPrint (eLogError, "I2PTunnel: Unable to resolve to compatible address");
				return;
			}

			auto addr = ep.address ();
			LogPrint (eLogInfo, "I2PTunnel: Server tunnel ", (*it).host_name (), " has been resolved to ", addr);
			m_Endpoint.address (addr);
			Accept ();
		}
		else
			LogPrint (eLogError, "I2PTunnel: Unable to resolve server tunnel address: ", ecode.message ());
	}

	void I2PServerTunnel::SetAccessList (const std::set<i2p::data::IdentHash>& accessList)
	{
		m_AccessList = accessList;
		m_IsAccessList = true;
	}

	void I2PServerTunnel::SetLocalAddress (const std::string& localAddress)
	{
		boost::system::error_code ec;
		auto addr = boost::asio::ip::address::from_string(localAddress, ec);
		if (!ec)
			m_LocalAddress.reset (new boost::asio::ip::address (addr));
		else
			LogPrint (eLogError, "I2PTunnel: Can't set local address ", localAddress);
	}

	void I2PServerTunnel::SetSSL (bool ssl)
	{
		if (ssl)
		{
			m_SSLCtx = std::make_shared<boost::asio::ssl::context> (boost::asio::ssl::context::sslv23);
			m_SSLCtx->set_verify_mode(boost::asio::ssl::context::verify_none);
		}
		else
			m_SSLCtx = nullptr;
	}

	void I2PServerTunnel::Accept ()
	{
		if (m_PortDestination)
			m_PortDestination->SetAcceptor (std::bind (&I2PServerTunnel::HandleAccept, this, std::placeholders::_1));

		auto localDestination = GetLocalDestination ();
		if (localDestination)
		{
			if (!localDestination->IsAcceptingStreams ()) // set it as default if not set yet
				localDestination->AcceptStreams (std::bind (&I2PServerTunnel::HandleAccept, this, std::placeholders::_1));
		}
		else
			LogPrint (eLogError, "I2PTunnel: Local destination not set for server tunnel");
	}

	void I2PServerTunnel::HandleAccept (std::shared_ptr<i2p::stream::Stream> stream)
	{
		if (stream)
		{
			if (m_IsAccessList)
			{
				if (!m_AccessList.count (stream->GetRemoteIdentity ()->GetIdentHash ()))
				{
					LogPrint (eLogWarning, "I2PTunnel: Address ", stream->GetRemoteIdentity ()->GetIdentHash ().ToBase32 (), " is not in white list. Incoming connection dropped");
					stream->Close ();
					return;
				}
			}
			// new connection
			auto conn = CreateI2PConnection (stream);
			AddHandler (conn);
			if (m_LocalAddress)
				conn->Connect (*m_LocalAddress);
			else
				conn->Connect (m_IsUniqueLocal);
		}
	}

	std::shared_ptr<I2PTunnelConnection> I2PServerTunnel::CreateI2PConnection (std::shared_ptr<i2p::stream::Stream> stream)
	{
		return std::make_shared<I2PTunnelConnection> (this, stream, GetEndpoint (), true, m_SSLCtx);

	}

	I2PServerTunnelHTTP::I2PServerTunnelHTTP (const std::string& name, const std::string& address,
		uint16_t port, std::shared_ptr<ClientDestination> localDestination,
		const std::string& host, uint16_t inport, bool gzip):
		I2PServerTunnel (name, address, port, localDestination, inport, gzip),
		m_Host (host)
	{
	}

	std::shared_ptr<I2PTunnelConnection> I2PServerTunnelHTTP::CreateI2PConnection (std::shared_ptr<i2p::stream::Stream> stream)
	{
		return std::make_shared<I2PServerTunnelConnectionHTTP> (this, stream, GetEndpoint (), m_Host, GetSSLCtx ());
	}

	I2PServerTunnelIRC::I2PServerTunnelIRC (const std::string& name, const std::string& address,
		uint16_t port, std::shared_ptr<ClientDestination> localDestination,
		const std::string& webircpass, uint16_t inport, bool gzip):
		I2PServerTunnel (name, address, port, localDestination, inport, gzip),
		m_WebircPass (webircpass)
	{
	}

	std::shared_ptr<I2PTunnelConnection> I2PServerTunnelIRC::CreateI2PConnection (std::shared_ptr<i2p::stream::Stream> stream)
	{
		return std::make_shared<I2PTunnelConnectionIRC> (this, stream, GetEndpoint (), m_WebircPass, GetSSLCtx ());
	}
}
}

