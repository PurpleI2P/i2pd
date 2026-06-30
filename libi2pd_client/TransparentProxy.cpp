/*
* Copyright (c) 2013-2026, The PurpleI2P Project
*
* This file is part of Purple i2pd project and licensed under BSD3
*
* See full license text in LICENSE file at top of project tree
*/

#include "TransparentProxy.h"
#include <cstring>
#include "Log.h"
#include "Streaming.h"
#include "I2PTunnel.h"
#include "ClientContext.h"

#if defined(__linux__)
#	include <netinet/in.h>
#	include <sys/socket.h>
#	include <linux/netfilter_ipv4.h> /* defines SO_ORIGINAL_DST */
#	ifndef IP_TRANSPARENT
#		define IP_TRANSPARENT 19
#	endif
#	ifndef SO_ORIGINAL_DST
#		define SO_ORIGINAL_DST 80
#	endif
#endif

namespace i2p
{
namespace client
{
	class TransparentProxyHandler: public I2PServiceHandler, public std::enable_shared_from_this<TransparentProxyHandler>
	{
		public:

			TransparentProxyHandler (TransparentProxyServer* owner, std::shared_ptr<boost::asio::ip::tcp::socket> sock,
					std::shared_ptr<AddressMapper> mapper, TransProxyType type):
				I2PServiceHandler (owner), m_Sock (sock), m_AddressMapper (mapper), m_Type (type) {}
			~TransparentProxyHandler () { Terminate (); }

			void Handle () override;

		private:

			void Terminate ();
			void HandleStreamRequestComplete (std::shared_ptr<i2p::stream::Stream> stream);
			// Recover the original destination of the diverted connection.
			bool GetOriginalDestination (boost::asio::ip::tcp::endpoint& ep);

			std::shared_ptr<boost::asio::ip::tcp::socket> m_Sock;
			std::shared_ptr<i2p::stream::Stream> m_Stream;
			std::shared_ptr<AddressMapper> m_AddressMapper;
			TransProxyType m_Type;
			uint16_t m_Port = 0;
	};

	TransparentProxyServer::TransparentProxyServer (const std::string& name, const std::string& address, uint16_t port,
			TransProxyType type, std::shared_ptr<AddressMapper> mapper, std::shared_ptr<ClientDestination> localDestination):
		I2PService (localDestination ? localDestination : i2p::client::context.GetSharedLocalDestination ()),
		m_Name (name), m_LocalEndpoint (boost::asio::ip::make_address (address), port),
		m_AddressMapper (mapper), m_Type (type)
	{
	}

	void TransparentProxyServer::Start ()
	{
		I2PService::Start ();
#if defined(__linux__) && defined(IP_TRANSPARENT)
		try
		{
			m_Acceptor.reset (new boost::asio::ip::tcp::acceptor (GetService ()));
			m_Acceptor->open (m_LocalEndpoint.protocol ());
			m_Acceptor->set_option (boost::asio::ip::tcp::acceptor::reuse_address (true));
			if (m_Type == TransProxyType::tproxy)
			{
				// Let the listener accept connections whose original destination is
				// not the local machine (packets redirected by iptables -j TPROXY).
				int one = 1;
				if (setsockopt (m_Acceptor->native_handle (), IPPROTO_IP, IP_TRANSPARENT, &one, sizeof (one)) < 0)
				{
					m_Acceptor.reset (nullptr);
					LogPrint (eLogError, "TransProxy: IP_TRANSPARENT failed: ", strerror (errno),
						" (need CAP_NET_ADMIN/root)");
					return;
				}
			}
			m_Acceptor->bind (m_LocalEndpoint);
			m_LocalEndpoint = m_Acceptor->local_endpoint ();
			m_Acceptor->listen ();
			LogPrint (eLogInfo, "TransProxy: ", m_Name, " listening on ",
				m_LocalEndpoint.address ().to_string (), ":", m_LocalEndpoint.port (),
				" (", m_Type == TransProxyType::tproxy ? "tproxy" : "redirect", ")");
			Accept ();
		}
		catch (std::exception& e)
		{
			LogPrint (eLogError, "TransProxy: Failed to start on ",
				m_LocalEndpoint.address ().to_string (), ":", m_LocalEndpoint.port (), ": ", e.what ());
			m_Acceptor.reset (nullptr);
		}
#else
		LogPrint (eLogError, "TransProxy: TPROXY/REDIRECT transparent proxying is not supported on this platform");
#endif
	}

	void TransparentProxyServer::Stop ()
	{
		if (m_Acceptor) { m_Acceptor->close (); m_Acceptor.reset (nullptr); }
		ClearHandlers ();
		I2PService::Stop ();
	}

	void TransparentProxyServer::Accept ()
	{
		if (!m_Acceptor) return;
		auto self = std::static_pointer_cast<TransparentProxyServer> (shared_from_this ());
		auto newSocket = std::make_shared<boost::asio::ip::tcp::socket> (GetService ());
		m_Acceptor->async_accept (*newSocket,
			[self, newSocket](const boost::system::error_code& ecode)
			{
				if (ecode == boost::asio::error::operation_aborted) return;
				if (!ecode)
				{
					LogPrint (eLogDebug, "TransProxy: accepted");
					auto handler = self->CreateHandler (newSocket);
					if (handler)
					{
						self->AddHandler (handler);
						handler->Handle ();
					}
					else
						newSocket->close ();
					self->Accept ();
				}
				else
					LogPrint (eLogError, "TransProxy: accept error: ", ecode.message ());
			});
	}

	std::shared_ptr<I2PServiceHandler> TransparentProxyServer::CreateHandler (std::shared_ptr<boost::asio::ip::tcp::socket> socket)
	{
		return std::make_shared<TransparentProxyHandler> (this, socket, m_AddressMapper, m_Type);
	}

	void TransparentProxyHandler::Terminate ()
	{
		if (Kill ()) return;
		if (m_Sock) { m_Sock->close (); m_Sock = nullptr; }
		if (m_Stream) { m_Stream->AsyncClose (); m_Stream = nullptr; }
		Done (shared_from_this ());
	}

	bool TransparentProxyHandler::GetOriginalDestination (boost::asio::ip::tcp::endpoint& ep)
	{
#if defined(__linux__)
		boost::system::error_code ec;
		if (m_Type == TransProxyType::tproxy)
		{
			// Under TPROXY the accepted socket's local address (getsockname) is
			// the original foreign destination, not the listener's address.
			ep = m_Sock->local_endpoint (ec);
			return !ec;
		}
		else
		{
#	ifdef SO_ORIGINAL_DST
			struct sockaddr_storage ss;
			socklen_t len = sizeof (ss);
			if (getsockopt (m_Sock->native_handle (), IPPROTO_IP, SO_ORIGINAL_DST, &ss, &len) < 0)
			{
				LogPrint (eLogWarning, "TransProxy: SO_ORIGINAL_DST failed: ", strerror (errno));
				return false;
			}
			if (ss.ss_family == AF_INET)
			{
				auto* sin = (struct sockaddr_in*)&ss;
				ep = boost::asio::ip::tcp::endpoint (
					boost::asio::ip::address_v4 (ntohl (sin->sin_addr.s_addr)), ntohs (sin->sin_port));
				return true;
			}
			return false;
#	else
			LogPrint (eLogError, "TransProxy: SO_ORIGINAL_DST unavailable");
			return false;
#	endif
		}
#else
		(void)ep;
		return false;
#endif
	}

	void TransparentProxyHandler::Handle ()
	{
		boost::asio::ip::tcp::endpoint dst;
		if (!GetOriginalDestination (dst))
		{
			LogPrint (eLogWarning, "TransProxy: could not recover original destination, closing");
			Terminate ();
			return;
		}
		auto addr = dst.address ();
		if (!addr.is_v4 ())
		{
			LogPrint (eLogWarning, "TransProxy: non-IPv4 original destination, closing");
			Terminate ();
			return;
		}
		auto v4 = addr.to_v4 ();
		if (!m_AddressMapper->IsVirtual (v4))
		{
			// Safety: never relay to arbitrary IPs — only mapped virtual .i2p dsts.
			LogPrint (eLogWarning, "TransProxy: original destination ", addr.to_string (),
				" not in virtual range, rejecting");
			Terminate ();
			return;
		}
		auto name = m_AddressMapper->GetName (v4);
		if (name.empty ())
		{
			LogPrint (eLogWarning, "TransProxy: no live mapping for ", addr.to_string (), ", rejecting");
			Terminate ();
			return;
		}
		m_Port = dst.port ();
		LogPrint (eLogInfo, "TransProxy: ", name, ":", m_Port);
		GetOwner ()->UpdateLastActivityTime ();
		GetOwner ()->CreateStream (
			std::bind (&TransparentProxyHandler::HandleStreamRequestComplete, shared_from_this (), std::placeholders::_1),
			name, m_Port);
	}

	void TransparentProxyHandler::HandleStreamRequestComplete (std::shared_ptr<i2p::stream::Stream> stream)
	{
		if (stream)
		{
			if (m_Sock && m_Sock->is_open ())
			{
				m_Stream = stream;
				LogPrint (eLogInfo, "TransProxy: new I2PTunnel connection");
				auto connection = std::make_shared<I2PTunnelConnection> (GetOwner (), m_Sock, m_Stream);
				GetOwner ()->AddHandler (connection);
				connection->I2PConnect ();
				Done (shared_from_this ()); // hand off to the tunnel connection handler
			}
			else
				stream->AsyncClose ();
		}
		else
		{
			LogPrint (eLogError, "TransProxy: stream creation failed");
			Terminate ();
		}
	}
}
}
