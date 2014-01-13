#include <boost/bind.hpp>
#include <boost/lexical_cast.hpp>
#include "base64.h"
#include "Tunnel.h"
#include "TransitTunnel.h"
#include "Transports.h"
#include "NetDb.h"
#include "Streaming.h"
#include "HTTPServer.h"

namespace i2p
{
namespace util
{
	namespace misc_strings 
	{

		const char name_value_separator[] = { ':', ' ' };
		const char crlf[] = { '\r', '\n' };

	} // namespace misc_strings

	std::vector<boost::asio::const_buffer> HTTPConnection::reply::to_buffers()
	{
		std::vector<boost::asio::const_buffer> buffers;
		buffers.push_back (boost::asio::buffer ("HTTP/1.0 200 OK\r\n")); // always OK
		for (std::size_t i = 0; i < headers.size(); ++i)
		{
			header& h = headers[i];
			buffers.push_back(boost::asio::buffer(h.name));
			buffers.push_back(boost::asio::buffer(misc_strings::name_value_separator));
			buffers.push_back(boost::asio::buffer(h.value));
			buffers.push_back(boost::asio::buffer(misc_strings::crlf));
		}
		buffers.push_back(boost::asio::buffer(misc_strings::crlf));
		buffers.push_back(boost::asio::buffer(content));
		return buffers;
	}

	void HTTPConnection::Terminate ()
	{
		m_Socket->close ();
		delete this;
	}

	void HTTPConnection::Receive ()
	{
		m_Socket->async_read_some (boost::asio::buffer (m_Buffer),
			 boost::bind(&HTTPConnection::HandleReceive, this,
				 boost::asio::placeholders::error, boost::asio::placeholders::bytes_transferred));
	}

	void HTTPConnection::HandleReceive (const boost::system::error_code& ecode, std::size_t bytes_transferred)
	{
		if (!ecode)
  		{
			HandleRequest ();
			boost::asio::async_write (*m_Socket, m_Reply.to_buffers(),
          		boost::bind (&HTTPConnection::HandleWrite, this,
           			boost::asio::placeholders::error));
			//Receive ();
		}
		else if (ecode != boost::asio::error::operation_aborted)
			Terminate ();
	}

	void HTTPConnection::HandleWrite (const boost::system::error_code& ecode)
	{
		Terminate ();
	}

	void HTTPConnection::HandleRequest ()
	{
		std::stringstream s;
		s << "<html>";
		FillContent (s);
		s << "</html>";
		m_Reply.content = s.str ();
		m_Reply.headers.resize(2);
		m_Reply.headers[0].name = "Content-Length";
		m_Reply.headers[0].value = boost::lexical_cast<std::string>(m_Reply.content.size());
		m_Reply.headers[1].name = "Content-Type";
		m_Reply.headers[1].value = "text/html";
	}	

	void HTTPConnection::FillContent (std::stringstream& s)
	{
		s << "<P>Tunnels</P>";
		for (auto it: i2p::tunnel::tunnels.GetOutboundTunnels ())
		{	
			it->GetTunnelConfig ()->Print (s);
			s << " " << (int)it->GetNumSentBytes () << "<BR>";
		}	

		for (auto it: i2p::tunnel::tunnels.GetInboundTunnels ())
		{	
			it.second->GetTunnelConfig ()->Print (s);
			s << " " << (int)it.second->GetNumReceivedBytes () << "<BR>";
		}	

		s << "<P>Transit tunnels</P>";
		for (auto it: i2p::tunnel::tunnels.GetTransitTunnels ())
		{	
			if (dynamic_cast<i2p::tunnel::TransitTunnelGateway *>(it.second))
				s << it.second->GetTunnelID () << "-->";
			else if (dynamic_cast<i2p::tunnel::TransitTunnelEndpoint *>(it.second))
				s << "-->" << it.second->GetTunnelID ();
			else
				s << "-->" << it.second->GetTunnelID () << "-->";
			s << " " << it.second->GetNumTransmittedBytes () << "<BR>";
		}	

		s << "<P>Transports</P>";
		for (auto it: i2p::transports.GetNTCPSessions ())
		{	
			// RouterInfo of incoming connection doesn't have address
			bool outgoing = it.second->GetRemoteRouterInfo ().GetNTCPAddress ();
			if (it.second->IsEstablished ())
			{
				if (outgoing) s << "-->";
				s << it.second->GetRemoteRouterInfo ().GetIdentHashAbbreviation () <<  ": " 
					<< it.second->GetSocket ().remote_endpoint().address ().to_string ();
				if (!outgoing) s << "-->";
				s << "<BR>";
			}	
		}	
	}	

	void HTTPConnection::HandleDestinationRequest (std::string b32)
	{
		uint8_t destination[32];
		i2p::data::Base32ToByteStream (b32.c_str (), b32.length (), destination, 32);
		auto leaseSet = i2p::data::netdb.FindLeaseSet (destination);
		if (!leaseSet)
		{
			i2p::data::netdb.RequestDestination (i2p::data::IdentHash (destination), true);
			std::this_thread::sleep_for (std::chrono::seconds(10)); // wait for 10 seconds
			leaseSet = i2p::data::netdb.FindLeaseSet (destination);
			if (!leaseSet) // still no LeaseSet
			{
				m_Reply.content = "<html>LeaseSet not found</html>";
				m_Reply.headers.resize(2);
				m_Reply.headers[0].name = "Content-Length";
				m_Reply.headers[0].value = boost::lexical_cast<std::string>(m_Reply.content.size());
				m_Reply.headers[1].name = "Content-Type";
				m_Reply.headers[1].value = "text/html";
				return;
			}	
		}	
		// we found LeaseSet
		auto s = i2p::stream::CreateStream (leaseSet);
		if (s)
		{
			std::string request = "GET / HTTP/1.1\n Host:" + b32 + ".b32.i2p\n";
			s->Send ((uint8_t *)request.c_str (), request.length (), 30);			
			std::stringstream ss;
			uint8_t buf[8192];
			size_t r = s->Receive (buf, 8192, 30); // 30 seconds
			if (r) // we recieved data
			{
				ss << std::string ((char *)buf, r);
				while (s->IsOpen () && (r = s->Receive (buf, 8192, 30)) > 0)
					ss << std::string ((char *)buf,r);	
			}	
			else // nothing received
				ss << "<html>Not responding</html>";
			s->Close ();
			//DeleteStream (s);
			
			m_Reply.content = ss.str ();
			m_Reply.headers.resize(2);
			m_Reply.headers[0].name = "Content-Length";
			m_Reply.headers[0].value = boost::lexical_cast<std::string>(m_Reply.content.size());
			m_Reply.headers[1].name = "Content-Type";
			m_Reply.headers[1].value = "text/html";
		}	
	}	
	
	
	HTTPServer::HTTPServer (int port): 
		m_Thread (nullptr), m_Work (m_Service), 
		m_Acceptor (m_Service, boost::asio::ip::tcp::endpoint (boost::asio::ip::tcp::v4(), port)),
		m_NewSocket (nullptr)
	{
		
	}

	HTTPServer::~HTTPServer ()
	{
		Stop ();
	}

	void HTTPServer::Start ()
	{
		m_Thread = new std::thread (std::bind (&HTTPServer::Run, this));
		m_Acceptor.listen ();
		Accept ();
	}

	void HTTPServer::Stop ()
	{
		m_Acceptor.close();
		m_Service.stop ();
		if (m_Thread)
        {       
            m_Thread->join (); 
            delete m_Thread;
            m_Thread = nullptr;
        }    
	}

	void HTTPServer::Run ()
	{
		m_Service.run ();
	}	

	void HTTPServer::Accept ()
	{
		m_NewSocket = new boost::asio::ip::tcp::socket (m_Service);
		m_Acceptor.async_accept (*m_NewSocket, boost::bind (&HTTPServer::HandleAccept, this,
			boost::asio::placeholders::error));
	}

	void HTTPServer::HandleAccept(const boost::system::error_code& ecode)
	{
		if (!ecode)
		{
			new HTTPConnection (m_NewSocket);
			Accept ();
		}
	}	
}
}

