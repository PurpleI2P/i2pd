#include <boost/bind.hpp>
#include <boost/lexical_cast.hpp>
#include "base64.h"
#include "Log.h"
#include "Tunnel.h"
#include "TransitTunnel.h"
#include "Transports.h"
#include "NetDb.h"
#include "HTTPServer.h"

namespace i2p
{
namespace util
{

	const std::string HTTPConnection::itoopieImage =
		"<img alt=\"\" src=\"data:image/png;base64,"
		"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"
		"+U0vclvzH+PAAAAAElFTkSuQmCC"
		"\" />";

	namespace misc_strings
	{

		const char name_value_separator[] = { ':', ' ' };
		const char crlf[] = { '\r', '\n' };

	} // namespace misc_strings

	std::vector<boost::asio::const_buffer> HTTPConnection::reply::to_buffers(int status)
	{
		std::vector<boost::asio::const_buffer> buffers;
		if (headers.size () > 0)
		{
			switch (status)
			{
				case 105: buffers.push_back(boost::asio::buffer("HTTP/1.0 105 Name Not Resolved\r\n")); break;
				case 200: buffers.push_back(boost::asio::buffer("HTTP/1.0 200 OK\r\n")); break;
				case 400: buffers.push_back(boost::asio::buffer("HTTP/1.0 400 Bad Request\r\n")); break;
				case 404: buffers.push_back(boost::asio::buffer("HTTP/1.0 404 Not Found\r\n")); break;
				case 408: buffers.push_back(boost::asio::buffer("HTTP/1.0 408 Request Timeout\r\n")); break;
				case 500: buffers.push_back(boost::asio::buffer("HTTP/1.0 500 Internal Server Error\r\n")); break;
				case 502: buffers.push_back(boost::asio::buffer("HTTP/1.0 502 Bad Gateway\r\n")); break;
				case 503: buffers.push_back(boost::asio::buffer("HTTP/1.0 503 Not Implemented\r\n")); break;
				case 504: buffers.push_back(boost::asio::buffer("HTTP/1.0 504 Gateway Timeout\r\n")); break;
				default:
					buffers.push_back(boost::asio::buffer("HTTP/1.0 200 OK\r\n"));
			}

			for (std::size_t i = 0; i < headers.size(); ++i)
			{
				header& h = headers[i];
				buffers.push_back(boost::asio::buffer(h.name));
				buffers.push_back(boost::asio::buffer(misc_strings::name_value_separator));
				buffers.push_back(boost::asio::buffer(h.value));
				buffers.push_back(boost::asio::buffer(misc_strings::crlf));
			}
			buffers.push_back(boost::asio::buffer(misc_strings::crlf));
		}
		buffers.push_back(boost::asio::buffer(content));
		return buffers;
	}

	void HTTPConnection::Terminate ()
	{
		if (m_Stream)
		{
			m_Stream->Close ();
			DeleteStream (m_Stream);
		}
		m_Socket->close ();
		delete this;
	}

	void HTTPConnection::Receive ()
	{
		m_Socket->async_read_some (boost::asio::buffer (m_Buffer, 8192),
			 boost::bind(&HTTPConnection::HandleReceive, this,
				 boost::asio::placeholders::error, boost::asio::placeholders::bytes_transferred));
	}

	void HTTPConnection::HandleReceive (const boost::system::error_code& ecode, std::size_t bytes_transferred)
	{
		if (!ecode)
  		{
			m_Buffer[bytes_transferred] = 0;
			RunRequest();
		}
		else if (ecode != boost::asio::error::operation_aborted)
			Terminate ();
	}

	void HTTPConnection::RunRequest ()
	{
		auto address = ExtractAddress ();
		if (address.length () > 1) // not just '/'
		{
			std::string uri ("/"), b32;
			size_t pos = address.find ('/', 1);
			if (pos == std::string::npos)
				b32 = address.substr (1); // excluding leading '/' to end of line
			else
			{
				b32 = address.substr (1, pos - 1); // excluding leading '/' to next '/'
				uri = address.substr (pos); // rest of line
			}

			HandleDestinationRequest (b32, uri);
		}
		else
			HandleRequest ();
	}

	std::string HTTPConnection::ExtractAddress ()
	{
		char * get = strstr (m_Buffer, "GET");
		if (get)
		{
			char * http = strstr (get, "HTTP");
			if (http)
				return std::string (get + 4, http - get - 5);
		}
		return "";
	}

	void HTTPConnection::HandleWriteReply (const boost::system::error_code& ecode)
	{
		Terminate ();
	}

	void HTTPConnection::HandleWrite (const boost::system::error_code& ecode)
	{
		if (ecode || (m_Stream && !m_Stream->IsOpen ()))
			Terminate ();
		else // data keeps coming
			AsyncStreamReceive ();
	}

	void HTTPConnection::HandleRequest ()
	{
		std::stringstream s;
		s << "<html>";
		FillContent (s);
		s << "</html>";
		SendReply (s.str ());
	}

	void HTTPConnection::FillContent (std::stringstream& s)
	{
		s << "Data path: " << i2p::util::filesystem::GetDataDir().string() << "<BR>" << "<BR>";
		s << "Our external address:" << "<BR>";
		for (auto& address : i2p::context.GetRouterInfo().GetAddresses())
		{
			switch (address.transportStyle)
			{
				case i2p::data::RouterInfo::eTransportNTCP:
					s << "NTCP&nbsp;&nbsp;";
				break;
				case i2p::data::RouterInfo::eTransportSSU:
					s << "SSU&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;";
				break;
				default:
					s << "Unknown&nbsp;&nbsp;";
			}
			s << address.host.to_string() << ":" << address.port << "<BR>";
		}
		s << "<BR>Routers: " << i2p::data::netdb.GetNumRouters () << " ";
		s << "Floodfills: " << i2p::data::netdb.GetNumFloodfills () << " ";
		s << "LeaseSets: " << i2p::data::netdb.GetNumLeaseSets () << "<BR>";

		s << "<P>Tunnels</P>";
		for (auto it: i2p::tunnel::tunnels.GetOutboundTunnels ())
		{
			it->GetTunnelConfig ()->Print (s);
			if (it->GetTunnelPool () && !it->GetTunnelPool ()->IsExploratory ())
				s << " " << "Pool";
			if (it->IsFailed ())
				s << " " << "Failed";
			s << " " << (int)it->GetNumSentBytes () << "<BR>";
		}

		for (auto it: i2p::tunnel::tunnels.GetInboundTunnels ())
		{
			it.second->GetTunnelConfig ()->Print (s);
			if (it.second->GetTunnelPool () && !it.second->GetTunnelPool ()->IsExploratory ())
				s << " " << "Pool";
			if (it.second->IsFailed ())
				s << " " << "Failed";
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
		s << "NTCP<BR>";
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
				s << " [" << it.second->GetNumSentBytes () << ":" << it.second->GetNumReceivedBytes () << "]";
				s << "<BR>";
			}
		}
		auto ssuServer = i2p::transports.GetSSUServer ();
		if (ssuServer)
		{
			s << "<BR>SSU<BR>";
			for (auto it: ssuServer->GetSessions ())
			{
				// incoming connections don't have remote router
				bool outgoing = it.second->GetRemoteRouter ();
				auto endpoint = it.second->GetRemoteEndpoint ();
				if (outgoing) s << "-->";
				s << endpoint.address ().to_string () << ":" << endpoint.port ();
				if (!outgoing) s << "-->";
				s << " [" << it.second->GetNumSentBytes () << ":" << it.second->GetNumReceivedBytes () << "]";
				s << "<BR>";
			}
		}
		s << "<p><a href=\"zmw2cyw2vj7f6obx3msmdvdepdhnw2ctc4okza2zjxlukkdfckhq\">Flibusta</a></p>";
	}
	void HTTPConnection::HandleDestinationRequest (const std::string& address, const std::string& uri)
  {
    HandleDestinationRequest(address, "GET", "", uri);
  }

	void HTTPConnection::HandleDestinationRequest (const std::string& address, const std::string& method, const std::string& data, const std::string& uri)
	{
		const i2p::data::LeaseSet * leaseSet = nullptr;
		i2p::data::IdentHash destination;
		std::string fullAddress;
		if (address.find(".b32.i2p") != std::string::npos)
		{
			if (i2p::data::Base32ToByteStream(address.c_str(), address.length() - strlen(".b32.i2p"), (uint8_t *)destination, 32) != 32)
			{
				LogPrint ("Invalid Base32 address ", address);
				SendReply ("<html>" + itoopieImage + "<br>Invalid Base32 address", 400);
				return;
			}
			fullAddress = address;
		}
		else
		{
			if (address.find(".i2p") != std::string::npos)
			{
				auto addr = i2p::data::netdb.FindAddress(address);
				if (!addr)
				{
					LogPrint ("Unknown address ", address);
					SendReply ("<html>" + itoopieImage + "<br>Unknown address " + address + "</html>", 105);
					return;
				}
				destination = *addr;
				fullAddress = address;
			}
			else
			{
				if (address == "local")
				{
					// TODO: remove later
					fullAddress = "local.i2p";
					auto destination = i2p::stream::GetSharedLocalDestination ();
					leaseSet = destination->GetLeaseSet ();
					EepAccept (destination);
				}
				else
				{	
					if (i2p::data::Base32ToByteStream(address.c_str(), address.length(), (uint8_t *)destination, 32) != 32)
					{
						LogPrint("Invalid Base32 address ", address);
						SendReply("<html>" + itoopieImage + "<br>Invalid Base32 address", 400);
						return;
					}
					fullAddress = address + ".b32.i2p";
				}	
			}
		}

		if (!leaseSet)
			leaseSet = i2p::data::netdb.FindLeaseSet (destination);
		if (!leaseSet || !leaseSet->HasNonExpiredLeases ())
		{
			i2p::data::netdb.Subscribe(destination);
			std::this_thread::sleep_for (std::chrono::seconds(10)); // wait for 10 seconds
			leaseSet = i2p::data::netdb.FindLeaseSet (destination);
			if (!leaseSet || !leaseSet->HasNonExpiredLeases ()) // still no LeaseSet
			{
				SendReply (leaseSet ? "<html>" + itoopieImage + "<br>Leases expired</html>" : "<html>" + itoopieImage + "LeaseSet not found</html>", 504);
				return;
			}
		}
		if (!m_Stream)
			m_Stream = i2p::stream::CreateStream (*leaseSet);
		if (m_Stream)
		{
			std::string request = method+" " + uri + " HTTP/1.1\n Host:" + fullAddress + "\r\n";
      if (!strcmp(method.c_str(), "GET"))
      {
        // POST/PUT, apply body
        request += "\r\n"+ data;
      }
      LogPrint("HTTP Client Request: ", request);
			m_Stream->Send ((uint8_t *)request.c_str (), request.length (), 10);
			AsyncStreamReceive ();
		}
	}

	void HTTPConnection::AsyncStreamReceive ()
	{
		if (m_Stream)
			m_Stream->AsyncReceive (boost::asio::buffer (m_StreamBuffer, 8192),
				boost::bind (&HTTPConnection::HandleStreamReceive, this,
					boost::asio::placeholders::error, boost::asio::placeholders::bytes_transferred),
				45); // 45 seconds timeout
	}

	void HTTPConnection::HandleStreamReceive (const boost::system::error_code& ecode, std::size_t bytes_transferred)
	{
		if (bytes_transferred)
		{
			boost::asio::async_write (*m_Socket, boost::asio::buffer (m_StreamBuffer, bytes_transferred),
        		boost::bind (&HTTPConnection::HandleWrite, this, boost::asio::placeholders::error));
		}
		else
		{
			if (ecode == boost::asio::error::timed_out)
				SendReply ("<html>" + itoopieImage + "<br>Not responding</html>", 504);
			else 
				Terminate ();
		}
	}

	void HTTPConnection::SendReply (const std::string& content, int status)
	{
		m_Reply.content = content;
		m_Reply.headers.resize(2);
		m_Reply.headers[0].name = "Content-Length";
		m_Reply.headers[0].value = boost::lexical_cast<std::string>(m_Reply.content.size());
		m_Reply.headers[1].name = "Content-Type";
		m_Reply.headers[1].value = "text/html";

		boost::asio::async_write (*m_Socket, m_Reply.to_buffers(status),
			boost::bind (&HTTPConnection::HandleWriteReply, this,
				boost::asio::placeholders::error));
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
			CreateConnection(m_NewSocket); // new HTTPConnection(m_NewSocket);
			Accept ();
		}
	}

	void HTTPServer::CreateConnection(boost::asio::ip::tcp::socket * m_NewSocket)
	{
		new HTTPConnection (m_NewSocket);
	}

// eepSite. TODO: move away
		
	void HTTPConnection::EepAccept (i2p::stream::StreamingDestination * destination)
	{
		if (destination)
			destination->SetAcceptor (std::bind (&HTTPConnection::HandleEepAccept, this, std::placeholders::_1));
	}
		
	void HTTPConnection::HandleEepAccept (i2p::stream::Stream * stream)
	{
		if (stream)
		{	
			auto conn = new EepSiteDummyConnection (stream);
			conn->AsyncStreamReceive ();
		}	
	}	

	void EepSiteDummyConnection::AsyncStreamReceive ()
	{
		if (m_Stream)
			m_Stream->AsyncReceive (boost::asio::buffer (m_StreamBuffer, 8192),
				boost::bind (&EepSiteDummyConnection::HandleStreamReceive, this,
					boost::asio::placeholders::error, boost::asio::placeholders::bytes_transferred),
				60); // 60 seconds timeout
	}	
		
	void EepSiteDummyConnection::HandleStreamReceive (const boost::system::error_code& ecode, std::size_t bytes_transferred)
	{
		if (ecode)
		{	
			LogPrint ("eepSite error: ", ecode.message ());
			DeleteStream (m_Stream);
		}	
		else
		{
			std::string content ("");
			content += "<html>" + HTTPConnection::itoopieImage + "</html>";
			std::string response ("HTTP/1.0 200 OK\r\n");
			response += "Content-Length: " + boost::lexical_cast<std::string>(content.length()) + "\r\n";
			response +=	"Content-Type: text/html\r\n\r\n";
			response += content;			
			m_Stream->Send ((uint8_t *)response.c_str (), response.length (), 30);
			m_Stream->Close ();
		}	
		delete this;
	}	
		
}
}

