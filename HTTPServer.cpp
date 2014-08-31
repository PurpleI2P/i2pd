#include <boost/bind.hpp>
#include <boost/lexical_cast.hpp>
#include "base64.h"
#include "Log.h"
#include "Tunnel.h"
#include "TransitTunnel.h"
#include "Transports.h"
#include "NetDb.h"
#include "HTTPServer.h"
#include "I2PEndian.h"

// For image and info
#include "version.h"

namespace i2p
{
namespace util
{

	const std::string HTTPConnection::itoopieImage = ICTOOPIE_128;

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
		// Html5 head start
		s << "<!DOCTYPE html>\n<html lang=\"en\">"; // TODO: Add support for locale.
		s << "<head><meta charset=\"utf-8\" />"; // TODO: Find something to parse html/template system. This is horrible.
		s << "<link rel='shortcut icon' href='";
		s << ICTOOPIE_64_FAVICON;
		s << "' /><title>Purple I2Pd Webconsole</title></head>";
		// Head end
		FillContent (s);
		s << "</html>";
		SendReply (s.str ());
	}

	void HTTPConnection::FillContent (std::stringstream& s)
	{
		s << "<h2>Welcome to the Webconsole!</h2><br><br>";
		s << "<b>Data path:</b> " << i2p::util::filesystem::GetDataDir().string() << "<br>" << "<br>";
		s << "<b>Our external address:</b>" << "<br>";
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
			s << address.host.to_string() << ":" << address.port << "<br>";
		}
		s << "<br><b>Routers:</b> <i>" << i2p::data::netdb.GetNumRouters () << "</i> ";
		s << "<b>Floodfills:</b> <i>" << i2p::data::netdb.GetNumFloodfills () << "</i> ";
		s << "<b>LeaseSets:</b> <i>" << i2p::data::netdb.GetNumLeaseSets () << "</i><br>";

		s << "<br><b>Tunnels</b><br>";
		for (auto it: i2p::tunnel::tunnels.GetOutboundTunnels ())
		{
			it->GetTunnelConfig ()->Print (s);
			if (it->GetTunnelPool () && !it->GetTunnelPool ()->IsExploratory ())
				s << " " << "Pool";
			auto state = it->GetState ();
			if (state == i2p::tunnel::eTunnelStateFailed)
				s << " " << "Failed";
			else if (state == i2p::tunnel::eTunnelStateExpiring)
				s << " " << "Exp";
			s << " " << (int)it->GetNumSentBytes () << "<br>";
		}

		for (auto it: i2p::tunnel::tunnels.GetInboundTunnels ())
		{
			it.second->GetTunnelConfig ()->Print (s);
			if (it.second->GetTunnelPool () && !it.second->GetTunnelPool ()->IsExploratory ())
				s << " " << "Pool";
			auto state = it.second->GetState ();
			if (state == i2p::tunnel::eTunnelStateFailed)
				s << " " << "Failed";
			else if (state == i2p::tunnel::eTunnelStateExpiring)
				s << " " << "Exp";
			s << " " << (int)it.second->GetNumReceivedBytes () << "<br>";
		}

		s << "<br><b>Transit tunnels</b><br>";
		for (auto it: i2p::tunnel::tunnels.GetTransitTunnels ())
		{
			if (dynamic_cast<i2p::tunnel::TransitTunnelGateway *>(it.second))
				s << it.second->GetTunnelID () << "-->";
			else if (dynamic_cast<i2p::tunnel::TransitTunnelEndpoint *>(it.second))
				s << "-->" << it.second->GetTunnelID ();
			else
				s << "-->" << it.second->GetTunnelID () << "-->";
			s << " " << it.second->GetNumTransmittedBytes () << "<br>";
		}

		s << "<br><b>Transports</b><br>";
		s << "NTCP<br>";
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
				s << "<br>";
			}
		}
		auto ssuServer = i2p::transports.GetSSUServer ();
		if (ssuServer)
		{
			s << "<br>SSU<br>";
			for (auto it: ssuServer->GetSessions ())
			{
				// incoming connections don't have remote router
				bool outgoing = it.second->GetRemoteRouter ();
				auto endpoint = it.second->GetRemoteEndpoint ();
				if (outgoing) s << "-->";
				s << endpoint.address ().to_string () << ":" << endpoint.port ();
				if (!outgoing) s << "-->";
				s << " [" << it.second->GetNumSentBytes () << ":" << it.second->GetNumReceivedBytes () << "]";
				s << "<br>";
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
      			if (!strcmp(method.c_str(), "GET") && data.size () > 0)
      			{
      					// POST/PUT, apply body
        				request +=  "Content-Length: " ;
        				request += request.size ();
        				request += "\r\n" + data;
      			}
      			LogPrint("HTTP Client Request: ", request);
			m_Stream->Send ((uint8_t *)request.c_str (), request.size (), 10);
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

