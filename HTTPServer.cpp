#include <ctime>
#include <iomanip>
#include <boost/bind.hpp>
#include <boost/date_time/posix_time/posix_time.hpp>
#include "Base.h"
#include "FS.h"
#include "Log.h"
#include "Tunnel.h"
#include "TransitTunnel.h"
#include "Transports.h"
#include "NetDb.h"
#include "I2PEndian.h"
#include "Streaming.h"
#include "Destination.h"
#include "RouterContext.h"
#include "ClientContext.h"
#include "HTTPServer.h"

// For image and info
#include "version.h"

namespace i2p
{
namespace util
{
	const std::string HTTPConnection::itoopieImage = 
		"<img alt=\"ICToopie Icon\" src=\"data:image/png;base64,"
		"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\" />";

	const std::string HTTPConnection::itoopieFavicon =
		"data:image/png;base64,"
		"iVBORw0KGgoAAAANSUhEUgAAABAAAAAQCAYAAAAf8/9hAAAAAXNSR0IArs4c6QAAAARnQU1BAACxjwv"
		"8YQUAAAAJcEhZcwAADsMAAA7DAcdvqGQAAAAYdEVYdFNvZnR3YXJlAFBhaW50Lk5FVCB2My4wOGVynO"
		"EAAAIzSURBVDhPjZNdSFNhGMf3nm3n7OzMs+8JtfJGzdlgoPtoWBrkqc1OsLTMKEY3eZOQbbS6aBVYO"
		"oO8CKSLXEulQtZNahAM9Cq6lS533UUaeDEEKcN/79x7kbQT/eDhfPB7/u/7Poej08JqtXoEQbhoMpmG"
		"ZFn2stf/h8nEZ4aHue1SiWBlhSCV4n41NBifBINBjina8DyfzOUIVlcJtrYINjcJ3rw1oFAg4HnjHaZ"
		"p4/Ppv8zPH0G5XKZNPZibO4lKpYJ8vgOqqv+uKMq/d9Hfz/0sFr3w+/3IZt2YnbWhszOAxUUv0mkCs9"
		"ncyNT6hEL6dYBgY4Ngd5eger+zU7sODHA/mpubzUytj9FofLa0VGv4s9bWCCTJUGSaNvSzXT3stuHDM"
		"rc3xEqF4N2CERciURyyHfgqSZKPqfuxUMyC+OKcL4YHyl28nDFAPdqDZMcQ7tPnSfURUt0jMBgMH1nL"
		"fkRRDPvcLds3otfhbRTwasaE8b6He43VSrT3QW3tBT3iPdbyN3T7Ibsor988H8OxtiaMx2sB1aBbCRW"
		"R1hbQhbqYXh+6QkaJn8DZyzF09x6HeiaOTC6NK9cSsFqkb3aH3cLU+tCAx9l8FoXPBUy9n8LgyCCmS9"
		"MYez0Gm9P2iWna0GOcDp8KY2JhAsnbSQS6Ahh9OgrlklINeM40bWhAkBd4SLIEh8cBURLhOeiBIArVA"
		"U4yTRvJItk5PRehQVFaYfpbt9PBtTmdziaXyyUzjaHT/QZBQuKHAA0UxAAAAABJRU5ErkJggg==";

	const char HTTP_COMMAND_TUNNELS[] = "tunnels";
	const char HTTP_COMMAND_TRANSIT_TUNNELS[] = "transit_tunnels";
	const char HTTP_COMMAND_TRANSPORTS[] = "transports";	
	const char HTTP_COMMAND_START_ACCEPTING_TUNNELS[] = "start_accepting_tunnels";	
	const char HTTP_COMMAND_STOP_ACCEPTING_TUNNELS[] = "stop_accepting_tunnels";	
	const char HTTP_COMMAND_RUN_PEER_TEST[] = "run_peer_test";	
	const char HTTP_COMMAND_LOCAL_DESTINATIONS[] = "local_destinations";
	const char HTTP_COMMAND_LOCAL_DESTINATION[] = "local_destination";
	const char HTTP_PARAM_BASE32_ADDRESS[] = "b32";
	const char HTTP_COMMAND_SAM_SESSIONS[] = "sam_sessions";
	const char HTTP_COMMAND_SAM_SESSION[] = "sam_session";
	const char HTTP_PARAM_SAM_SESSION_ID[] = "id";
	const char HTTP_COMMAND_I2P_TUNNELS[] = "i2p_tunnels";
	const char HTTP_COMMAND_JUMPSERVICES[] = "jumpservices=";
	const char HTTP_PARAM_ADDRESS[] = "address";
	const char HTTP_HEADER_KV_SEP[] = ": ";
	const char HTTP_CRLF[] = "\r\n";
	
	std::string HTTPConnection::reply::to_string(int code)
	{
		std::stringstream ss("");
		if (headers.size () > 0)
		{
			const char *status;
			switch (code)
			{
				case 105: status = "Name Not Resolved"; break;
				case 200: status = "OK"; break;
				case 400: status = "Bad Request"; break;
				case 404: status = "Not Found"; break;
				case 408: status = "Request Timeout"; break;
				case 500: status = "Internal Server Error"; break;
				case 502: status = "Bad Gateway"; break;
				case 503: status = "Not Implemented"; break;
				case 504: status = "Gateway Timeout"; break;
				default: status = "WTF";
			}
			ss << "HTTP/1.1 " << code << "" << status << HTTP_CRLF;
			for (header & h : headers) {
				ss << h.name << HTTP_HEADER_KV_SEP << h.value << HTTP_CRLF;
			}
			ss << HTTP_CRLF; /* end of headers */
		}
		ss << content;
		return ss.str();
	}

	void HTTPConnection::Terminate ()
	{
		if (!m_Stream) return;
		m_Stream->Close ();
		m_Stream = nullptr;
		m_Socket->close ();
	}

	void HTTPConnection::Receive ()
	{
		m_Socket->async_read_some (boost::asio::buffer (m_Buffer, HTTP_CONNECTION_BUFFER_SIZE),
			 std::bind(&HTTPConnection::HandleReceive, shared_from_this (),
				 std::placeholders::_1, std::placeholders::_2));
	}

	void HTTPConnection::HandleReceive (const boost::system::error_code& ecode, std::size_t bytes_transferred)
	{
		if (!ecode)
  		{
			if (!m_Stream) // new request
			{
				m_Buffer[bytes_transferred] = 0;
				m_BufferLen = bytes_transferred;
				RunRequest();
			}
			else // follow-on
				m_Stream->Send ((uint8_t *)m_Buffer, bytes_transferred);
			Receive ();
		}
		else if (ecode != boost::asio::error::operation_aborted)
			Terminate ();
	}

	void HTTPConnection::RunRequest ()
	{
		auto address = ExtractAddress ();
		if (address.length () > 1 && address[1] != '?') // not just '/' or '/?'
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
			HandleRequest (address);
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

	void HTTPConnection::ExtractParams (const std::string& str, std::map<std::string, std::string>& params)
	{
		if (str[0] != '&') return;
		size_t pos = 1, end;
		do
		{
			end = str.find ('&', pos);
			std::string param = str.substr (pos, end - pos);
			LogPrint (eLogDebug, "HTTPServer: extracted parameters: ", param);
			size_t e = param.find ('=');
			if (e != std::string::npos)
				params[param.substr(0, e)] = param.substr(e+1);
			pos = end + 1;
		}	
		while (end != std::string::npos);
	}
	
	void HTTPConnection::HandleWriteReply (const boost::system::error_code& ecode)
	{
		if (ecode != boost::asio::error::operation_aborted)
		{
			boost::system::error_code ignored_ec;
			m_Socket->shutdown(boost::asio::ip::tcp::socket::shutdown_both, ignored_ec);
			Terminate ();
		}	
	}

	void HTTPConnection::HandleWrite (const boost::system::error_code& ecode)
	{
		if (ecode || (m_Stream && !m_Stream->IsOpen ()))
		{
			if (ecode != boost::asio::error::operation_aborted)
				Terminate ();
		}	
		else // data keeps coming
			AsyncStreamReceive ();
	}

	void HTTPConnection::HandleRequest (const std::string& address)
	{
		std::stringstream s;
		// Html5 head start
		s << "<!DOCTYPE html>\r\n<html lang=\"en\">"; // TODO: Add support for locale.
		s << "<head>\r\n<meta charset=\"utf-8\">\r\n"; // TODO: Find something to parse html/template system. This is horrible.
		s << "<link rel='shortcut icon' href='" + itoopieFavicon + "'>\r\n";
		s << "<title>Purple I2P " << VERSION " Webconsole</title>\r\n";
		s << "<style>\r\n";
		s << "body {font: 100%/1.5em sans-serif; margin: 0; padding: 1.5em; background: #FAFAFA; color: #103456;}";
		s << "a {text-decoration: none; color: #894C84;}";
		s << "a:hover {color: #FAFAFA; background: #894C84;}";
		s << ".header {font-size: 2.5em; text-align: center; margin: 1.5em 0; color: #894C84;}";
		s << ".wrapper {margin: 0 auto; padding: 1em; max-width: 60em;}";
		s << ".left {float: left; position: absolute;}";
		s << ".right {font-size: 1em; margin-left: 13em; float: left; max-width: 46em; overflow: auto;}";
		s << ".established_tunnel {color: #56b734;}";
		s << ".expiring_tunnel {color: #d3ae3f;}";
		s << ".failed_tunnel {color: #d33f3f;}";
		s << ".another_tunnel {color: #434343;}";
		s << "caption {font-size: 1.5em; text-align: center; color: #894C84;}";
		s << "table {width: 100%; border-collapse: collapse; text-align: center;}";
		s << "</style>\r\n</head>\r\n<body>\r\n";
		s << "<div class=header><b>i2pd </b>webconsole</div>";
		s << "<div class=wrapper>";
		s << "<div class=left>\r\n";
		s << "<a href=/>Main page</a><br>\r\n<br>\r\n";
		s << "<a href=/?" << HTTP_COMMAND_LOCAL_DESTINATIONS << ">Local destinations</a><br>\r\n";
		s << "<a href=/?" << HTTP_COMMAND_TUNNELS << ">Tunnels</a><br>\r\n";
		s << "<a href=/?" << HTTP_COMMAND_TRANSIT_TUNNELS << ">Transit tunnels</a><br>\r\n";
		s << "<a href=/?" << HTTP_COMMAND_TRANSPORTS << ">Transports</a><br>\r\n<br>\r\n";
		s << "<a href=/?" << HTTP_COMMAND_I2P_TUNNELS << ">I2P tunnels</a><br>\r\n";
		if (i2p::client::context.GetSAMBridge ())
			s << "<a href=/?" << HTTP_COMMAND_SAM_SESSIONS << ">SAM sessions</a><br>\r\n<br>\r\n";
		if (i2p::context.AcceptsTunnels ())
			s << "<a href=/?" << HTTP_COMMAND_STOP_ACCEPTING_TUNNELS << ">Stop accepting tunnels</a><br>\r\n<br>\r\n";
		else	
			s << "<a href=/?" << HTTP_COMMAND_START_ACCEPTING_TUNNELS << ">Start accepting tunnels</a><br>\r\n<br>\r\n";
		s << "<a href=/?" << HTTP_COMMAND_RUN_PEER_TEST << ">Run peer test</a><br>\r\n<br>\r\n";
		s << "<a href=/?" << HTTP_COMMAND_JUMPSERVICES << "&address=example.i2p>Jump services</a><br>\r\n<br>\r\n";
		s << "</div><div class=right>";
		if (address.length () > 1)
			HandleCommand (address.substr (2), s);
		else			
			FillContent (s);
		s << "</div></div>\r\n</body>\r\n</html>";
		SendReply (s.str ());
	}

	void HTTPConnection::FillContent (std::stringstream& s)
	{
		s << "<b>Uptime:</b> " << boost::posix_time::to_simple_string (
			boost::posix_time::time_duration (boost::posix_time::seconds (
			i2p::context.GetUptime ()))) << "<br>\r\n";
		s << "<b>Status:</b> ";
		switch (i2p::context.GetStatus ())
		{
			case eRouterStatusOK: s << "OK"; break;
			case eRouterStatusTesting: s << "Testing"; break;
			case eRouterStatusFirewalled: s << "Firewalled"; break; 
			default: s << "Unknown";
		} 
		s << "<br>\r\n";
		s << "<b>Tunnel creation success rate:</b> " << i2p::tunnel::tunnels.GetTunnelCreationSuccessRate () << "%<br>\r\n";
		s << "<b>Received:</b> ";
		s << std::fixed << std::setprecision(2);
		auto numKBytesReceived = (double) i2p::transport::transports.GetTotalReceivedBytes () / 1024;
		if (numKBytesReceived < 1024)
			s << numKBytesReceived << " KiB";
		else if (numKBytesReceived < 1024 * 1024)
			s << numKBytesReceived / 1024 << " MiB";
		else
			s << numKBytesReceived / 1024 / 1024 << " GiB";
		s << " (" << (double) i2p::transport::transports.GetInBandwidth () / 1024 << " KiB/s)<br>\r\n";
		s << "<b>Sent:</b> ";
		auto numKBytesSent = (double) i2p::transport::transports.GetTotalSentBytes () / 1024;
		if (numKBytesSent < 1024)
			s << numKBytesSent << " KiB";
		else if (numKBytesSent < 1024 * 1024)
			s << numKBytesSent / 1024 << " MiB";
		else
			s << numKBytesSent / 1024 / 1024 << " GiB";
		s << " (" << (double) i2p::transport::transports.GetOutBandwidth () / 1024 << " KiB/s)<br>\r\n";
		s << "<b>Data path:</b> " << i2p::fs::GetDataDir() << "<br>\r\n<br>\r\n";
		s << "<b>Our external address:</b>" << "<br>\r\n" ;
		for (auto address : i2p::context.GetRouterInfo().GetAddresses())
		{
			switch (address->transportStyle)
			{
				case i2p::data::RouterInfo::eTransportNTCP:
					if (address->host.is_v6 ())
						s << "NTCP6&nbsp;&nbsp;";
					else
						s << "NTCP&nbsp;&nbsp;";
				break;
				case i2p::data::RouterInfo::eTransportSSU:
					if (address->host.is_v6 ())
						s << "SSU6&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;";
					else
						s << "SSU&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;";
				break;
				default:
					s << "Unknown&nbsp;&nbsp;";
			}
			s << address->host.to_string() << ":" << address->port << "<br>\r\n";
		}
		s << "<br>\r\n<b>Routers:</b> " << i2p::data::netdb.GetNumRouters () << " ";
		s << "<b>Floodfills:</b> " << i2p::data::netdb.GetNumFloodfills () << " ";
		s << "<b>LeaseSets:</b> " << i2p::data::netdb.GetNumLeaseSets () << "<br>\r\n";

		size_t clientTunnelCount = i2p::tunnel::tunnels.CountOutboundTunnels();
		clientTunnelCount += i2p::tunnel::tunnels.CountInboundTunnels();
		size_t transitTunnelCount = i2p::tunnel::tunnels.CountTransitTunnels();
		
		s << "<b>Client Tunnels:</b> " << std::to_string(clientTunnelCount) << " ";
		s << "<b>Transit Tunnels:</b> " << std::to_string(transitTunnelCount) << "<br>\r\n";
	}

	void HTTPConnection::HandleCommand (const std::string& command, std::stringstream& s)
	{
		size_t paramsPos = command.find('&');
		std::string cmd = command.substr (0, paramsPos);
		if (cmd == HTTP_COMMAND_TRANSPORTS)
			ShowTransports (s);
		else if (cmd == HTTP_COMMAND_TUNNELS)
			ShowTunnels (s);
		else if (cmd == HTTP_COMMAND_JUMPSERVICES)
        {
			std::map<std::string, std::string> params;
			ExtractParams (command.substr (paramsPos), params);
			auto address = params[HTTP_PARAM_ADDRESS];
			ShowJumpServices (address, s);
		} else if (cmd == HTTP_COMMAND_TRANSIT_TUNNELS)
			ShowTransitTunnels (s);
		else if (cmd == HTTP_COMMAND_START_ACCEPTING_TUNNELS)
			StartAcceptingTunnels (s);
		else if (cmd == HTTP_COMMAND_STOP_ACCEPTING_TUNNELS)
			StopAcceptingTunnels (s);
		else if (cmd == HTTP_COMMAND_RUN_PEER_TEST)
			RunPeerTest (s);
		else if (cmd == HTTP_COMMAND_LOCAL_DESTINATIONS)
			ShowLocalDestinations (s);	
		else if (cmd == HTTP_COMMAND_LOCAL_DESTINATION)
		{
			std::map<std::string, std::string> params;
			ExtractParams (command.substr (paramsPos), params);
			auto b32 = params[HTTP_PARAM_BASE32_ADDRESS];
			ShowLocalDestination (b32, s);
		}	
		else if (cmd == HTTP_COMMAND_SAM_SESSIONS)
			ShowSAMSessions (s);
		else if (cmd == HTTP_COMMAND_SAM_SESSION)
		{
			std::map<std::string, std::string> params;
			ExtractParams (command.substr (paramsPos), params);
			auto id = params[HTTP_PARAM_SAM_SESSION_ID];
			ShowSAMSession (id, s);
		}	
		else if (cmd == HTTP_COMMAND_I2P_TUNNELS)
			ShowI2PTunnels (s);
	}	

	void HTTPConnection::ShowJumpServices (const std::string& address, std::stringstream& s)
	{
		s << "<form type=\"get\" action=\"/\">";
		s << "<input type=\"hidden\" name=\"jumpservices\">";
		s << "<input type=\"text\" value=\"" << address << "\" name=\"address\"> </form><br>\r\n";
		s << "<b>Jump services for " << address << "</b>";
		s << "<ul><li><a href=\"http://joajgazyztfssty4w2on5oaqksz6tqoxbduy553y34mf4byv6gpq.b32.i2p/search/?q=" << address << "\">inr.i2p jump service</a> <br>\r\n";
		s << "<li><a href=\"http://7tbay5p4kzeekxvyvbf6v7eauazemsnnl2aoyqhg5jzpr5eke7tq.b32.i2p/cgi-bin/jump.cgi?a=" << address << "\">stats.i2p jump service</a></ul>";
    }

	void HTTPConnection::ShowLocalDestinations (std::stringstream& s)
	{
		s << "<b>Local Destinations:</b><br>\r\n<br>\r\n";
		for (auto& it: i2p::client::context.GetDestinations ())
		{
			auto ident = it.second->GetIdentHash ();; 
			s << "<a href=/?" << HTTP_COMMAND_LOCAL_DESTINATION;
			s << "&" << HTTP_PARAM_BASE32_ADDRESS << "=" << ident.ToBase32 () << ">"; 
			s << i2p::client::context.GetAddressBook ().ToAddress(ident) << "</a><br>\r\n" << std::endl;
		}
	}

	void  HTTPConnection::ShowLocalDestination (const std::string& b32, std::stringstream& s)
	{
		s << "<b>Local Destination:</b><br>\r\n<br>\r\n";
		i2p::data::IdentHash ident;
		ident.FromBase32 (b32);
		auto dest = i2p::client::context.FindLocalDestination (ident);
		if (dest)
		{
			s << "<b>Base64:</b><br>\r\n<textarea readonly=\"readonly\" cols=\"64\" rows=\"11\" wrap=\"on\">";
			s << dest->GetIdentity ()->ToBase64 () << "</textarea><br>\r\n<br>\r\n";
			s << "<b>LeaseSets:</b> <i>" << dest->GetNumRemoteLeaseSets () << "</i><br>\r\n";
			auto pool = dest->GetTunnelPool ();
			if (pool)
			{
				s << "<b>Tunnels:</b><br>\r\n";
				for (auto it: pool->GetOutboundTunnels ())
				{
					it->Print (s);
					auto state = it->GetState ();
					if (state == i2p::tunnel::eTunnelStateFailed)
						s << " " << "Failed";
					else if (state == i2p::tunnel::eTunnelStateExpiring)
						s << " " << "Exp";
					s << "<br>\r\n" << std::endl;
				}
				for (auto it: pool->GetInboundTunnels ())
				{
					it->Print (s);
					auto state = it->GetState ();
					if (state == i2p::tunnel::eTunnelStateFailed)
						s << " " << "Failed";
					else if (state == i2p::tunnel::eTunnelStateExpiring)
						s << " " << "Exp";
					s << "<br>\r\n" << std::endl;
				}
			}	
			s << "<b>Tags</b><br>Incoming: " << dest->GetNumIncomingTags () << "<br>Outgoing:<br>" << std::endl;
			for (auto it: dest->GetSessions ())
			{
				s << i2p::client::context.GetAddressBook ().ToAddress(it.first) << " ";
				s << it.second->GetNumOutgoingTags () << "<br>" << std::endl;
			}	
			s << "<br>" << std::endl;
			// s << "<br>\r\n<b>Streams:</b><br>\r\n";
			// for (auto it: dest->GetStreamingDestination ()->GetStreams ())
			// {	
				// s << it.first << "->" << i2p::client::context.GetAddressBook ().ToAddress(it.second->GetRemoteIdentity ()) << " ";
				// s << " [" << it.second->GetNumSentBytes () << ":" << it.second->GetNumReceivedBytes () << "]";
				// s << " [out:" << it.second->GetSendQueueSize () << "][in:" << it.second->GetReceiveQueueSize () << "]";
				// s << "[buf:" << it.second->GetSendBufferSize () << "]";
				// s << "[RTT:" << it.second->GetRTT () << "]";
				// s << "[Window:" << it.second->GetWindowSize () << "]";
				// s << "[Status:" << (int)it.second->GetStatus () << "]"; 
				// s << "<br>\r\n"<< std::endl; 
			// }	
			s << "<br>\r\n<table><caption>Streams</caption><tr>";
			s << "<th>StreamID</th>";
			s << "<th>Destination</th>";
			s << "<th>Sent</th>";
			s << "<th>Received</th>";
			s << "<th>Out</th>";
			s << "<th>In</th>";
			s << "<th>Buf</th>";
			s << "<th>RTT</th>";
			s << "<th>Window</th>";
			s << "<th>Status</th>";
			s << "</tr>";

			for (auto it: dest->GetAllStreams ())
			{	
				s << "<tr>";
				s << "<td>" << it->GetSendStreamID () << "</td>";
				s << "<td>" << i2p::client::context.GetAddressBook ().ToAddress(it->GetRemoteIdentity ()) << "</td>";
				s << "<td>" << it->GetNumSentBytes () << "</td>";
				s << "<td>" << it->GetNumReceivedBytes () << "</td>";
				s << "<td>" << it->GetSendQueueSize () << "</td>";
				s << "<td>" << it->GetReceiveQueueSize () << "</td>";
				s << "<td>" << it->GetSendBufferSize () << "</td>";
				s << "<td>" << it->GetRTT () << "</td>";
				s << "<td>" << it->GetWindowSize () << "</td>";
				s << "<td>" << (int)it->GetStatus () << "</td>";
				s << "</tr><br>\r\n" << std::endl; 
			}
		}	
	}

	void HTTPConnection::ShowTunnels (std::stringstream& s)
	{
		s << "<b>Tunnels:</b><br>\r\n<br>\r\n";
		s << "<b>Queue size:</b> " << i2p::tunnel::tunnels.GetQueueSize () << "<br>\r\n";
		for (auto it: i2p::tunnel::tunnels.GetOutboundTunnels ())
		{
			it->Print (s);
			auto state = it->GetState ();
			if (state == i2p::tunnel::eTunnelStateFailed)
				s << "<span class=failed_tunnel> " << "Failed</span>";
			else if (state == i2p::tunnel::eTunnelStateExpiring)
				s << "<span class=expiring_tunnel> " << "Exp</span>";
			s << " " << (int)it->GetNumSentBytes () << "<br>\r\n";
			s << std::endl;
		}

		for (auto it: i2p::tunnel::tunnels.GetInboundTunnels ())
		{
			it->Print (s);
			auto state = it->GetState ();
			if (state == i2p::tunnel::eTunnelStateFailed)
				s << "<span class=failed_tunnel> " << "Failed</span>";
			else if (state == i2p::tunnel::eTunnelStateExpiring)
				s << "<span class=expiring_tunnel> " << "Exp</span>";
			s << " " << (int)it->GetNumReceivedBytes () << "<br>\r\n";
			s << std::endl;
		}
	}	

	void HTTPConnection::ShowTransitTunnels (std::stringstream& s)
	{
		s << "<b>Transit tunnels:</b><br>\r\n<br>\r\n";
		for (auto it: i2p::tunnel::tunnels.GetTransitTunnels ())
		{
			if (std::dynamic_pointer_cast<i2p::tunnel::TransitTunnelGateway>(it))
				s << it->GetTunnelID () << " ⇒ ";
			else if (std::dynamic_pointer_cast<i2p::tunnel::TransitTunnelEndpoint>(it))
				s << " ⇒ " << it->GetTunnelID ();
			else
				s << " ⇒ " << it->GetTunnelID () << " ⇒ ";
			s << " " << it->GetNumTransmittedBytes () << "<br>\r\n";
		}
	}

	void HTTPConnection::ShowTransports (std::stringstream& s)
	{
		s << "<b>Transports:</b><br>\r\n<br>\r\n";
		auto ntcpServer = i2p::transport::transports.GetNTCPServer (); 
		if (ntcpServer)
		{	
			s << "<b>NTCP</b><br>\r\n";
			for (auto it: ntcpServer->GetNTCPSessions ())
			{
				if (it.second && it.second->IsEstablished ())
				{
					// incoming connection doesn't have remote RI
					if (it.second->IsOutgoing ()) s << " ⇒ ";
					s << i2p::data::GetIdentHashAbbreviation (it.second->GetRemoteIdentity ()->GetIdentHash ()) <<  ": "
						<< it.second->GetSocket ().remote_endpoint().address ().to_string ();
					if (!it.second->IsOutgoing ()) s << " ⇒ ";
					s << " [" << it.second->GetNumSentBytes () << ":" << it.second->GetNumReceivedBytes () << "]";
					s << "<br>\r\n" << std::endl;
				}
			}
		}	
		auto ssuServer = i2p::transport::transports.GetSSUServer ();
		if (ssuServer)
		{
			s << "<br>\r\n<b>SSU</b><br>\r\n";
			for (auto it: ssuServer->GetSessions ())
			{
				auto endpoint = it.second->GetRemoteEndpoint ();
				if (it.second->IsOutgoing ()) s << " ⇒ ";
				s << endpoint.address ().to_string () << ":" << endpoint.port ();
				if (!it.second->IsOutgoing ()) s << " ⇒ ";
				s << " [" << it.second->GetNumSentBytes () << ":" << it.second->GetNumReceivedBytes () << "]";
				if (it.second->GetRelayTag ())
					s << " [itag:" << it.second->GetRelayTag () << "]";
				s << "<br>\r\n" << std::endl;
			}
			s << "<br>\r\n<b>SSU6</b><br>\r\n";
			for (auto it: ssuServer->GetSessionsV6 ())
			{
				auto endpoint = it.second->GetRemoteEndpoint ();
				if (it.second->IsOutgoing ()) s << " ⇒ ";
				s << endpoint.address ().to_string () << ":" << endpoint.port ();
				if (!it.second->IsOutgoing ()) s << " ⇒ ";
				s << " [" << it.second->GetNumSentBytes () << ":" << it.second->GetNumReceivedBytes () << "]";
				s << "<br>\r\n" << std::endl;
			}
		}
	}
	
	void HTTPConnection::ShowSAMSessions (std::stringstream& s)
	{
		s << "<b>SAM Sessions:</b><br>\r\n<br>\r\n";
		auto sam = i2p::client::context.GetSAMBridge ();
		if (sam)
		{	
			for (auto& it: sam->GetSessions ())
			{
				s << "<a href=/?" << HTTP_COMMAND_SAM_SESSION;
				s << "&" << HTTP_PARAM_SAM_SESSION_ID << "=" << it.first << ">";
				s << it.first << "</a><br>\r\n" << std::endl;
			}	
		}	
	}	

	void HTTPConnection::ShowSAMSession (const std::string& id, std::stringstream& s)
	{
		s << "<b>SAM Session:</b><br>\r\n<br>\r\n";
		auto sam = i2p::client::context.GetSAMBridge ();
		if (sam)
		{
			auto session = sam->FindSession (id);
			if (session)
			{
				auto& ident = session->localDestination->GetIdentHash();
				s << "<a href=/?" << HTTP_COMMAND_LOCAL_DESTINATION;
				s << "&" << HTTP_PARAM_BASE32_ADDRESS << "=" << ident.ToBase32 () << ">"; 
				s << i2p::client::context.GetAddressBook ().ToAddress(ident) << "</a><br>\r\n" << std::endl;
				s << "<b>Streams:</b><br>\r\n";
				for (auto it: session->ListSockets())
				{
					switch (it->GetSocketType ())
					{
						case i2p::client::eSAMSocketTypeSession:
							s << "session";
						break;	
						case i2p::client::eSAMSocketTypeStream:
							s << "stream";
						break;	
						case i2p::client::eSAMSocketTypeAcceptor:
							s << "acceptor";
						break;
						default:
							s << "unknown";
					}
					s << " [" << it->GetSocket ().remote_endpoint() << "]";
					s << "<br>\r\n" << std::endl;
				}	
			}
		}	
	}	

	void HTTPConnection::ShowI2PTunnels (std::stringstream& s)
	{
		s << "<b>Client Tunnels:</b><br>\r\n<br>\r\n";
		for (auto& it: i2p::client::context.GetClientTunnels ())
		{
			auto& ident = it.second->GetLocalDestination ()->GetIdentHash();
			s << "<a href=/?" << HTTP_COMMAND_LOCAL_DESTINATION;
			s << "&" << HTTP_PARAM_BASE32_ADDRESS << "=" << ident.ToBase32 () << ">"; 
			s << it.second->GetName () << "</a> ⇐ ";			
			s << i2p::client::context.GetAddressBook ().ToAddress(ident);
			s << "<br>\r\n"<< std::endl;
		}	
		s << "<br>\r\n<b>Server Tunnels:</b><br>\r\n<br>\r\n";
		for (auto& it: i2p::client::context.GetServerTunnels ())
		{
			auto& ident = it.second->GetLocalDestination ()->GetIdentHash();
			s << "<a href=/?" << HTTP_COMMAND_LOCAL_DESTINATION;
			s << "&" << HTTP_PARAM_BASE32_ADDRESS << "=" << ident.ToBase32 () << ">"; 
			s << it.second->GetName () << "</a> ⇒ ";
			s << i2p::client::context.GetAddressBook ().ToAddress(ident);
			s << ":" << it.second->GetLocalPort ();
			s << "</a><br>\r\n"<< std::endl;
		}	
	}	
	
	void HTTPConnection::StopAcceptingTunnels (std::stringstream& s)
	{
		s << "<b>Stop Accepting Tunnels:</b><br>\r\n<br>\r\n";
		i2p::context.SetAcceptsTunnels (false);
		s << "Accepting tunnels stopped" <<  std::endl;
	}

	void HTTPConnection::StartAcceptingTunnels (std::stringstream& s)
	{
		s << "<b>Start Accepting Tunnels:</b><br>\r\n<br>\r\n";
		i2p::context.SetAcceptsTunnels (true);
		s << "Accepting tunnels started" <<  std::endl;		
	}

	void HTTPConnection::RunPeerTest (std::stringstream& s)
	{
		s << "<b>Run Peer Test:</b><br>\r\n<br>\r\n";
		i2p::transport::transports.PeerTest ();
		s << "Peer test is running" <<  std::endl;
	}

	void HTTPConnection::HandleDestinationRequest (const std::string& address, const std::string& uri)
	{
		std::string request = "GET " + uri + " HTTP/1.1\r\nHost:" + address + "\r\n\r\n";
		LogPrint(eLogInfo, "HTTPServer: client request: ", request);
		SendToAddress (address, 80, request.c_str (), request.size ());		
	}

	void HTTPConnection::SendToAddress (const std::string& address, int port, const char * buf, size_t len)
	{	
		i2p::data::IdentHash destination;
		if (!i2p::client::context.GetAddressBook ().GetIdentHash (address, destination))
		{
			LogPrint (eLogWarning, "HTTPServer: Unknown address ", address);
			SendReply ("<html>" + itoopieImage + "<br>\r\nUnknown address " + address + "</html>", 404);
			return;
		}		

		auto leaseSet = i2p::client::context.GetSharedLocalDestination ()->FindLeaseSet (destination);
		if (leaseSet && !leaseSet->IsExpired ())
			SendToDestination (leaseSet, port, buf, len);
		else
		{
			memcpy (m_Buffer, buf, len);
			m_BufferLen = len;
			i2p::client::context.GetSharedLocalDestination ()->RequestDestination (destination);
			m_Timer.expires_from_now (boost::posix_time::seconds(HTTP_DESTINATION_REQUEST_TIMEOUT));
			m_Timer.async_wait (std::bind (&HTTPConnection::HandleDestinationRequestTimeout,
				shared_from_this (), std::placeholders::_1, destination, port, m_Buffer, m_BufferLen));
		}
	}
	
	void HTTPConnection::HandleDestinationRequestTimeout (const boost::system::error_code& ecode, 
		i2p::data::IdentHash destination, int port, const char * buf, size_t len)
	{	
		if (ecode != boost::asio::error::operation_aborted)
		{	
			auto leaseSet = i2p::client::context.GetSharedLocalDestination ()->FindLeaseSet (destination);
			if (leaseSet && !leaseSet->IsExpired ()) {
				SendToDestination (leaseSet, port, buf, len);
			} else if (leaseSet) {
				SendReply ("<html>" + itoopieImage + "<br>\r\nLeaseSet expired</html>", 504);
			} else {
				SendReply ("<html>" + itoopieImage + "<br>\r\nLeaseSet not found</html>", 504);
			}
		}
	}	
	
	void HTTPConnection::SendToDestination (std::shared_ptr<const i2p::data::LeaseSet> remote, int port, const char * buf, size_t len)
	{
		if (!m_Stream)
			m_Stream = i2p::client::context.GetSharedLocalDestination ()->CreateStream (remote, port);
		if (m_Stream)
		{
			m_Stream->Send ((uint8_t *)buf, len);
			AsyncStreamReceive ();
		}
	}

	void HTTPConnection::AsyncStreamReceive ()
	{
		if (m_Stream)
			m_Stream->AsyncReceive (boost::asio::buffer (m_StreamBuffer, 8192),
				std::bind (&HTTPConnection::HandleStreamReceive, shared_from_this (),
					std::placeholders::_1, std::placeholders::_2),
				45); // 45 seconds timeout
	}

	void HTTPConnection::HandleStreamReceive (const boost::system::error_code& ecode, std::size_t bytes_transferred)
	{
		if (!ecode)
		{
			boost::asio::async_write (*m_Socket, boost::asio::buffer (m_StreamBuffer, bytes_transferred),
        		std::bind (&HTTPConnection::HandleWrite, shared_from_this (), std::placeholders::_1));
		}
		else
		{
			if (ecode == boost::asio::error::timed_out)
				SendReply ("<html>" + itoopieImage + "<br>\r\nNot responding</html>", 504);
			else if (ecode != boost::asio::error::operation_aborted)
				Terminate ();
		}
	}

	void HTTPConnection::SendReply (const std::string& content, int status)
	{
		m_Reply.content = content;
		m_Reply.headers.resize(3);
        // we need the date header to be complaint with http 1.1
        std::time_t time_now = std::time(nullptr);
        char time_buff[128];
        if (std::strftime(time_buff, sizeof(time_buff), "%a, %d %b %Y %H:%M:%S GMT", std::gmtime(&time_now))) 
		{
            m_Reply.headers[0].name = "Date";
            m_Reply.headers[0].value = std::string(time_buff);
            m_Reply.headers[1].name = "Content-Length";
            m_Reply.headers[1].value = std::to_string(m_Reply.content.size());
            m_Reply.headers[2].name = "Content-Type";
            m_Reply.headers[2].value = "text/html";
        }
		
		boost::asio::async_write (*m_Socket, m_Reply.to_buffers(status),
			std::bind (&HTTPConnection::HandleWriteReply, shared_from_this (), std::placeholders::_1));
	}

	HTTPServer::HTTPServer (const std::string& address, int port):
		m_Thread (nullptr), m_Work (m_Service),
		m_Acceptor (m_Service, boost::asio::ip::tcp::endpoint (boost::asio::ip::address::from_string(address), port))
	{
	}

	HTTPServer::~HTTPServer ()
	{
		Stop ();
	}

	void HTTPServer::Start ()
	{
		m_Thread = std::unique_ptr<std::thread>(new std::thread (std::bind (&HTTPServer::Run, this)));
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
            m_Thread = nullptr;
        }
	}

	void HTTPServer::Run ()
	{
		m_Service.run ();
	}

	void HTTPServer::Accept ()
	{
		auto newSocket = std::make_shared<boost::asio::ip::tcp::socket> (m_Service);
		m_Acceptor.async_accept (*newSocket, boost::bind (&HTTPServer::HandleAccept, this,
			boost::asio::placeholders::error, newSocket));
	}

	void HTTPServer::HandleAccept(const boost::system::error_code& ecode, 
		std::shared_ptr<boost::asio::ip::tcp::socket> newSocket)
	{
		if (!ecode)
		{
			CreateConnection(newSocket);
			Accept ();
		}
	}

	void HTTPServer::CreateConnection(std::shared_ptr<boost::asio::ip::tcp::socket> newSocket)
	{
		auto conn = std::make_shared<HTTPConnection> (newSocket);
		conn->Receive ();
	}
}
}
