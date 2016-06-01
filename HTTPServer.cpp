#include <iomanip>
#include <sstream>
#include <thread>
#include <memory>

#include <boost/asio.hpp>
#include <boost/bind.hpp>

#include "Base.h"
#include "FS.h"
#include "Log.h"
#include "Config.h"
#include "Tunnel.h"
#include "TransitTunnel.h"
#include "Transports.h"
#include "NetDb.h"
#include "HTTP.h"
#include "LeaseSet.h"
#include "Destination.h"
#include "RouterContext.h"
#include "ClientContext.h"
#include "HTTPServer.h"
#include "Daemon.h"

// For image and info
#include "version.h"

namespace i2p {
namespace http {
	const char *itoopieImage =
		"<img alt=\"ICToopie Icon\" src=\"data:image/png;base64,"
		"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\" />";

	const char *itoopieFavicon =
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

	const char *cssStyles =
		"<style>\r\n"
		"  body { font: 100%/1.5em sans-serif; margin: 0; padding: 1.5em; background: #FAFAFA; color: #103456; }\r\n"
		"  a { text-decoration: none; color: #894C84; }\r\n"
		"  a:hover { color: #FAFAFA; background: #894C84; }\r\n"
		"  .header { font-size: 2.5em; text-align: center; margin: 1.5em 0; color: #894C84; }\r\n"
		"  .wrapper { margin: 0 auto; padding: 1em; max-width: 60em; }\r\n"
		"  .left  { float: left; position: absolute; }\r\n"
		"  .right { float: left; font-size: 1em; margin-left: 13em; max-width: 46em; overflow: auto; }\r\n"
		"  .tunnel.established { color: #56B734; }\r\n"
		"  .tunnel.expiring    { color: #D3AE3F; }\r\n"
		"  .tunnel.failed      { color: #D33F3F; }\r\n"
		"  .tunnel.another     { color: #434343; }\r\n"
		"  caption { font-size: 1.5em; text-align: center; color: #894C84; }\r\n"
		"  table { width: 100%; border-collapse: collapse; text-align: center; }\r\n"
		"</style>\r\n";

	const char HTTP_PAGE_TUNNELS[] = "tunnels";
	const char HTTP_PAGE_TRANSIT_TUNNELS[] = "transit_tunnels";
	const char HTTP_PAGE_TRANSPORTS[] = "transports";	
	const char HTTP_PAGE_LOCAL_DESTINATIONS[] = "local_destinations";
	const char HTTP_PAGE_LOCAL_DESTINATION[] = "local_destination";
	const char HTTP_PAGE_SAM_SESSIONS[] = "sam_sessions";
	const char HTTP_PAGE_SAM_SESSION[] = "sam_session";
	const char HTTP_PAGE_I2P_TUNNELS[] = "i2p_tunnels";
	const char HTTP_PAGE_JUMPSERVICES[] = "jumpservices";
	const char HTTP_PAGE_COMMANDS[] = "commands";
	const char HTTP_COMMAND_START_ACCEPTING_TUNNELS[] = "start_accepting_tunnels";	
	const char HTTP_COMMAND_STOP_ACCEPTING_TUNNELS[] = "stop_accepting_tunnels";	
	const char HTTP_COMMAND_SHUTDOWN_START[] = "shutdown_start";
	const char HTTP_COMMAND_SHUTDOWN_CANCEL[] = "shutdown_cancel";
	const char HTTP_COMMAND_SHUTDOWN_NOW[]   = "terminate";
	const char HTTP_COMMAND_RUN_PEER_TEST[] = "run_peer_test";
	const char HTTP_COMMAND_RELOAD_CONFIG[] = "reload_config";	
	const char HTTP_PARAM_BASE32_ADDRESS[] = "b32";
	const char HTTP_PARAM_SAM_SESSION_ID[] = "id";
	const char HTTP_PARAM_ADDRESS[] = "address";

	std::map<std::string, std::string> jumpservices = {
		{ "inr.i2p",    "http://joajgazyztfssty4w2on5oaqksz6tqoxbduy553y34mf4byv6gpq.b32.i2p/search/?q=" },
		{ "stats.i2p",  "http://7tbay5p4kzeekxvyvbf6v7eauazemsnnl2aoyqhg5jzpr5eke7tq.b32.i2p/cgi-bin/jump.cgi?a=" },
	};

	void ShowUptime (std::stringstream& s, int seconds) {
		int num;

		if ((num = seconds / 86400) > 0) {
			s << num << " days, ";
			seconds -= num * 86400;
		}
		if ((num = seconds / 3600) > 0) {
			s << num << " hours, ";
			seconds -= num * 3600;
		}
		if ((num = seconds / 60) > 0) {
			s << num << " min, ";
			seconds -= num * 60;
		}
		s << seconds << " seconds";
	}

	void ShowTunnelDetails (std::stringstream& s, enum i2p::tunnel::TunnelState eState, int bytes)
	{
		std::string state;
		switch (eState) {
			case i2p::tunnel::eTunnelStateBuildReplyReceived :
			case i2p::tunnel::eTunnelStatePending     : state = "building"; break;
			case i2p::tunnel::eTunnelStateBuildFailed :
			case i2p::tunnel::eTunnelStateTestFailed  :
			case i2p::tunnel::eTunnelStateFailed      : state = "failed";   break;
			case i2p::tunnel::eTunnelStateExpiring    : state = "expiring"; break;
			case i2p::tunnel::eTunnelStateEstablished : state = "established"; break;
			default: state = "unknown"; break;
		}
		s << "<span class=\"tunnel " << state << "\"> " << state << "</span>, ";
		s << " " << (int) (bytes / 1024) << "&nbsp;KiB<br>\r\n";
	}

	void ShowPageHead (std::stringstream& s)
	{
		s <<
			"<!DOCTYPE html>\r\n"
			"<html lang=\"en\">\r\n" /* TODO: Add support for locale */
			"  <head>\r\n"
			"  <meta charset=\"UTF-8\">\r\n" /* TODO: Find something to parse html/template system. This is horrible. */
			"  <link rel='shortcut icon' href='" << itoopieFavicon << "'>\r\n"
			"  <title>Purple I2P " VERSION " Webconsole</title>\r\n"
			<< cssStyles <<
			"</head>\r\n";
		s <<
			"<body>\r\n"
			"<div class=header><b>i2pd</b> webconsole</div>\r\n"
			"<div class=wrapper>\r\n"
			"<div class=left>\r\n"
			"  <a href=/>Main page</a><br>\r\n<br>\r\n"
			"  <a href=/?page=" << HTTP_PAGE_COMMANDS << ">Router commands</a><br>\r\n"
			"  <a href=/?page=" << HTTP_PAGE_LOCAL_DESTINATIONS << ">Local destinations</a><br>\r\n"
			"  <a href=/?page=" << HTTP_PAGE_TUNNELS << ">Tunnels</a><br>\r\n"
			"  <a href=/?page=" << HTTP_PAGE_TRANSIT_TUNNELS << ">Transit tunnels</a><br>\r\n"
			"  <a href=/?page=" << HTTP_PAGE_TRANSPORTS << ">Transports</a><br>\r\n"
			"  <a href=/?page=" << HTTP_PAGE_I2P_TUNNELS << ">I2P tunnels</a><br>\r\n"
			"  <a href=/?page=" << HTTP_PAGE_JUMPSERVICES << ">Jump services</a><br>\r\n"
			"  <a href=/?page=" << HTTP_PAGE_SAM_SESSIONS << ">SAM sessions</a><br>\r\n"
			"</div>\r\n"
			"<div class=right>";
	}

	void ShowPageTail (std::stringstream& s)
	{
		s <<
			"</div></div>\r\n"
			"</body>\r\n"
			"</html>\r\n";
	}

	void ShowError(std::stringstream& s, const std::string& string)
	{
		s << "<b>ERROR:</b>&nbsp;" << string << "<br>\r\n";
	}

	void ShowStatus (std::stringstream& s)
	{
		s << "<b>Uptime:</b> ";
		ShowUptime(s, i2p::context.GetUptime ());
		s << "<br>\r\n";
		s << "<b>Status:</b> ";
		switch (i2p::context.GetStatus ())
		{
			case eRouterStatusOK: s << "OK"; break;
			case eRouterStatusTesting: s << "Testing"; break;
			case eRouterStatusFirewalled: s << "Firewalled"; break; 
			default: s << "Unknown";
		} 
		s << "<br>\r\n";
		auto family = i2p::context.GetFamily ();
		if (family.length () > 0)
			s << "<b>Family:</b> " << family << "<br>\r\n";
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

	void ShowJumpServices (std::stringstream& s, const std::string& address)
	{
		s << "<form type=\"GET\" action=\"/\">";
		s << "<input type=\"hidden\" name=\"page\" value=\"jumpservices\">";
		s << "<input type=\"text\"   name=\"address\" value=\"" << address << "\">";
		s << "<input type=\"submit\" value=\"Update\">";
		s << "</form><br>\r\n";
		s << "<b>Jump services for " << address << "</b>\r\n<ul>\r\n";
		for (auto & js : jumpservices) {
			s << "  <li><a href=\"" << js.second << address << "\">" << js.first << "</a></li>\r\n";
		}
		s << "</ul>\r\n";
	}

	void ShowLocalDestinations (std::stringstream& s)
	{
		s << "<b>Local Destinations:</b><br>\r\n<br>\r\n";
		for (auto& it: i2p::client::context.GetDestinations ())
		{
			auto ident = it.second->GetIdentHash ();; 
			s << "<a href=/?page=" << HTTP_PAGE_LOCAL_DESTINATION << "&b32=" << ident.ToBase32 () << ">"; 
			s << i2p::client::context.GetAddressBook ().ToAddress(ident) << "</a><br>\r\n" << std::endl;
		}
	}

	void  ShowLocalDestination (std::stringstream& s, const std::string& b32)
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
				s << "<b>Inbound tunnels:</b><br>\r\n";
				for (auto & it : pool->GetInboundTunnels ()) {
					it->Print(s);
					ShowTunnelDetails(s, it->GetState (), it->GetNumReceivedBytes ());
				}
				s << "<br>\r\n";
				s << "<b>Outbound tunnels:</b><br>\r\n";
				for (auto & it : pool->GetOutboundTunnels ()) {
					it->Print(s);
					ShowTunnelDetails(s, it->GetState (), it->GetNumSentBytes ());
				}
			}	
			s << "<br>\r\n";
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

	void ShowTunnels (std::stringstream& s)
	{
		s << "<b>Queue size:</b> " << i2p::tunnel::tunnels.GetQueueSize () << "<br>\r\n";

		s << "<b>Inbound tunnels:</b><br>\r\n";
		for (auto & it : i2p::tunnel::tunnels.GetInboundTunnels ()) {
			it->Print(s);
			ShowTunnelDetails(s, it->GetState (), it->GetNumReceivedBytes ());
		}
		s << "<br>\r\n";
		s << "<b>Outbound tunnels:</b><br>\r\n";
		for (auto & it : i2p::tunnel::tunnels.GetOutboundTunnels ()) {
			it->Print(s);
			ShowTunnelDetails(s, it->GetState (), it->GetNumSentBytes ());
		}
		s << "<br>\r\n";
	}	

	void ShowCommands (std::stringstream& s)
	{
		/* commands */
		s << "<b>Router Commands</b><br>\r\n";
		s << "  <a href=/?cmd=" << HTTP_COMMAND_RUN_PEER_TEST << ">Run peer test</a><br>\r\n";
		//s << "  <a href=/?cmd=" << HTTP_COMMAND_RELOAD_CONFIG << ">Reload config</a><br>\r\n";
		if (i2p::context.AcceptsTunnels ())
			s << "  <a href=/?cmd=" << HTTP_COMMAND_STOP_ACCEPTING_TUNNELS << ">Stop accepting tunnels</a><br>\r\n";
		else	
			s << "  <a href=/?cmd=" << HTTP_COMMAND_START_ACCEPTING_TUNNELS << ">Start accepting tunnels</a><br>\r\n";
#ifndef WIN32
		if (Daemon.gracefullShutdownInterval) {
			s << "  <a href=/?cmd=" << HTTP_COMMAND_SHUTDOWN_CANCEL << ">Cancel gracefull shutdown (";
			s << Daemon.gracefullShutdownInterval;
			s << " seconds remains)</a><br>\r\n";
		} else {
			s << "  <a href=/?cmd=" << HTTP_COMMAND_SHUTDOWN_START << ">Start gracefull shutdown</a><br>\r\n";
		}
		s << "  <a href=/?cmd=" << HTTP_COMMAND_SHUTDOWN_NOW << ">Force shutdown</a><br>\r\n";
#endif
	}

	void ShowTransitTunnels (std::stringstream& s)
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

	void ShowTransports (std::stringstream& s)
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
	
	void ShowSAMSessions (std::stringstream& s)
	{
		auto sam = i2p::client::context.GetSAMBridge ();
		if (!sam) {
			ShowError(s, "SAM disabled");
			return;
		}
		s << "<b>SAM Sessions:</b><br>\r\n<br>\r\n";
		for (auto& it: sam->GetSessions ())
		{
			s << "<a href=/?page=" << HTTP_PAGE_SAM_SESSION << "&sam_id=" << it.first << ">";
			s << it.first << "</a><br>\r\n" << std::endl;
		}	
	}	

	void ShowSAMSession (std::stringstream& s, const std::string& id)
	{
		s << "<b>SAM Session:</b><br>\r\n<br>\r\n";
		auto sam = i2p::client::context.GetSAMBridge ();
		if (!sam) {
			ShowError(s, "SAM disabled");
			return;
		}
		auto session = sam->FindSession (id);
		if (!session) {
			ShowError(s, "SAM session not found");
			return;
		}
		auto& ident = session->localDestination->GetIdentHash();
		s << "<a href=/?page=" << HTTP_PAGE_LOCAL_DESTINATION << "&b32=" << ident.ToBase32 () << ">";
		s << i2p::client::context.GetAddressBook ().ToAddress(ident) << "</a><br>\r\n";
		s << "<br>\r\n";
		s << "<b>Streams:</b><br>\r\n";
		for (auto it: session->ListSockets())
		{
			switch (it->GetSocketType ())
			{
				case i2p::client::eSAMSocketTypeSession  : s << "session";  break;
				case i2p::client::eSAMSocketTypeStream   : s << "stream";   break;
				case i2p::client::eSAMSocketTypeAcceptor : s << "acceptor"; break;
				default: s << "unknown"; break;
			}
			s << " [" << it->GetSocket ().remote_endpoint() << "]";
			s << "<br>\r\n";
		}	
	}	

	void ShowI2PTunnels (std::stringstream& s)
	{
		s << "<b>Client Tunnels:</b><br>\r\n<br>\r\n";
		for (auto& it: i2p::client::context.GetClientTunnels ())
		{
			auto& ident = it.second->GetLocalDestination ()->GetIdentHash();
			s << "<a href=/?page=" << HTTP_PAGE_LOCAL_DESTINATION << "&b32=" << ident.ToBase32 () << ">"; 
			s << it.second->GetName () << "</a> ⇐ ";			
			s << i2p::client::context.GetAddressBook ().ToAddress(ident);
			s << "<br>\r\n"<< std::endl;
		}	
		s << "<br>\r\n<b>Server Tunnels:</b><br>\r\n<br>\r\n";
		for (auto& it: i2p::client::context.GetServerTunnels ())
		{
			auto& ident = it.second->GetLocalDestination ()->GetIdentHash();
			s << "<a href=/?page=" << HTTP_PAGE_LOCAL_DESTINATION << "&b32=" << ident.ToBase32 () << ">"; 
			s << it.second->GetName () << "</a> ⇒ ";
			s << i2p::client::context.GetAddressBook ().ToAddress(ident);
			s << ":" << it.second->GetLocalPort ();
			s << "</a><br>\r\n"<< std::endl;
		}	
	}	

	HTTPConnection::HTTPConnection (std::shared_ptr<boost::asio::ip::tcp::socket> socket):
				m_Socket (socket), m_Timer (socket->get_io_service ()), m_BufferLen (0)
	{
		/* cache options */
		i2p::config::GetOption("http.auth", needAuth);
		i2p::config::GetOption("http.user", user);
		i2p::config::GetOption("http.pass", pass);
	}

	void HTTPConnection::Receive ()
	{
		m_Socket->async_read_some (boost::asio::buffer (m_Buffer, HTTP_CONNECTION_BUFFER_SIZE),
			 std::bind(&HTTPConnection::HandleReceive, shared_from_this (),
				 std::placeholders::_1, std::placeholders::_2));
	}

	void HTTPConnection::HandleReceive (const boost::system::error_code& ecode, std::size_t bytes_transferred)
	{
		if (ecode) {
			if (ecode != boost::asio::error::operation_aborted)
				Terminate (ecode);
			return;
		}
		m_Buffer[bytes_transferred] = '\0';
		m_BufferLen = bytes_transferred;
		RunRequest();
		Receive ();
	}

	void HTTPConnection::RunRequest ()
	{
		HTTPReq request;
		int ret = request.parse(m_Buffer);
		if (ret < 0) {
			m_Buffer[0] = '\0';
			m_BufferLen = 0;
			return; /* error */
		}
		if (ret == 0)
			return; /* need more data */

		HandleRequest (request);
	}

	void HTTPConnection::Terminate (const boost::system::error_code& ecode)
	{
		if (ecode == boost::asio::error::operation_aborted)
			return;
		boost::system::error_code ignored_ec;
		m_Socket->shutdown(boost::asio::ip::tcp::socket::shutdown_both, ignored_ec);
		m_Socket->close ();
	}

	bool HTTPConnection::CheckAuth (const HTTPReq & req) {
		/* method #1: http://user:pass@127.0.0.1:7070/ */
		if (req.uri.find('@') != std::string::npos) {
			URL url;
			if (url.parse(req.uri) && url.user == user && url.pass == pass)
				return true;
		}
		/* method #2: 'Authorization' header sent */
		if (req.headers.count("Authorization") > 0) {
			std::string provided = req.headers.find("Authorization")->second;
			std::string expected = user + ":" + pass;
			char b64_creds[64];
			std::size_t len = 0;
			len = i2p::data::ByteStreamToBase64((unsigned char *)expected.c_str(), expected.length(), b64_creds, sizeof(b64_creds));
			b64_creds[len] = '\0';
			expected = "Basic ";
			expected += b64_creds;
			if (provided == expected)
				return true;
		}

		LogPrint(eLogWarning, "HTTPServer: auth failure from ", m_Socket->remote_endpoint().address ());
		return false;
	}

	void HTTPConnection::HandleRequest (const HTTPReq & req)
	{
		std::stringstream s;
		std::string content;
		HTTPRes res;

		LogPrint(eLogDebug, "HTTPServer: request: ", req.uri);

		if (needAuth && !CheckAuth(req)) {
			res.code = 401;
			res.add_header("WWW-Authenticate", "Basic realm=\"WebAdmin\"");
			SendReply(res, content);
			return;
		}

		// Html5 head start
		ShowPageHead (s);
		if (req.uri.find("page=") != std::string::npos) {
			HandlePage (req, res, s);
		} else if (req.uri.find("cmd=") != std::string::npos) {
			HandleCommand (req, res, s);
		} else {
			ShowStatus (s);
		  res.add_header("Refresh", "5");
		}
		ShowPageTail (s);

		res.code = 200;
		content = s.str ();
		SendReply (res, content);
	}

	void HTTPConnection::HandlePage (const HTTPReq& req, HTTPRes& res, std::stringstream& s)
  {
		std::map<std::string, std::string> params;
		std::string page("");
		URL url;

		url.parse(req.uri);
		url.parse_query(params);
		page = params["page"];

		if (page == HTTP_PAGE_TRANSPORTS)
			ShowTransports (s);
		else if (page == HTTP_PAGE_TUNNELS)
			ShowTunnels (s);
		else if (page == HTTP_PAGE_COMMANDS)
			ShowCommands (s);
		else if (page == HTTP_PAGE_JUMPSERVICES)
			ShowJumpServices (s, params["address"]);
		else if (page == HTTP_PAGE_TRANSIT_TUNNELS)
			ShowTransitTunnels (s);
		else if (page == HTTP_PAGE_LOCAL_DESTINATIONS)
			ShowLocalDestinations (s);	
		else if (page == HTTP_PAGE_LOCAL_DESTINATION)
			ShowLocalDestination (s, params["b32"]);
		else if (page == HTTP_PAGE_SAM_SESSIONS)
			ShowSAMSessions (s);
		else if (page == HTTP_PAGE_SAM_SESSION)
			ShowSAMSession (s, params["sam_id"]);
		else if (page == HTTP_PAGE_I2P_TUNNELS)
			ShowI2PTunnels (s);
		else {
			res.code = 400;
			ShowError(s, "Unknown page: " + page);
			return;
		}
  }

	void HTTPConnection::HandleCommand (const HTTPReq& req, HTTPRes& res, std::stringstream& s)
	{
		std::map<std::string, std::string> params;
		std::string cmd("");
		URL url;

		url.parse(req.uri);
		url.parse_query(params);
		cmd = params["cmd"];

		if (cmd == HTTP_COMMAND_RUN_PEER_TEST)
			i2p::transport::transports.PeerTest ();
		else if (cmd == HTTP_COMMAND_RELOAD_CONFIG)
			i2p::client::context.ReloadConfig ();
		else if (cmd == HTTP_COMMAND_START_ACCEPTING_TUNNELS)
			i2p::context.SetAcceptsTunnels (true);
		else if (cmd == HTTP_COMMAND_STOP_ACCEPTING_TUNNELS)
			i2p::context.SetAcceptsTunnels (false);
		else if (cmd == HTTP_COMMAND_SHUTDOWN_START) {
			i2p::context.SetAcceptsTunnels (false);
#ifndef WIN32
			Daemon.gracefullShutdownInterval = 10*60;
#endif
		} else if (cmd == HTTP_COMMAND_SHUTDOWN_CANCEL) {
			i2p::context.SetAcceptsTunnels (true);
#ifndef WIN32
			Daemon.gracefullShutdownInterval = 0;
#endif
		} else if (cmd == HTTP_COMMAND_SHUTDOWN_NOW) {
			Daemon.running = false;
		} else {
			res.code = 400;
			ShowError(s, "Unknown command: " + cmd);
			return;
		}
		s << "<b>SUCCESS</b>:&nbsp;Command accepted<br><br>\r\n";
		s << "<a href=\"/?page=commands\">Back to commands list</a><br>\r\n";
		s << "<p>You will be redirected in 5 seconds</b>";
		res.add_header("Refresh", "5; url=/?page=commands");
	}	

	void HTTPConnection::SendReply (HTTPRes& reply, std::string& content)
	{
		reply.add_header("Content-Type", "text/html");
		reply.body = content;

		std::string res = reply.to_string();
		boost::asio::async_write (*m_Socket, boost::asio::buffer(res),
			std::bind (&HTTPConnection::Terminate, shared_from_this (), std::placeholders::_1));
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
		bool needAuth;    i2p::config::GetOption("http.auth", needAuth);
		std::string user; i2p::config::GetOption("http.user", user);
		std::string pass; i2p::config::GetOption("http.pass", pass);
		/* generate pass if needed */
		if (needAuth && pass == "") {
			char alnum[] = "0123456789"
			  "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
			  "abcdefghijklmnopqrstuvwxyz";
			pass.resize(16);
			for (size_t i = 0; i < pass.size(); i++) {
				pass[i] = alnum[rand() % (sizeof(alnum) - 1)];
			}
			i2p::config::SetOption("http.pass", pass);
			LogPrint(eLogInfo, "HTTPServer: password set to ", pass);
		}
		m_Thread = std::unique_ptr<std::thread>(new std::thread (std::bind (&HTTPServer::Run, this)));
		m_Acceptor.listen ();
		Accept ();
	}

	void HTTPServer::Stop ()
	{
		m_Acceptor.close();
		m_Service.stop ();
		if (m_Thread) {
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
		if (ecode)
			return;
		CreateConnection(newSocket);
		Accept ();
	}

	void HTTPServer::CreateConnection(std::shared_ptr<boost::asio::ip::tcp::socket> newSocket)
	{
		auto conn = std::make_shared<HTTPConnection> (newSocket);
		conn->Receive ();
	}
} // http
} // i2p
