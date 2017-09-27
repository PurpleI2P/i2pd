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
#include "Transports.h"
#include "NetDb.hpp"
#include "HTTP.h"
#include "LeaseSet.h"
#include "Destination.h"
#include "RouterContext.h"
#include "ClientContext.h"
#include "HTTPServer.h"
#include "Daemon.h"
#include "util.h"
#ifdef WIN32_APP
#include "Win32/Win32App.h"
#endif

// For image and info
#include "version.h"

namespace i2p {
namespace http {
	const char *itoopieFavicon =
		"data:image/png;base64,"
		"iVBORw0KGgoAAAANSUhEUgAAABAAAAAQCAYAAAAf8/9hAAAAAXNSR0IArs4c6QAAAARnQU1BAACx"
		"jwv8YQUAAAAJcEhZcwAALiIAAC4iAari3ZIAAAAHdElNRQfgCQsUNSZrkhi1AAAAGXRFWHRTb2Z0"
		"d2FyZQBwYWludC5uZXQgNC4wLjEyQwRr7AAAAoJJREFUOE9jwAUqi4Q1oEwwcDTV1+5sETaBclGB"
		"vb09C5QJB6kWpvFQJoOCeLC5kmjEHCgXE2SlyETLi3h6QrkM4VL+ssWSCZUgtopITLKqaOotRTEn"
		"cbAkLqAkGtOqLBLVAWLXyWSVFkkmRiqLxuaqiWb/VBYJMAYrwgckJY25VEUzniqKhjU2y+RtCRSP"
		"6lUXy/1jIBV5tlYxZUaFVMq2NInwIi9hO8fSfOEAqDZUoCwal6MulvOvyS7gi69K4j9zxZT/m0ps"
		"/28ptvvvquXXryIa7QYMMdTwqi0WNtVi0GIDseXl7TnUxFKfnGlxAGp0+D8j2eH/8Ub7/9e7nf7X"
		"+Af/B7rwt6pI0h0l0WhQADOC9DBkhSirpImHNVZKp24ukkyoshGLnN8d5fA/y13t/44Kq/8hlnL/"
		"z7fZ/58f6vcxSNpbVUVFhV1RLNBVTsQzVYZPSwhsCAhkiIfpNMrkbO6TLf071Sfk/5ZSi/+7q6z/"
		"P5ns+v9mj/P/CpuI/20y+aeNGYxZoVoYGmsF3aFMBAAZlCwftnF9ke3//bU2//fXWP8/UGv731Am"
		"+V+DdNblSqnUYqhSTKAiYSOqJBrVqiaa+S3UNPr/gmyH/xuKXf63hnn/B8bIP0UxHfEyyeSNQKVM"
		"EB1AEB2twhcTLp+gIBJUoyKasEpVJHmqskh8qryovUG/ffCHHRU2q/Tk/YuB6eGPsbExa7ZkpLu1"
		"oLEcVDtuUCgV1w60rQzElpRUE1EVSX0BYidHiInXF4nagNhYQW60EF+ApH1ktni0A1SIITSUgVlZ"
		"JHYnlIsfzJjIp9xZKswL5YKBHL+coKJoRDaUSzoozxHVrygQU4JykQADAwAT5b1NHtwZugAAAABJ"
		"RU5ErkJggg==";

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
		"  .private { background: black; color: black; } .private:hover { background: black; color: white } \r\n"
		"  .slide p, .slide [type='checkbox']{ display:none; } \r\n"
		"  .slide [type='checkbox']:checked ~ p { display:block; } \r\n"
		"</style>\r\n";

	const char HTTP_PAGE_TUNNELS[] = "tunnels";
	const char HTTP_PAGE_TRANSIT_TUNNELS[] = "transit_tunnels";
	const char HTTP_PAGE_TRANSPORTS[] = "transports";
	const char HTTP_PAGE_LOCAL_DESTINATIONS[] = "local_destinations";
	const char HTTP_PAGE_LOCAL_DESTINATION[] = "local_destination";
	const char HTTP_PAGE_I2CP_LOCAL_DESTINATION[] = "i2cp_local_destination";
	const char HTTP_PAGE_SAM_SESSIONS[] = "sam_sessions";
	const char HTTP_PAGE_SAM_SESSION[] = "sam_session";
	const char HTTP_PAGE_I2P_TUNNELS[] = "i2p_tunnels";
	const char HTTP_PAGE_COMMANDS[] = "commands";
	const char HTTP_PAGE_LEASESETS[] = "leasesets";
	const char HTTP_COMMAND_ENABLE_TRANSIT[] = "enable_transit";
	const char HTTP_COMMAND_DISABLE_TRANSIT[] = "disable_transit";
	const char HTTP_COMMAND_SHUTDOWN_START[] = "shutdown_start";
	const char HTTP_COMMAND_SHUTDOWN_CANCEL[] = "shutdown_cancel";
	const char HTTP_COMMAND_SHUTDOWN_NOW[] = "terminate";
	const char HTTP_COMMAND_RUN_PEER_TEST[] = "run_peer_test";
	const char HTTP_COMMAND_RELOAD_CONFIG[] = "reload_config";
	const char HTTP_PARAM_SAM_SESSION_ID[] = "id";
	const char HTTP_PARAM_ADDRESS[] = "address";

	static void ShowUptime (std::stringstream& s, int seconds)
	{
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

	static void ShowTraffic (std::stringstream& s, uint64_t bytes)
	{
		s << std::fixed << std::setprecision(2);
		auto numKBytes = (double) bytes / 1024;
		if (numKBytes < 1024)
			s << numKBytes << " KiB";
		else if (numKBytes < 1024 * 1024)
			s << numKBytes / 1024 << " MiB";
		else
			s << numKBytes / 1024 / 1024 << " GiB";
	}

	static void ShowTunnelDetails (std::stringstream& s, enum i2p::tunnel::TunnelState eState, int bytes)
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

	static void ShowPageHead (std::stringstream& s)
	{
		s <<
			"<!DOCTYPE html>\r\n"
			"<html lang=\"en\">\r\n" /* TODO: Add support for locale */
			"  <head>\r\n" /* TODO: Find something to parse html/template system. This is horrible. */
#if (!defined(WIN32))
			"  <meta charset=\"UTF-8\">\r\n"
#else
			"  <meta charset=\"windows-1251\">\r\n"
#endif
			"  <link rel=\"shortcut icon\" href=\"" << itoopieFavicon << "\">\r\n"
			"  <title>Purple I2P " VERSION " Webconsole</title>\r\n"
			<< cssStyles <<
			"</head>\r\n";
		s <<
			"<body>\r\n"
			"<div class=header><b>i2pd</b> webconsole</div>\r\n"
			"<div class=wrapper>\r\n"
			"<div class=left>\r\n"
			"  <a href=\"/\">Main page</a><br>\r\n<br>\r\n"
			"  <a href=\"/?page=" << HTTP_PAGE_COMMANDS << "\">Router commands</a><br>\r\n"
			"  <a href=\"/?page=" << HTTP_PAGE_LOCAL_DESTINATIONS << "\">Local destinations</a><br>\r\n"
			"  <a href=\"/?page=" << HTTP_PAGE_LEASESETS << "\">LeaseSets</a><br>\r\n"
			"  <a href=\"/?page=" << HTTP_PAGE_TUNNELS << "\">Tunnels</a><br>\r\n"
			"  <a href=\"/?page=" << HTTP_PAGE_TRANSIT_TUNNELS << "\">Transit tunnels</a><br>\r\n"
			"  <a href=\"/?page=" << HTTP_PAGE_TRANSPORTS << "\">Transports</a><br>\r\n"
			"  <a href=\"/?page=" << HTTP_PAGE_I2P_TUNNELS << "\">I2P tunnels</a><br>\r\n";
		if (i2p::client::context.GetSAMBridge ())
			s << "  <a href=\"/?page=" << HTTP_PAGE_SAM_SESSIONS << "\">SAM sessions</a><br>\r\n";
		s <<
			"</div>\r\n"
			"<div class=right>";
	}

	static void ShowPageTail (std::stringstream& s)
	{
		s <<
			"</div></div>\r\n"
			"</body>\r\n"
			"</html>\r\n";
	}

	static void ShowError(std::stringstream& s, const std::string& string)
	{
		s << "<b>ERROR:</b>&nbsp;" << string << "<br>\r\n";
	}

	void ShowStatus (std::stringstream& s, bool includeHiddenContent)
	{
		s << "<b>Uptime:</b> ";
		ShowUptime(s, i2p::context.GetUptime ());
		s << "<br>\r\n";
		s << "<b>Network status:</b> ";
		switch (i2p::context.GetStatus ())
		{
			case eRouterStatusOK: s << "OK"; break;
			case eRouterStatusTesting: s << "Testing"; break;
			case eRouterStatusFirewalled: s << "Firewalled"; break;
			case eRouterStatusError:
			{
				s << "Error";
				switch (i2p::context.GetError ())
				{
					case eRouterErrorClockSkew:
						s << "<br>Clock skew";
					break;
					default: ;
				}
				break;
			}
			default: s << "Unknown";
		}
		s << "<br>\r\n";
#if (!defined(WIN32) && !defined(QT_GUI_LIB) && !defined(ANDROID))
		if (auto remains = Daemon.gracefulShutdownInterval) {
			s << "<b>Stopping in:</b> ";
			s << remains << " seconds";
			s << "<br>\r\n";
		}
#endif
		auto family = i2p::context.GetFamily ();
		if (family.length () > 0)
			s << "<b>Family:</b> " << family << "<br>\r\n";
		s << "<b>Tunnel creation success rate:</b> " << i2p::tunnel::tunnels.GetTunnelCreationSuccessRate () << "%<br>\r\n";
		s << "<b>Received:</b> ";
		ShowTraffic (s, i2p::transport::transports.GetTotalReceivedBytes ());
		s << " (" << (double) i2p::transport::transports.GetInBandwidth () / 1024 << " KiB/s)<br>\r\n";
		s << "<b>Sent:</b> ";
		ShowTraffic (s, i2p::transport::transports.GetTotalSentBytes ());
		s << " (" << (double) i2p::transport::transports.GetOutBandwidth () / 1024 << " KiB/s)<br>\r\n";
		s << "<b>Transit:</b> ";
		ShowTraffic (s, i2p::transport::transports.GetTotalTransitTransmittedBytes ());
		s << " (" << (double) i2p::transport::transports.GetTransitBandwidth () / 1024 << " KiB/s)<br>\r\n";
		s << "<b>Data path:</b> " << i2p::fs::GetDataDir() << "<br>\r\n";
		s << "<div class='slide'\r\n><label for='slide1'>Hidden content. Press on text to see.</label>\r\n<input type='checkbox' id='slide1'/>\r\n<p class='content'>\r\n";
		if(includeHiddenContent) {
			s << "<b>Router Ident:</b> " << i2p::context.GetRouterInfo().GetIdentHashBase64() << "<br>\r\n";
			s << "<b>Router Family:</b> " << i2p::context.GetRouterInfo().GetProperty("family") << "<br>\r\n";
			s << "<b>Router Caps:</b> " << i2p::context.GetRouterInfo().GetProperty("caps") << "<br>\r\n";
			s << "<b>Our external address:</b>" << "<br>\r\n" ;
			for (const auto& address : i2p::context.GetRouterInfo().GetAddresses())
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
		}
		s << "</p>\r\n</div>\r\n";
		s << "<b>Routers:</b> " << i2p::data::netdb.GetNumRouters () << " ";
		s << "<b>Floodfills:</b> " << i2p::data::netdb.GetNumFloodfills () << " ";
		s << "<b>LeaseSets:</b> " << i2p::data::netdb.GetNumLeaseSets () << "<br>\r\n";

		size_t clientTunnelCount = i2p::tunnel::tunnels.CountOutboundTunnels();
		clientTunnelCount += i2p::tunnel::tunnels.CountInboundTunnels();
		size_t transitTunnelCount = i2p::tunnel::tunnels.CountTransitTunnels();

		s << "<b>Client Tunnels:</b> " << std::to_string(clientTunnelCount) << " ";
		s << "<b>Transit Tunnels:</b> " << std::to_string(transitTunnelCount) << "<br>\r\n";
	}

	void ShowLocalDestinations (std::stringstream& s)
	{
		s << "<b>Local Destinations:</b><br>\r\n<br>\r\n";
		for (auto& it: i2p::client::context.GetDestinations ())
		{
			auto ident = it.second->GetIdentHash ();
			s << "<a href=\"/?page=" << HTTP_PAGE_LOCAL_DESTINATION << "&b32=" << ident.ToBase32 () << "\">";
			s << i2p::client::context.GetAddressBook ().ToAddress(ident) << "</a><br>\r\n" << std::endl;
		}

		auto i2cpServer = i2p::client::context.GetI2CPServer ();
		if (i2cpServer)
		{
			s << "<br><b>I2CP Local Destinations:</b><br>\r\n<br>\r\n";
			for (auto& it: i2cpServer->GetSessions ())
			{
				auto dest = it.second->GetDestination ();
				if (dest)
				{
					auto ident = dest->GetIdentHash ();
					s << "<a href=\"/?page=" << HTTP_PAGE_I2CP_LOCAL_DESTINATION << "&i2cp_id=" << it.first << "\">";
					s << i2p::client::context.GetAddressBook ().ToAddress(ident) << "</a><br>\r\n" << std::endl;
				}
			}
		}
	}

	static void ShowLeaseSetDestination (std::stringstream& s, std::shared_ptr<const i2p::client::LeaseSetDestination> dest)
	{
		s << "<b>Base64:</b><br>\r\n<textarea readonly=\"readonly\" cols=\"64\" rows=\"11\" wrap=\"on\">";
		s << dest->GetIdentity ()->ToBase64 () << "</textarea><br>\r\n<br>\r\n";
		s << "<b>LeaseSets:</b> <i>" << dest->GetNumRemoteLeaseSets () << "</i><br>\r\n";
		if(dest->GetNumRemoteLeaseSets())
		{
			s << "<div class='slide'\r\n><label for='slide1'>Hidden content. Press on text to see.</label>\r\n<input type='checkbox' id='slide1'/>\r\n<p class='content'>\r\n";
			for(auto& it: dest->GetLeaseSets ())
				s << it.second->GetIdentHash ().ToBase32 () << "<br>\r\n";
			s << "</p>\r\n</div>\r\n";
		}
		auto pool = dest->GetTunnelPool ();
		if (pool)
		{
			s << "<b>Inbound tunnels:</b><br>\r\n";
			for (auto & it : pool->GetInboundTunnels ()) {
				it->Print(s);
				if(it->LatencyIsKnown())
					s << " ( " << it->GetMeanLatency() << "ms )";
				ShowTunnelDetails(s, it->GetState (), it->GetNumReceivedBytes ());
			}
			s << "<br>\r\n";
			s << "<b>Outbound tunnels:</b><br>\r\n";
			for (auto & it : pool->GetOutboundTunnels ()) {
				it->Print(s);
				if(it->LatencyIsKnown())
					s << " ( " << it->GetMeanLatency() << "ms )";
				ShowTunnelDetails(s, it->GetState (), it->GetNumSentBytes ());
			}
		}
		s << "<br>\r\n";
		s << "<b>Tags</b><br>Incoming: " << dest->GetNumIncomingTags () << "<br>Outgoing:<br>" << std::endl;
		for (const auto& it: dest->GetSessions ())
		{
			s << i2p::client::context.GetAddressBook ().ToAddress(it.first) << " ";
			s << it.second->GetNumOutgoingTags () << "<br>" << std::endl;
		}
		s << "<br>" << std::endl;
	}

	void ShowLocalDestination (std::stringstream& s, const std::string& b32)
	{
		s << "<b>Local Destination:</b><br>\r\n<br>\r\n";
		i2p::data::IdentHash ident;
		ident.FromBase32 (b32);
		auto dest = i2p::client::context.FindLocalDestination (ident);
		if (dest)
		{
			ShowLeaseSetDestination (s, dest);
			// show streams
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

			for (const auto& it: dest->GetAllStreams ())
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
			s << "</table>";
		}
	}

	static void ShowI2CPLocalDestination (std::stringstream& s, const std::string& id)
	{
		auto i2cpServer = i2p::client::context.GetI2CPServer ();
		if (i2cpServer)
		{
			s << "<b>I2CP Local Destination:</b><br>\r\n<br>\r\n";
			auto it = i2cpServer->GetSessions ().find (std::stoi (id));
			if (it != i2cpServer->GetSessions ().end ())
				ShowLeaseSetDestination (s, it->second->GetDestination ());
			else
				ShowError(s, "I2CP session not found");
		}
		else
			ShowError(s, "I2CP is not enabled");
	}

	void ShowLeasesSets(std::stringstream& s)
	{
		s << "<div id='leasesets'><b>LeaseSets (click on to show info):</b></div><br>\r\n";
		int counter = 1;
		// for each lease set
		i2p::data::netdb.VisitLeaseSets(
			[&s, &counter](const i2p::data::IdentHash dest, std::shared_ptr<i2p::data::LeaseSet> leaseSet)
			{
				// create copy of lease set so we extract leases
				i2p::data::LeaseSet ls(leaseSet->GetBuffer(), leaseSet->GetBufferLen());
				s << "<div class='leaseset";
				if (ls.IsExpired())
					s << " expired"; // additional css class for expired
				s << "'>\r\n";
				if (!ls.IsValid())
					s << "<div class='invalid'>!! Invalid !! </div>\r\n";
				s << "<div class='slide'><label for='slide" << counter << "'>" << dest.ToBase32() << "</label>\r\n";
				s << "<input type='checkbox' id='slide" << (counter++) << "'/>\r\n<p class='content'>\r\n";
				s << "<b>Expires:</b> " << ls.GetExpirationTime() << "<br>\r\n";
				auto leases = ls.GetNonExpiredLeases();
				s << "<b>Non Expired Leases: " << leases.size() << "</b><br>\r\n";
				for ( auto & l : leases )
				{
					s << "<b>Gateway:</b> " << l->tunnelGateway.ToBase64() << "<br>\r\n";
					s << "<b>TunnelID:</b> " << l->tunnelID << "<br>\r\n";
					s << "<b>EndDate:</b> " << l->endDate << "<br>\r\n";
				}
				s << "</p>\r\n</div>\r\n</div>\r\n";
			}
		);
		// end for each lease set
	}

	void ShowTunnels (std::stringstream& s)
	{
		s << "<b>Queue size:</b> " << i2p::tunnel::tunnels.GetQueueSize () << "<br>\r\n";

		s << "<b>Inbound tunnels:</b><br>\r\n";
		for (auto & it : i2p::tunnel::tunnels.GetInboundTunnels ()) {
			it->Print(s);
			if(it->LatencyIsKnown())
				s << " ( " << it->GetMeanLatency() << "ms )";
			ShowTunnelDetails(s, it->GetState (), it->GetNumReceivedBytes ());
		}
		s << "<br>\r\n";
		s << "<b>Outbound tunnels:</b><br>\r\n";
		for (auto & it : i2p::tunnel::tunnels.GetOutboundTunnels ()) {
			it->Print(s);
			if(it->LatencyIsKnown())
				s << " ( " << it->GetMeanLatency() << "ms )";
			ShowTunnelDetails(s, it->GetState (), it->GetNumSentBytes ());
		}
		s << "<br>\r\n";
	}

	static void ShowCommands (std::stringstream& s, uint32_t token)
	{
		/* commands */
		s << "<b>Router Commands</b><br>\r\n";
		s << "  <a href=\"/?cmd=" << HTTP_COMMAND_RUN_PEER_TEST << "&token=" << token << "\">Run peer test</a><br>\r\n";
		//s << "  <a href=\"/?cmd=" << HTTP_COMMAND_RELOAD_CONFIG << "\">Reload config</a><br>\r\n";
		if (i2p::context.AcceptsTunnels ())
			s << "  <a href=\"/?cmd=" << HTTP_COMMAND_DISABLE_TRANSIT << "&token=" << token << "\">Decline transit tunnels</a><br>\r\n";
		else
			s << "  <a href=\"/?cmd=" << HTTP_COMMAND_ENABLE_TRANSIT << "&token=" << token << "\">Accept transit tunnels</a><br>\r\n";
#if (!defined(WIN32) && !defined(QT_GUI_LIB) && !defined(ANDROID))
		if (Daemon.gracefulShutdownInterval)
			s << "  <a href=\"/?cmd=" << HTTP_COMMAND_SHUTDOWN_CANCEL << "&token=" << token << "\">Cancel graceful shutdown</a><br>";
		else
			s << "  <a href=\"/?cmd=" << HTTP_COMMAND_SHUTDOWN_START << "&token=" << token << "\">Start graceful shutdown</a><br>\r\n";
#elif defined(WIN32_APP)
		if (i2p::util::DaemonWin32::Instance().isGraceful)
			s << "  <a href=\"/?cmd=" << HTTP_COMMAND_SHUTDOWN_CANCEL << "&token=" << token << "\">Cancel graceful shutdown</a><br>";
		else
			s << "  <a href=\"/?cmd=" << HTTP_COMMAND_SHUTDOWN_START << "&token=" << token << "\">Graceful shutdown</a><br>\r\n";
#endif
		s << "  <a href=\"/?cmd=" << HTTP_COMMAND_SHUTDOWN_NOW << "&token=" << token << "\">Force shutdown</a><br>\r\n";
	}

	void ShowTransitTunnels (std::stringstream& s)
	{
		s << "<b>Transit tunnels:</b><br>\r\n<br>\r\n";
		for (const auto& it: i2p::tunnel::tunnels.GetTransitTunnels ())
		{
			if (std::dynamic_pointer_cast<i2p::tunnel::TransitTunnelGateway>(it))
				s << it->GetTunnelID () << " &#8658; ";
			else if (std::dynamic_pointer_cast<i2p::tunnel::TransitTunnelEndpoint>(it))
				s << " &#8658; " << it->GetTunnelID ();
			else
				s << " &#8658; " << it->GetTunnelID () << " &#8658; ";
			s << " " << it->GetNumTransmittedBytes () << "<br>\r\n";
		}
	}

	void ShowTransports (std::stringstream& s)
	{
		s << "<b>Transports:</b><br>\r\n<br>\r\n";
		auto ntcpServer = i2p::transport::transports.GetNTCPServer ();
		if (ntcpServer)
		{
			auto sessions = ntcpServer->GetNTCPSessions ();
			if (!sessions.empty ())
			{
				std::stringstream tmp_s, tmp_s6; uint16_t cnt = 0, cnt6 = 0;
				for (const auto& it: sessions )
				{
					if (it.second && it.second->IsEstablished () && !it.second->GetSocket ().remote_endpoint ().address ().is_v6 ())
					{
						// incoming connection doesn't have remote RI
						if (it.second->IsOutgoing ()) tmp_s << " &#8658; ";
						tmp_s << i2p::data::GetIdentHashAbbreviation (it.second->GetRemoteIdentity ()->GetIdentHash ()) << ": "
							<< it.second->GetSocket ().remote_endpoint().address ().to_string ();
						if (!it.second->IsOutgoing ()) tmp_s << " &#8658; ";
						tmp_s << " [" << it.second->GetNumSentBytes () << ":" << it.second->GetNumReceivedBytes () << "]";
						tmp_s << "<br>\r\n" << std::endl;
						cnt++;
					}
					if (it.second && it.second->IsEstablished () && it.second->GetSocket ().remote_endpoint ().address ().is_v6 ())
					{
						if (it.second->IsOutgoing ()) tmp_s6 << " &#8658; ";
						tmp_s6 << i2p::data::GetIdentHashAbbreviation (it.second->GetRemoteIdentity ()->GetIdentHash ()) << ": "
							<< "[" << it.second->GetSocket ().remote_endpoint().address ().to_string () << "]";
						if (!it.second->IsOutgoing ()) tmp_s6 << " &#8658; ";
						tmp_s6 << " [" << it.second->GetNumSentBytes () << ":" << it.second->GetNumReceivedBytes () << "]";
						tmp_s6 << "<br>\r\n" << std::endl;
						cnt6++;
					}
				}
				if (!tmp_s.str ().empty ())
				{
					s << "<b>NTCP</b> ( " << cnt << " )<br>\r\n";
					s << tmp_s.str () << "<br>\r\n";
				}
				if (!tmp_s6.str ().empty ())
				{
					s << "<b>NTCP6</b> ( " << cnt6 << " )<br>\r\n";
					s << tmp_s6.str () << "<br>\r\n";
				}
			}
		}
		auto ssuServer = i2p::transport::transports.GetSSUServer ();
		if (ssuServer)
		{
			auto sessions = ssuServer->GetSessions ();
			if (!sessions.empty ())
			{
				s << "<b>SSU</b> ( " << (int) sessions.size() << " )<br>\r\n";
				for (const auto& it: sessions)
				{
					auto endpoint = it.second->GetRemoteEndpoint ();
					if (it.second->IsOutgoing ()) s << " &#8658; ";
					s << endpoint.address ().to_string () << ":" << endpoint.port ();
					if (!it.second->IsOutgoing ()) s << " &#8658; ";
					s << " [" << it.second->GetNumSentBytes () << ":" << it.second->GetNumReceivedBytes () << "]";
					if (it.second->GetRelayTag ())
						s << " [itag:" << it.second->GetRelayTag () << "]";
					s << "<br>\r\n" << std::endl;
				}
				s << "<br>\r\n";
			}
			auto sessions6 = ssuServer->GetSessionsV6 ();
			if (!sessions6.empty ())
			{
				s << "<b>SSU6</b> ( " << (int) sessions6.size() << " )<br>\r\n";
				for (const auto& it: sessions6)
				{
					auto endpoint = it.second->GetRemoteEndpoint ();
					if (it.second->IsOutgoing ()) s << " &#8658; ";
					s << "[" << endpoint.address ().to_string () << "]:" << endpoint.port ();
					if (!it.second->IsOutgoing ()) s << " &#8658; ";
					s << " [" << it.second->GetNumSentBytes () << ":" << it.second->GetNumReceivedBytes () << "]";
					if (it.second->GetRelayTag ())
						s << " [itag:" << it.second->GetRelayTag () << "]";
					s << "<br>\r\n" << std::endl;
				}
				s << "<br>\r\n";
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
			s << "<a href=\"/?page=" << HTTP_PAGE_SAM_SESSION << "&sam_id=" << it.first << "\">";
			s << it.first << "</a><br>\r\n" << std::endl;
		}
	}

	static void ShowSAMSession (std::stringstream& s, const std::string& id)
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
		s << "<a href=\"/?page=" << HTTP_PAGE_LOCAL_DESTINATION << "&b32=" << ident.ToBase32 () << "\">";
		s << i2p::client::context.GetAddressBook ().ToAddress(ident) << "</a><br>\r\n";
		s << "<br>\r\n";
		s << "<b>Streams:</b><br>\r\n";
		for (const auto& it: session->ListSockets())
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
			s << "<a href=\"/?page=" << HTTP_PAGE_LOCAL_DESTINATION << "&b32=" << ident.ToBase32 () << "\">";
			s << it.second->GetName () << "</a> &#8656; ";
			s << i2p::client::context.GetAddressBook ().ToAddress(ident);
			s << "<br>\r\n"<< std::endl;
		}
		auto httpProxy = i2p::client::context.GetHttpProxy ();
		if (httpProxy)
		{
			auto& ident = httpProxy->GetLocalDestination ()->GetIdentHash();
			s << "<a href=\"/?page=" << HTTP_PAGE_LOCAL_DESTINATION << "&b32=" << ident.ToBase32 () << "\">";
			s << "HTTP Proxy" << "</a> &#8656; ";
			s << i2p::client::context.GetAddressBook ().ToAddress(ident);
			s << "<br>\r\n"<< std::endl;
		}
		auto socksProxy = i2p::client::context.GetSocksProxy ();
		if (socksProxy)
		{
			auto& ident = socksProxy->GetLocalDestination ()->GetIdentHash();
			s << "<a href=\"/?page=" << HTTP_PAGE_LOCAL_DESTINATION << "&b32=" << ident.ToBase32 () << "\">";
			s << "SOCKS Proxy" << "</a> &#8656; ";
			s << i2p::client::context.GetAddressBook ().ToAddress(ident);
			s << "<br>\r\n"<< std::endl;
		}
		auto& serverTunnels = i2p::client::context.GetServerTunnels ();
		if (!serverTunnels.empty ()) {
			s << "<br>\r\n<b>Server Tunnels:</b><br>\r\n<br>\r\n";
			for (auto& it: serverTunnels)
			{
				auto& ident = it.second->GetLocalDestination ()->GetIdentHash();
				s << "<a href=\"/?page=" << HTTP_PAGE_LOCAL_DESTINATION << "&b32=" << ident.ToBase32 () << "\">";
				s << it.second->GetName () << "</a> &#8658; ";
				s << i2p::client::context.GetAddressBook ().ToAddress(ident);
				s << ":" << it.second->GetLocalPort ();
				s << "</a><br>\r\n"<< std::endl;
			}
		}
		auto& clientForwards = i2p::client::context.GetClientForwards ();
		if (!clientForwards.empty ())
		{
			s << "<br>\r\n<b>Client Forwards:</b><br>\r\n<br>\r\n";
			for (auto& it: clientForwards)
			{
				auto& ident = it.second->GetLocalDestination ()->GetIdentHash();
				s << "<a href=\"/?page=" << HTTP_PAGE_LOCAL_DESTINATION << "&b32=" << ident.ToBase32 () << "\">";
				s << it.second->GetName () << "</a> &#8656; ";
				s << i2p::client::context.GetAddressBook ().ToAddress(ident);
				s << "<br>\r\n"<< std::endl;
			}
		}
		auto& serverForwards = i2p::client::context.GetServerForwards ();
		if (!serverForwards.empty ())
		{
			s << "<br>\r\n<b>Server Forwards:</b><br>\r\n<br>\r\n";
			for (auto& it: serverForwards)
			{
				auto& ident = it.second->GetLocalDestination ()->GetIdentHash();
				s << "<a href=\"/?page=" << HTTP_PAGE_LOCAL_DESTINATION << "&b32=" << ident.ToBase32 () << "\">";
				s << it.second->GetName () << "</a> &#8656; ";
				s << i2p::client::context.GetAddressBook ().ToAddress(ident);
				s << "<br>\r\n"<< std::endl;
			}
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
		auto provided = req.GetHeader ("Authorization");
		if (provided.length () > 0)
		{
			bool result = false;

			std::string expected = user + ":" + pass;
			size_t b64_sz = i2p::data::Base64EncodingBufferSize(expected.length()) + 1;
			char * b64_creds = new char[b64_sz];
			std::size_t len = 0;
			len = i2p::data::ByteStreamToBase64((unsigned char *)expected.c_str(), expected.length(), b64_creds, b64_sz);
			/* if we decoded properly then check credentials */
			if(len) {
				b64_creds[len] = '\0';
				expected = "Basic ";
				expected += b64_creds;
				result = expected == provided;
			}
			delete [] b64_creds;
			return result;
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
			ShowStatus (s, true);
			res.add_header("Refresh", "10");
		}
		ShowPageTail (s);

		res.code = 200;
		content = s.str ();
		SendReply (res, content);
	}

	std::map<uint32_t, uint32_t> HTTPConnection::m_Tokens;
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
		{
			uint32_t token;
			RAND_bytes ((uint8_t *)&token, 4);
			token &= 0x7FFFFFFF; // clear first bit
			auto ts = i2p::util::GetSecondsSinceEpoch ();
			for (auto it = m_Tokens.begin (); it != m_Tokens.end (); )
			{
				if (ts > it->second + TOKEN_EXPIRATION_TIMEOUT)
					it = m_Tokens.erase (it);
				else
					++it;
			}
			m_Tokens[token] = ts;
			ShowCommands (s, token);
		}
		else if (page == HTTP_PAGE_TRANSIT_TUNNELS)
			ShowTransitTunnels (s);
		else if (page == HTTP_PAGE_LOCAL_DESTINATIONS)
			ShowLocalDestinations (s);
		else if (page == HTTP_PAGE_LOCAL_DESTINATION)
			ShowLocalDestination (s, params["b32"]);
		else if (page == HTTP_PAGE_I2CP_LOCAL_DESTINATION)
			ShowI2CPLocalDestination (s, params["i2cp_id"]);
		else if (page == HTTP_PAGE_SAM_SESSIONS)
			ShowSAMSessions (s);
		else if (page == HTTP_PAGE_SAM_SESSION)
			ShowSAMSession (s, params["sam_id"]);
		else if (page == HTTP_PAGE_I2P_TUNNELS)
			ShowI2PTunnels (s);
		else if (page == HTTP_PAGE_LEASESETS)
			ShowLeasesSets(s);
		else {
			res.code = 400;
			ShowError(s, "Unknown page: " + page);
			return;
		}
	}

	void HTTPConnection::HandleCommand (const HTTPReq& req, HTTPRes& res, std::stringstream& s)
	{
		std::map<std::string, std::string> params;
		URL url;

		url.parse(req.uri);
		url.parse_query(params);

		std::string token = params["token"];
		if (token.empty () || m_Tokens.find (std::stoi (token)) == m_Tokens.end ())
		{
			ShowError(s, "Invalid token");
			return;
		}

		std::string cmd = params["cmd"];
		if (cmd == HTTP_COMMAND_RUN_PEER_TEST)
			i2p::transport::transports.PeerTest ();
		else if (cmd == HTTP_COMMAND_RELOAD_CONFIG)
			i2p::client::context.ReloadConfig ();
		else if (cmd == HTTP_COMMAND_ENABLE_TRANSIT)
			i2p::context.SetAcceptsTunnels (true);
		else if (cmd == HTTP_COMMAND_DISABLE_TRANSIT)
			i2p::context.SetAcceptsTunnels (false);
		else if (cmd == HTTP_COMMAND_SHUTDOWN_START) {
			i2p::context.SetAcceptsTunnels (false);
#if (!defined(WIN32) && !defined(QT_GUI_LIB) && !defined(ANDROID))
			Daemon.gracefulShutdownInterval = 10*60;
#elif defined(WIN32_APP)
			i2p::win32::GracefulShutdown ();
#endif
		} else if (cmd == HTTP_COMMAND_SHUTDOWN_CANCEL) {
			i2p::context.SetAcceptsTunnels (true);
#if (!defined(WIN32) && !defined(QT_GUI_LIB) && !defined(ANDROID))
			Daemon.gracefulShutdownInterval = 0;
#elif defined(WIN32_APP)
			i2p::win32::StopGracefulShutdown ();
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
		reply.add_header("X-Frame-Options", "SAMEORIGIN");
		reply.add_header("Content-Type", "text/html");
		reply.body = content;

		m_SendBuffer = reply.to_string();
		boost::asio::async_write (*m_Socket, boost::asio::buffer(m_SendBuffer),
			std::bind (&HTTPConnection::Terminate, shared_from_this (), std::placeholders::_1));
	}

	HTTPServer::HTTPServer (const std::string& address, int port):
		m_IsRunning (false), m_Thread (nullptr), m_Work (m_Service),
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
			uint8_t random[16];
			char alnum[] = "0123456789"
			  "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
			  "abcdefghijklmnopqrstuvwxyz";
			pass.resize(sizeof(random));
			RAND_bytes(random, sizeof(random));
			for (size_t i = 0; i < sizeof(random); i++) {
				pass[i] = alnum[random[i] % (sizeof(alnum) - 1)];
			}
			i2p::config::SetOption("http.pass", pass);
			LogPrint(eLogInfo, "HTTPServer: password set to ", pass);
		}
		m_IsRunning = true;
		m_Thread = std::unique_ptr<std::thread>(new std::thread (std::bind (&HTTPServer::Run, this)));
		m_Acceptor.listen ();
		Accept ();
	}

	void HTTPServer::Stop ()
	{
		m_IsRunning = false;
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
		while (m_IsRunning)
		{
			try
			{
				m_Service.run ();
			}
			catch (std::exception& ex)
			{
				LogPrint (eLogError, "HTTPServer: runtime exception: ", ex.what ());
			}
		}
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
		{
			if(newSocket) newSocket->close();
			LogPrint(eLogError, "HTTP Server: error handling accept ", ecode.message());
			if(ecode != boost::asio::error::operation_aborted)
				Accept();
			return;
		}
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
