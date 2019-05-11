#include <iomanip>
#include <sstream>
#include <thread>
#include <memory>

#include <boost/asio.hpp>
#include <boost/bind.hpp>
#include <boost/algorithm/string.hpp>

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

namespace dotnet {
namespace http {
	const char *dotnetFavicon =
		"data:image/png;base64,"
		"iVBORw0KGgoAAAANSUhEUgAAABAAAAAQCAMAAAAoLQ9TAAAABGdBTUEAALGPC/xhBQAAACBjSFJN"
		"AAB6JgAAgIQAAPoAAACA6AAAdTAAAOpgAAA6mAAAF3CculE8AAAA21BMVEUAe/8Ae/8Ae/8Ae/8A"
		"e/8Ae/8Ae/8Ae/8Aev8Be/8Bev8CfP8Aef8Mgf9irv8Qg/9Tpv+NxP+hzv9Spf8Ogv9zt/+gzf9O"
		"o/9hrf/k8f99u/8Eff+HwP+x1/9wtf++3f98u//F4f/G4f9qsf/O5v9Fn/8Fff+Hwf91t/8ah/+6"
		"2/+jz//M5P+Kwv+n0f9Mof+72/8bif8ijP+Avf+Mw/9vtP8ZiP+x1v+42v+02P+Ev/9+vP8KgP8p"
		"kP8aif8Gfv8rkf8Hfv8gi/89m/8ShP8eiv8ukv8BfP////+bBSPRAAAAB3RSTlNJ0v5I0f3TQCa6"
		"oQAAAAFiS0dESPAC1OoAAAAHdElNRQfjBQsVIRNRKf5bAAAAk0lEQVQY02NgYGRihwMmRmYGRnYU"
		"wMLAiirAysCOBigV4IAKcHJxc3BwcfPw8vGDBTgEBIWERUTFxCUkpaRBAjwysnLyCooySsoqqpxA"
		"AW41dQ1NLW0dXT19A0MOdgYOI2MTUzNzAQtLKzNza252BlYbWyM7ewdHJ2cXDlc3d1ag5zg4OIAW"
		"cvAAMQfQcwxsqN4HANirD5vH/S79AAAAJXRFWHRkYXRlOmNyZWF0ZQAyMDE5LTA1LTExVDIxOjMz"
		"OjE5KzAyOjAwfkCHiwAAACV0RVh0ZGF0ZTptb2RpZnkAMjAxOS0wNS0xMVQyMTozMzoxOSswMjow"
		"MA8dPzcAAABXelRYdFJhdyBwcm9maWxlIHR5cGUgaXB0YwAAeJzj8gwIcVYoKMpPy8xJ5VIAAyML"
		"LmMLEyMTS5MUAxMgRIA0w2QDI7NUIMvY1MjEzMQcxAfLgEigSi4A6hcRdPJCNZUAAAAASUVORK5C"
		"YII=";


	const char *cssStyles =
		"<style>\r\n"
		"  body { font: 100%/1.5em sans-serif; margin: 0; padding: 1.5em; background: #fff; color: #000; }\r\n"
		"  a, .slide label { text-decoration: none; color: #000; }\r\n"
		"  a:hover, .slide label:hover { color: #fff; background: #000; }\r\n"
		"  .header { font-size: 2.5em; text-align: center; margin: 1.5em 0; color: #000; }\r\n"
		"  .wrapper { margin: 0 auto; padding: 1em; max-width: 60em; }\r\n"
		"  .left  { float: left; position: absolute; }\r\n"
		"  .right { float: left; font-size: 1em; margin-left: 13em; max-width: 46em; overflow: auto; }\r\n"
		"  .tunnel.established { color: #56b734; }\r\n"
		"  .tunnel.expiring    { color: #d3ae3f; }\r\n"
		"  .tunnel.failed      { color: #d33f3f; }\r\n"
		"  .tunnel.building    { color: #434343; }\r\n"
		"  caption { font-size: 1.5em; text-align: center; color: #000; }\r\n"
		"  table { width: 100%; border-collapse: collapse; text-align: center; }\r\n"
		"  .slide p, .slide [type='checkbox']{ display:none; }\r\n"
		"  .slide [type='checkbox']:checked ~ p { display:block; margin-top: 0; padding: 0; }\r\n"
		"  .disabled:after { color: #d33f3f; content: \"Disabled\" }\r\n"
		"  .enabled:after  { color: #56b734; content: \"Enabled\"  }\r\n"
		"</style>\r\n";

	const char HTTP_PAGE_TUNNELS[] = "tunnels";
	const char HTTP_PAGE_TRANSIT_TUNNELS[] = "transit_tunnels";
	const char HTTP_PAGE_TRANSPORTS[] = "transports";
	const char HTTP_PAGE_LOCAL_DESTINATIONS[] = "local_destinations";
	const char HTTP_PAGE_LOCAL_DESTINATION[] = "local_destination";
	const char HTTP_PAGE_DNCP_LOCAL_DESTINATION[] = "dncp_local_destination";
	const char HTTP_PAGE_SAM_SESSIONS[] = "sam_sessions";
	const char HTTP_PAGE_SAM_SESSION[] = "sam_session";
	const char HTTP_PAGE_DOTNET_TUNNELS[] = "dotnet_tunnels";
	const char HTTP_PAGE_COMMANDS[] = "commands";
	const char HTTP_PAGE_LEASESETS[] = "leasesets";
	const char HTTP_COMMAND_ENABLE_TRANSIT[] = "enable_transit";
	const char HTTP_COMMAND_DISABLE_TRANSIT[] = "disable_transit";
	const char HTTP_COMMAND_SHUTDOWN_START[] = "shutdown_start";
	const char HTTP_COMMAND_SHUTDOWN_CANCEL[] = "shutdown_cancel";
	const char HTTP_COMMAND_SHUTDOWN_NOW[] = "terminate";
	const char HTTP_COMMAND_RUN_PEER_TEST[] = "run_peer_test";
	const char HTTP_COMMAND_RELOAD_CONFIG[] = "reload_config";
	const char HTTP_COMMAND_LOGLEVEL[] = "set_loglevel";
	const char HTTP_PARAM_SAM_SESSION_ID[] = "id";
	const char HTTP_PARAM_ADDRESS[] = "address";

	static std::string ConvertTime (uint64_t time);

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

	static void ShowTunnelDetails (std::stringstream& s, enum dotnet::tunnel::TunnelState eState, bool explr, int bytes)
	{
		std::string state;
		switch (eState) {
			case dotnet::tunnel::eTunnelStateBuildReplyReceived :
			case dotnet::tunnel::eTunnelStatePending     : state = "building"; break;
			case dotnet::tunnel::eTunnelStateBuildFailed :
			case dotnet::tunnel::eTunnelStateTestFailed  :
			case dotnet::tunnel::eTunnelStateFailed      : state = "failed";   break;
			case dotnet::tunnel::eTunnelStateExpiring    : state = "expiring"; break;
			case dotnet::tunnel::eTunnelStateEstablished : state = "established"; break;
			default: state = "unknown"; break;
		}
		s << "<span class=\"tunnel " << state << "\"> " << state << ((explr) ? " (exploratory)" : "") << "</span>, ";
		s << " " << (int) (bytes / 1024) << "&nbsp;KiB<br>\r\n";
	}

	static void SetLogLevel (const std::string& level)
	{
		if (level == "none" || level == "error" || level == "warn" || level == "info" || level == "debug")
			dotnet::log::Logger().SetLogLevel(level);
		else {
			LogPrint(eLogError, "HTTPServer: unknown loglevel set attempted");
			return;
		}
		dotnet::log::Logger().Reopen ();
	}

	static void ShowPageHead (std::stringstream& s)
	{
		std::string webroot;
		dotnet::config::GetOption("http.webroot", webroot);
		s <<
			"<!DOCTYPE html>\r\n"
			"<html lang=\"en\">\r\n" /* TODO: Add support for locale */
			"  <head>\r\n" /* TODO: Find something to parse html/template system. This is horrible. */
#if (!defined(WIN32))
			"  <meta charset=\"UTF-8\">\r\n"
#else
			"  <meta charset=\"windows-1251\">\r\n"
#endif
			"  <link rel=\"shortcut icon\" href=\"" << dotnetFavicon << "\">\r\n"
			"  <title>Purple DOTNET " VERSION " Webconsole</title>\r\n"
			<< cssStyles <<
			"</head>\r\n";
		s <<
			"<body>\r\n"
			"<div class=header><b>dotnet</b> webconsole</div>\r\n"
			"<div class=wrapper>\r\n"
			"<div class=left>\r\n"
			"  <a href=\"" << webroot << "\">Main page</a><br>\r\n<br>\r\n"
			"  <a href=\"" << webroot << "?page=" << HTTP_PAGE_COMMANDS << "\">Router commands</a><br>\r\n"
			"  <a href=\"" << webroot << "?page=" << HTTP_PAGE_LOCAL_DESTINATIONS << "\">Local destinations</a><br>\r\n"
			"  <a href=\"" << webroot << "?page=" << HTTP_PAGE_LEASESETS << "\">LeaseSets</a><br>\r\n"
			"  <a href=\"" << webroot << "?page=" << HTTP_PAGE_TUNNELS << "\">Tunnels</a><br>\r\n"
			"  <a href=\"" << webroot << "?page=" << HTTP_PAGE_TRANSIT_TUNNELS << "\">Transit tunnels</a><br>\r\n"
			"  <a href=\"" << webroot << "?page=" << HTTP_PAGE_TRANSPORTS << "\">Transports</a><br>\r\n"
			"  <a href=\"" << webroot << "?page=" << HTTP_PAGE_DOTNET_TUNNELS << "\">DOTNET tunnels</a><br>\r\n";
		if (dotnet::client::context.GetSAMBridge ())
			s << "  <a href=\"" << webroot << "?page=" << HTTP_PAGE_SAM_SESSIONS << "\">SAM sessions</a><br>\r\n";
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

    void ShowStatus (
            std::stringstream& s,
            bool includeHiddenContent,
            dotnet::http::OutputFormatEnum outputFormat)
	{
		s << "<b>Uptime:</b> ";
		ShowUptime(s, dotnet::context.GetUptime ());
		s << "<br>\r\n";
		s << "<b>Network status:</b> ";
		switch (dotnet::context.GetStatus ())
		{
			case eRouterStatusOK: s << "OK"; break;
			case eRouterStatusTesting: s << "Testing"; break;
			case eRouterStatusFirewalled: s << "Firewalled"; break;
			case eRouterStatusError:
			{
				s << "Error";
				switch (dotnet::context.GetError ())
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
#if ((!defined(WIN32) && !defined(QT_GUI_LIB) && !defined(ANDROID)) || defined(ANDROID_BINARY))
		if (auto remains = Daemon.gracefulShutdownInterval) {
			s << "<b>Stopping in:</b> ";
			s << remains << " seconds";
			s << "<br>\r\n";
		}
#endif
		auto family = dotnet::context.GetFamily ();
		if (family.length () > 0)
			s << "<b>Family:</b> " << family << "<br>\r\n";
		s << "<b>Tunnel creation success rate:</b> " << dotnet::tunnel::tunnels.GetTunnelCreationSuccessRate () << "%<br>\r\n";
		s << "<b>Received:</b> ";
		ShowTraffic (s, dotnet::transport::transports.GetTotalReceivedBytes ());
		s << " (" << (double) dotnet::transport::transports.GetInBandwidth () / 1024 << " KiB/s)<br>\r\n";
		s << "<b>Sent:</b> ";
		ShowTraffic (s, dotnet::transport::transports.GetTotalSentBytes ());
		s << " (" << (double) dotnet::transport::transports.GetOutBandwidth () / 1024 << " KiB/s)<br>\r\n";
		s << "<b>Transit:</b> ";
		ShowTraffic (s, dotnet::transport::transports.GetTotalTransitTransmittedBytes ());
		s << " (" << (double) dotnet::transport::transports.GetTransitBandwidth () / 1024 << " KiB/s)<br>\r\n";
		s << "<b>Data path:</b> " << dotnet::fs::GetDataDir() << "<br>\r\n";
        s << "<div class='slide'>";
        if((outputFormat==OutputFormatEnum::forWebConsole)||!includeHiddenContent) {
            s << "<label for='slide-info'>Hidden content. Press on text to see.</label>\r\n<input type='checkbox' id='slide-info'/>\r\n<p class='content'>\r\n";
        }
        if(includeHiddenContent) {
            s << "<b>Router Ident:</b> " << dotnet::context.GetRouterInfo().GetIdentHashBase64() << "<br>\r\n";
			s << "<b>Router Family:</b> " << dotnet::context.GetRouterInfo().GetProperty("family") << "<br>\r\n";
			s << "<b>Router Caps:</b> " << dotnet::context.GetRouterInfo().GetProperty("caps") << "<br>\r\n";
			s << "<b>Our external address:</b>" << "<br>\r\n" ;
			for (const auto& address : dotnet::context.GetRouterInfo().GetAddresses())
			{
				if (address->IsNTCP2 () && !address->IsPublishedNTCP2 ())
				{
					s << "NTCP2";
					if (address->host.is_v6 ()) s << "v6";
					s << "&nbsp;&nbsp; supported <br>\r\n";
					continue;
				}
				switch (address->transportStyle)
				{
					case dotnet::data::RouterInfo::eTransportNTCP:
					{
						s << "NTCP";
						if (address->IsPublishedNTCP2 ()) s << "2";
						if (address->host.is_v6 ()) s << "v6";
						s << "&nbsp;&nbsp;";
						break;
					}
					case dotnet::data::RouterInfo::eTransportSSU:
						if (address->host.is_v6 ())
							s << "SSUv6&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;";
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
        if(outputFormat==OutputFormatEnum::forQtUi) {
            s << "<br>";
        }
        s << "<b>Routers:</b> " << dotnet::data::netdb.GetNumRouters () << " ";
		s << "<b>Floodfills:</b> " << dotnet::data::netdb.GetNumFloodfills () << " ";
		s << "<b>LeaseSets:</b> " << dotnet::data::netdb.GetNumLeaseSets () << "<br>\r\n";

		size_t clientTunnelCount = dotnet::tunnel::tunnels.CountOutboundTunnels();
		clientTunnelCount += dotnet::tunnel::tunnels.CountInboundTunnels();
		size_t transitTunnelCount = dotnet::tunnel::tunnels.CountTransitTunnels();

		s << "<b>Client Tunnels:</b> " << std::to_string(clientTunnelCount) << " ";
		s << "<b>Transit Tunnels:</b> " << std::to_string(transitTunnelCount) << "<br>\r\n<br>\r\n";

        if(outputFormat==OutputFormatEnum::forWebConsole) {
            s << "<table><caption>Services</caption><tr><th>Service</th><th>State</th></tr>\r\n";
            s << "<tr><td>" << "HTTP Proxy"		<< "</td><td><div class='" << ((dotnet::client::context.GetHttpProxy ())			? "enabled" : "disabled") << "'></div></td></tr>\r\n";
            s << "<tr><td>" << "SOCKS Proxy"	<< "</td><td><div class='" << ((dotnet::client::context.GetSocksProxy ())			? "enabled" : "disabled") << "'></div></td></tr>\r\n";
            s << "<tr><td>" << "BOB"			<< "</td><td><div class='" << ((dotnet::client::context.GetBOBCommandChannel ())	? "enabled" : "disabled") << "'></div></td></tr>\r\n";
            s << "<tr><td>" << "SAM"			<< "</td><td><div class='" << ((dotnet::client::context.GetSAMBridge ())			? "enabled" : "disabled") << "'></div></td></tr>\r\n";
            s << "<tr><td>" << "DNCP"			<< "</td><td><div class='" << ((dotnet::client::context.GetDNCPServer ())			? "enabled" : "disabled") << "'></div></td></tr>\r\n";
            bool dotnetcontrol; dotnet::config::GetOption("dotnetcontrol.enabled", dotnetcontrol);
            s << "<tr><td>" << "DotNetControl"		<< "</td><td><div class='" << ((dotnetcontrol) 									? "enabled" : "disabled") << "'></div></td></tr>\r\n";
            s << "</table>\r\n";
        }
	}

	void ShowLocalDestinations (std::stringstream& s)
	{
		std::string webroot; dotnet::config::GetOption("http.webroot", webroot);
		s << "<b>Local Destinations:</b><br>\r\n<br>\r\n";
		for (auto& it: dotnet::client::context.GetDestinations ())
		{
			auto ident = it.second->GetIdentHash ();
			s << "<a href=\"" << webroot << "?page=" << HTTP_PAGE_LOCAL_DESTINATION << "&b32=" << ident.ToBase32 () << "\">";
			s << dotnet::client::context.GetAddressBook ().ToAddress(ident) << "</a><br>\r\n" << std::endl;
		}

		auto dncpServer = dotnet::client::context.GetDNCPServer ();
		if (dncpServer && !(dncpServer->GetSessions ().empty ()))
		{
			s << "<br><b>DNCP Local Destinations:</b><br>\r\n<br>\r\n";
			for (auto& it: dncpServer->GetSessions ())
			{
				auto dest = it.second->GetDestination ();
				if (dest)
				{
					auto ident = dest->GetIdentHash ();
					auto& name = dest->GetNickname ();
					s << "<a href=\"" << webroot << "?page=" << HTTP_PAGE_DNCP_LOCAL_DESTINATION << "&dncp_id=" << it.first << "\">[ ";
					s << name << " ]</a> &#8660; " << dotnet::client::context.GetAddressBook ().ToAddress(ident) <<"<br>\r\n" << std::endl;
				}
			}
		}
	}

	static void ShowLeaseSetDestination (std::stringstream& s, std::shared_ptr<const dotnet::client::LeaseSetDestination> dest)
	{
		s << "<b>Base64:</b><br>\r\n<textarea readonly=\"readonly\" cols=\"64\" rows=\"11\" wrap=\"on\">";
		s << dest->GetIdentity ()->ToBase64 () << "</textarea><br>\r\n<br>\r\n";
		if(dest->GetNumRemoteLeaseSets())
		{
			s << "<div class='slide'><label for='slide-lease'><b>LeaseSets:</b> <i>" << dest->GetNumRemoteLeaseSets () << "</i></label>\r\n<input type='checkbox' id='slide-lease'/>\r\n<p class='content'>\r\n";
			for(auto& it: dest->GetLeaseSets ())
				s << it.first.ToBase32 () << " " << (int)it.second->GetStoreType () << "<br>\r\n";
			s << "</p>\r\n</div>\r\n";
		} else
			s << "<b>LeaseSets:</b> <i>0</i><br>\r\n";
		auto pool = dest->GetTunnelPool ();
		if (pool)
		{
			s << "<b>Inbound tunnels:</b><br>\r\n";
			for (auto & it : pool->GetInboundTunnels ()) {
				it->Print(s);
				if(it->LatencyIsKnown())
					s << " ( " << it->GetMeanLatency() << "ms )";
				ShowTunnelDetails(s, it->GetState (), false, it->GetNumReceivedBytes ());
			}
			s << "<br>\r\n";
			s << "<b>Outbound tunnels:</b><br>\r\n";
			for (auto & it : pool->GetOutboundTunnels ()) {
				it->Print(s);
				if(it->LatencyIsKnown())
					s << " ( " << it->GetMeanLatency() << "ms )";
				ShowTunnelDetails(s, it->GetState (), false, it->GetNumSentBytes ());
			}
		}
		s << "<br>\r\n";
		s << "<b>Tags</b><br>Incoming: <i>" << dest->GetNumIncomingTags () << "</i><br>";
		if (!dest->GetSessions ().empty ()) {
			std::stringstream tmp_s; uint32_t out_tags = 0;
			for (const auto& it: dest->GetSessions ()) {
				tmp_s << dotnet::client::context.GetAddressBook ().ToAddress(it.first) << " " << it.second->GetNumOutgoingTags () << "<br>\r\n";
				out_tags = out_tags + it.second->GetNumOutgoingTags ();
			}
			s << "<div class='slide'><label for='slide-tags'>Outgoing: <i>" << out_tags << "</i></label>\r\n<input type='checkbox' id='slide-tags'/>\r\n<p class='content'>\r\n" << tmp_s.str () << "</p>\r\n</div>\r\n";
		} else
			s << "Outgoing: <i>0</i><br>\r\n";
		s << "<br>\r\n";
	}

	void ShowLocalDestination (std::stringstream& s, const std::string& b32)
	{
		s << "<b>Local Destination:</b><br>\r\n<br>\r\n";
		dotnet::data::IdentHash ident;
		ident.FromBase32 (b32);
		auto dest = dotnet::client::context.FindLocalDestination (ident);
		if (dest)
		{
			ShowLeaseSetDestination (s, dest);
			// show streams
			s << "<table><caption>Streams</caption>\r\n<tr>";
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
			s << "</tr>\r\n";

			for (const auto& it: dest->GetAllStreams ())
			{
				s << "<tr>";
				s << "<td>" << it->GetSendStreamID () << "</td>";
				s << "<td>" << dotnet::client::context.GetAddressBook ().ToAddress(it->GetRemoteIdentity ()) << "</td>";
				s << "<td>" << it->GetNumSentBytes () << "</td>";
				s << "<td>" << it->GetNumReceivedBytes () << "</td>";
				s << "<td>" << it->GetSendQueueSize () << "</td>";
				s << "<td>" << it->GetReceiveQueueSize () << "</td>";
				s << "<td>" << it->GetSendBufferSize () << "</td>";
				s << "<td>" << it->GetRTT () << "</td>";
				s << "<td>" << it->GetWindowSize () << "</td>";
				s << "<td>" << (int)it->GetStatus () << "</td>";
				s << "</tr>\r\n";
			}
			s << "</table>";
		}
	}

	static void ShowDNCPLocalDestination (std::stringstream& s, const std::string& id)
	{
		auto dncpServer = dotnet::client::context.GetDNCPServer ();
		if (dncpServer)
		{
			s << "<b>DNCP Local Destination:</b><br>\r\n<br>\r\n";
			auto it = dncpServer->GetSessions ().find (std::stoi (id));
			if (it != dncpServer->GetSessions ().end ())
				ShowLeaseSetDestination (s, it->second->GetDestination ());
			else
				ShowError(s, "DNCP session not found");
		}
		else
			ShowError(s, "DNCP is not enabled");
	}

	void ShowLeasesSets(std::stringstream& s)
	{
		s << "<b>LeaseSets:</b><br>\r\n<br>\r\n";
		int counter = 1;
		// for each lease set
		dotnet::data::netdb.VisitLeaseSets(
			[&s, &counter](const dotnet::data::IdentHash dest, std::shared_ptr<dotnet::data::LeaseSet> leaseSet)
			{
				// create copy of lease set so we extract leases
				auto storeType = leaseSet->GetStoreType ();
				std::unique_ptr<dotnet::data::LeaseSet> ls;
				if (storeType == dotnet::data::NETDB_STORE_TYPE_LEASESET)
					ls.reset (new dotnet::data::LeaseSet (leaseSet->GetBuffer(), leaseSet->GetBufferLen()));
				else
					ls.reset (new dotnet::data::LeaseSet2 (storeType, leaseSet->GetBuffer(), leaseSet->GetBufferLen()));
				if (!ls) return;
				s << "<div class='leaseset";
				if (ls->IsExpired())
					s << " expired"; // additional css class for expired
				s << "'>\r\n";
				if (!ls->IsValid())
					s << "<div class='invalid'>!! Invalid !! </div>\r\n";
				s << "<div class='slide'><label for='slide" << counter << "'>" << dest.ToBase32() << "</label>\r\n";
				s << "<input type='checkbox' id='slide" << (counter++) << "'/>\r\n<p class='content'>\r\n";
				s << "<b>Store type:</b> " << (int)storeType << "<br>\r\n";
				s << "<b>Expires:</b> " << ConvertTime(ls->GetExpirationTime()) << "<br>\r\n";
				if (storeType == dotnet::data::NETDB_STORE_TYPE_LEASESET || storeType == dotnet::data::NETDB_STORE_TYPE_STANDARD_LEASESET2)
				{	
					// leases information is available
					auto leases = ls->GetNonExpiredLeases();
					s << "<b>Non Expired Leases: " << leases.size() << "</b><br>\r\n";
					for ( auto & l : leases )
					{
						s << "<b>Gateway:</b> " << l->tunnelGateway.ToBase64() << "<br>\r\n";
						s << "<b>TunnelID:</b> " << l->tunnelID << "<br>\r\n";
						s << "<b>EndDate:</b> " << ConvertTime(l->endDate) << "<br>\r\n";
					}
				}	
				s << "</p>\r\n</div>\r\n</div>\r\n";
			}
		);
		// end for each lease set
	}

	void ShowTunnels (std::stringstream& s)
	{
		s << "<b>Tunnels:</b><br>\r\n<br>\r\n";
		s << "<b>Queue size:</b> " << dotnet::tunnel::tunnels.GetQueueSize () << "<br>\r\n";

		auto ExplPool = dotnet::tunnel::tunnels.GetExploratoryPool ();

		s << "<b>Inbound tunnels:</b><br>\r\n";
		for (auto & it : dotnet::tunnel::tunnels.GetInboundTunnels ()) {
			it->Print(s);
			if(it->LatencyIsKnown())
				s << " ( " << it->GetMeanLatency() << "ms )";
			ShowTunnelDetails(s, it->GetState (), (it->GetTunnelPool () == ExplPool), it->GetNumReceivedBytes ());
		}
		s << "<br>\r\n";
		s << "<b>Outbound tunnels:</b><br>\r\n";
		for (auto & it : dotnet::tunnel::tunnels.GetOutboundTunnels ()) {
			it->Print(s);
			if(it->LatencyIsKnown())
				s << " ( " << it->GetMeanLatency() << "ms )";
			ShowTunnelDetails(s, it->GetState (), (it->GetTunnelPool () == ExplPool), it->GetNumSentBytes ());
		}
		s << "<br>\r\n";
	}

	static void ShowCommands (std::stringstream& s, uint32_t token)
	{
		std::string webroot; dotnet::config::GetOption("http.webroot", webroot);
		/* commands */
		s << "<b>Router Commands</b><br>\r\n<br>\r\n";
		s << "  <a href=\"" << webroot << "?cmd=" << HTTP_COMMAND_RUN_PEER_TEST << "&token=" << token << "\">Run peer test</a><br>\r\n";
		//s << "  <a href=\"/?cmd=" << HTTP_COMMAND_RELOAD_CONFIG << "\">Reload config</a><br>\r\n";
		if (dotnet::context.AcceptsTunnels ())
			s << "  <a href=\"" << webroot << "?cmd=" << HTTP_COMMAND_DISABLE_TRANSIT << "&token=" << token << "\">Decline transit tunnels</a><br>\r\n";
		else
			s << "  <a href=\"" << webroot << "?cmd=" << HTTP_COMMAND_ENABLE_TRANSIT << "&token=" << token << "\">Accept transit tunnels</a><br>\r\n";
#if ((!defined(WIN32) && !defined(QT_GUI_LIB) && !defined(ANDROID)) || defined(ANDROID_BINARY))
		if (Daemon.gracefulShutdownInterval)
			s << "  <a href=\"" << webroot << "?cmd=" << HTTP_COMMAND_SHUTDOWN_CANCEL << "&token=" << token << "\">Cancel graceful shutdown</a><br>";
		else
			s << "  <a href=\"" << webroot << "?cmd=" << HTTP_COMMAND_SHUTDOWN_START << "&token=" << token << "\">Start graceful shutdown</a><br>\r\n";
#elif defined(WIN32_APP)
		if (dotnet::util::DaemonWin32::Instance().isGraceful)
			s << "  <a href=\"" << webroot << "?cmd=" << HTTP_COMMAND_SHUTDOWN_CANCEL << "&token=" << token << "\">Cancel graceful shutdown</a><br>";
		else
			s << "  <a href=\"" << webroot << "?cmd=" << HTTP_COMMAND_SHUTDOWN_START << "&token=" << token << "\">Graceful shutdown</a><br>\r\n";
#endif
		s << "  <a href=\"" << webroot << "?cmd=" << HTTP_COMMAND_SHUTDOWN_NOW << "&token=" << token << "\">Force shutdown</a><br>\r\n";

		s << "<br>\r\n<b>Logging level</b><br>\r\n";
		s << "  <a href=\"" << webroot << "?cmd=" << HTTP_COMMAND_LOGLEVEL << "&level=none&token=" << token << "\">[none]</a> ";
		s << "  <a href=\"" << webroot << "?cmd=" << HTTP_COMMAND_LOGLEVEL << "&level=error&token=" << token << "\">[error]</a> ";
		s << "  <a href=\"" << webroot << "?cmd=" << HTTP_COMMAND_LOGLEVEL << "&level=warn&token=" << token << "\">[warn]</a> ";
		s << "  <a href=\"" << webroot << "?cmd=" << HTTP_COMMAND_LOGLEVEL << "&level=info&token=" << token << "\">[info]</a> ";
		s << "  <a href=\"" << webroot << "?cmd=" << HTTP_COMMAND_LOGLEVEL << "&level=debug&token=" << token << "\">[debug]</a><br>\r\n";
	}

	void ShowTransitTunnels (std::stringstream& s)
	{
		s << "<b>Transit tunnels:</b><br>\r\n<br>\r\n";
		for (const auto& it: dotnet::tunnel::tunnels.GetTransitTunnels ())
		{
			if (std::dynamic_pointer_cast<dotnet::tunnel::TransitTunnelGateway>(it))
				s << it->GetTunnelID () << " &#8658; ";
			else if (std::dynamic_pointer_cast<dotnet::tunnel::TransitTunnelEndpoint>(it))
				s << " &#8658; " << it->GetTunnelID ();
			else
				s << " &#8658; " << it->GetTunnelID () << " &#8658; ";
			s << " " << it->GetNumTransmittedBytes () << "<br>\r\n";
		}
	}

	template<typename Sessions>
	static void ShowNTCPTransports (std::stringstream& s, const Sessions& sessions, const std::string name)
	{
		std::stringstream tmp_s, tmp_s6; uint16_t cnt = 0, cnt6 = 0;
		for (const auto& it: sessions )
		{
			if (it.second && it.second->IsEstablished () && !it.second->GetSocket ().remote_endpoint ().address ().is_v6 ())
			{
				// incoming connection doesn't have remote RI
				if (it.second->IsOutgoing ()) tmp_s << " &#8658; ";
				tmp_s << dotnet::data::GetIdentHashAbbreviation (it.second->GetRemoteIdentity ()->GetIdentHash ()) << ": "
					<< it.second->GetSocket ().remote_endpoint().address ().to_string ();
				if (!it.second->IsOutgoing ()) tmp_s << " &#8658; ";
				tmp_s << " [" << it.second->GetNumSentBytes () << ":" << it.second->GetNumReceivedBytes () << "]";
				tmp_s << "<br>\r\n" << std::endl;
				cnt++;
			}
			if (it.second && it.second->IsEstablished () && it.second->GetSocket ().remote_endpoint ().address ().is_v6 ())
			{
				if (it.second->IsOutgoing ()) tmp_s6 << " &#8658; ";
				tmp_s6 << dotnet::data::GetIdentHashAbbreviation (it.second->GetRemoteIdentity ()->GetIdentHash ()) << ": "
					<< "[" << it.second->GetSocket ().remote_endpoint().address ().to_string () << "]";
				if (!it.second->IsOutgoing ()) tmp_s6 << " &#8658; ";
				tmp_s6 << " [" << it.second->GetNumSentBytes () << ":" << it.second->GetNumReceivedBytes () << "]";
				tmp_s6 << "<br>\r\n" << std::endl;
				cnt6++;
			}
		}
		if (!tmp_s.str ().empty ())
		{
			s << "<div class='slide'><label for='slide_" << boost::algorithm::to_lower_copy(name) << "'><b>" << name << "</b> ( " << cnt << " )</label>\r\n<input type='checkbox' id='slide_" << boost::algorithm::to_lower_copy(name) << "'/>\r\n<p class='content'>";
			s << tmp_s.str () << "</p>\r\n</div>\r\n";
		}
		if (!tmp_s6.str ().empty ())
		{
			s << "<div class='slide'><label for='slide_" << boost::algorithm::to_lower_copy(name) << "v6'><b>" << name << "v6</b> ( " << cnt6 << " )</label>\r\n<input type='checkbox' id='slide_" << boost::algorithm::to_lower_copy(name) << "v6'/>\r\n<p class='content'>";
			s << tmp_s6.str () << "</p>\r\n</div>\r\n";
		}
	}

	void ShowTransports (std::stringstream& s)
	{
		s << "<b>Transports:</b><br>\r\n<br>\r\n";
		auto ntcpServer = dotnet::transport::transports.GetNTCPServer ();
		if (ntcpServer)
		{
			auto sessions = ntcpServer->GetNTCPSessions ();
			if (!sessions.empty ())
				ShowNTCPTransports (s, sessions, "NTCP");
		}
		auto ntcp2Server = dotnet::transport::transports.GetNTCP2Server ();
		if (ntcp2Server)
		{
			auto sessions = ntcp2Server->GetNTCP2Sessions ();
			if (!sessions.empty ())
				ShowNTCPTransports (s, sessions, "NTCP2");
		}
		auto ssuServer = dotnet::transport::transports.GetSSUServer ();
		if (ssuServer)
		{
			auto sessions = ssuServer->GetSessions ();
			if (!sessions.empty ())
			{
				s << "<div class='slide'><label for='slide_ssu'><b>SSU</b> ( " << (int) sessions.size() << " )</label>\r\n<input type='checkbox' id='slide_ssu'/>\r\n<p class='content'>";
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
				s << "</p>\r\n</div>\r\n";
			}
			auto sessions6 = ssuServer->GetSessionsV6 ();
			if (!sessions6.empty ())
			{
				s << "<div class='slide'><label for='slide_ssuv6'><b>SSUv6</b> ( " << (int) sessions6.size() << " )</label>\r\n<input type='checkbox' id='slide_ssuv6'/>\r\n<p class='content'>";
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
				s << "</p>\r\n</div>\r\n";
			}
		}
	}

	void ShowSAMSessions (std::stringstream& s)
	{
		std::string webroot; dotnet::config::GetOption("http.webroot", webroot);
		auto sam = dotnet::client::context.GetSAMBridge ();
		if (!sam) {
			ShowError(s, "SAM disabled");
			return;
		}
		s << "<b>SAM Sessions:</b><br>\r\n<br>\r\n";
		for (auto& it: sam->GetSessions ())
		{
			auto& name = it.second->localDestination->GetNickname ();
			s << "<a href=\"" << webroot << "?page=" << HTTP_PAGE_SAM_SESSION << "&sam_id=" << it.first << "\">";
			s << name << " (" << it.first << ")</a><br>\r\n" << std::endl;
		}
	}

	static void ShowSAMSession (std::stringstream& s, const std::string& id)
	{
		std::string webroot; dotnet::config::GetOption("http.webroot", webroot);
		s << "<b>SAM Session:</b><br>\r\n<br>\r\n";
		auto sam = dotnet::client::context.GetSAMBridge ();
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
		s << "<a href=\"" << webroot << "?page=" << HTTP_PAGE_LOCAL_DESTINATION << "&b32=" << ident.ToBase32 () << "\">";
		s << dotnet::client::context.GetAddressBook ().ToAddress(ident) << "</a><br>\r\n";
		s << "<br>\r\n";
		s << "<b>Streams:</b><br>\r\n";
		for (const auto& it: sam->ListSockets(id))
		{
			switch (it->GetSocketType ())
			{
				case dotnet::client::eSAMSocketTypeSession  : s << "session";  break;
				case dotnet::client::eSAMSocketTypeStream   : s << "stream";   break;
				case dotnet::client::eSAMSocketTypeAcceptor : s << "acceptor"; break;
				default: s << "unknown"; break;
			}
			s << " [" << it->GetSocket ().remote_endpoint() << "]";
			s << "<br>\r\n";
		}
	}

	void ShowDotNetTunnels (std::stringstream& s)
	{
		std::string webroot; dotnet::config::GetOption("http.webroot", webroot);
		s << "<b>Client Tunnels:</b><br>\r\n<br>\r\n";
		for (auto& it: dotnet::client::context.GetClientTunnels ())
		{
			auto& ident = it.second->GetLocalDestination ()->GetIdentHash();
			s << "<a href=\"" << webroot << "?page=" << HTTP_PAGE_LOCAL_DESTINATION << "&b32=" << ident.ToBase32 () << "\">";
			s << it.second->GetName () << "</a> &#8656; ";
			s << dotnet::client::context.GetAddressBook ().ToAddress(ident);
			s << "<br>\r\n"<< std::endl;
		}
		auto httpProxy = dotnet::client::context.GetHttpProxy ();
		if (httpProxy)
		{
			auto& ident = httpProxy->GetLocalDestination ()->GetIdentHash();
			s << "<a href=\"" << webroot << "?page=" << HTTP_PAGE_LOCAL_DESTINATION << "&b32=" << ident.ToBase32 () << "\">";
			s << "HTTP Proxy" << "</a> &#8656; ";
			s << dotnet::client::context.GetAddressBook ().ToAddress(ident);
			s << "<br>\r\n"<< std::endl;
		}
		auto socksProxy = dotnet::client::context.GetSocksProxy ();
		if (socksProxy)
		{
			auto& ident = socksProxy->GetLocalDestination ()->GetIdentHash();
			s << "<a href=\"" << webroot << "?page=" << HTTP_PAGE_LOCAL_DESTINATION << "&b32=" << ident.ToBase32 () << "\">";
			s << "SOCKS Proxy" << "</a> &#8656; ";
			s << dotnet::client::context.GetAddressBook ().ToAddress(ident);
			s << "<br>\r\n"<< std::endl;
		}
		auto& serverTunnels = dotnet::client::context.GetServerTunnels ();
		if (!serverTunnels.empty ()) {
			s << "<br>\r\n<b>Server Tunnels:</b><br>\r\n<br>\r\n";
			for (auto& it: serverTunnels)
			{
				auto& ident = it.second->GetLocalDestination ()->GetIdentHash();
				s << "<a href=\"" << webroot << "?page=" << HTTP_PAGE_LOCAL_DESTINATION << "&b32=" << ident.ToBase32 () << "\">";
				s << it.second->GetName () << "</a> &#8658; ";
				s << dotnet::client::context.GetAddressBook ().ToAddress(ident);
				s << ":" << it.second->GetLocalPort ();
				s << "</a><br>\r\n"<< std::endl;
			}
		}
		auto& clientForwards = dotnet::client::context.GetClientForwards ();
		if (!clientForwards.empty ())
		{
			s << "<br>\r\n<b>Client Forwards:</b><br>\r\n<br>\r\n";
			for (auto& it: clientForwards)
			{
				auto& ident = it.second->GetLocalDestination ()->GetIdentHash();
				s << "<a href=\"" << webroot << "?page=" << HTTP_PAGE_LOCAL_DESTINATION << "&b32=" << ident.ToBase32 () << "\">";
				s << it.second->GetName () << "</a> &#8656; ";
				s << dotnet::client::context.GetAddressBook ().ToAddress(ident);
				s << "<br>\r\n"<< std::endl;
			}
		}
		auto& serverForwards = dotnet::client::context.GetServerForwards ();
		if (!serverForwards.empty ())
		{
			s << "<br>\r\n<b>Server Forwards:</b><br>\r\n<br>\r\n";
			for (auto& it: serverForwards)
			{
				auto& ident = it.second->GetLocalDestination ()->GetIdentHash();
				s << "<a href=\"" << webroot << "?page=" << HTTP_PAGE_LOCAL_DESTINATION << "&b32=" << ident.ToBase32 () << "\">";
				s << it.second->GetName () << "</a> &#8656; ";
				s << dotnet::client::context.GetAddressBook ().ToAddress(ident);
				s << "<br>\r\n"<< std::endl;
			}
		}
	}

	std::string ConvertTime (uint64_t time)
	{
		ldiv_t divTime = ldiv(time,1000);
		time_t t = divTime.quot;
		struct tm *tm = localtime(&t);
		char date[128];
		snprintf(date, sizeof(date), "%02d/%02d/%d %02d:%02d:%02d.%03ld", tm->tm_mday, tm->tm_mon + 1, tm->tm_year + 1900, tm->tm_hour, tm->tm_min, tm->tm_sec, divTime.rem);
		return date;
	}

	HTTPConnection::HTTPConnection (std::string hostname, std::shared_ptr<boost::asio::ip::tcp::socket> socket):
		m_Socket (socket), m_BufferLen (0), expected_host(hostname)
	{
		/* cache options */
		dotnet::config::GetOption("http.auth", needAuth);
		dotnet::config::GetOption("http.user", user);
		dotnet::config::GetOption("http.pass", pass);
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
			std::string expected = "Basic " + dotnet::data::ToBase64Standard (user + ":" + pass);
			if (expected == provided) return true;
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
		bool strictheaders;
		dotnet::config::GetOption("http.strictheaders", strictheaders);
		if (strictheaders)
		{
			std::string http_hostname;
			dotnet::config::GetOption("http.hostname", http_hostname);
			std::string host = req.GetHeader("Host");
			auto idx = host.find(':');
			/* strip out port so it's just host */
			if (idx != std::string::npos && idx > 0)
			{
				host = host.substr(0, idx);
			}
			if (!(host == expected_host || host == http_hostname))
			{
				/* deny request as it's from a non whitelisted hostname */
				res.code = 403;
				content = "host mismatch";
				SendReply(res, content);
				return;
			}
		}
		// Html5 head start
		ShowPageHead (s);
		if (req.uri.find("page=") != std::string::npos) {
			HandlePage (req, res, s);
		} else if (req.uri.find("cmd=") != std::string::npos) {
			HandleCommand (req, res, s);
		} else {
            ShowStatus (s, true, dotnet::http::OutputFormatEnum::forWebConsole);
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
			auto ts = dotnet::util::GetSecondsSinceEpoch ();
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
		else if (page == HTTP_PAGE_DNCP_LOCAL_DESTINATION)
			ShowDNCPLocalDestination (s, params["dncp_id"]);
		else if (page == HTTP_PAGE_SAM_SESSIONS)
			ShowSAMSessions (s);
		else if (page == HTTP_PAGE_SAM_SESSION)
			ShowSAMSession (s, params["sam_id"]);
		else if (page == HTTP_PAGE_DOTNET_TUNNELS)
			ShowDotNetTunnels (s);
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
			dotnet::transport::transports.PeerTest ();
		else if (cmd == HTTP_COMMAND_RELOAD_CONFIG)
			dotnet::client::context.ReloadConfig ();
		else if (cmd == HTTP_COMMAND_ENABLE_TRANSIT)
			dotnet::context.SetAcceptsTunnels (true);
		else if (cmd == HTTP_COMMAND_DISABLE_TRANSIT)
			dotnet::context.SetAcceptsTunnels (false);
		else if (cmd == HTTP_COMMAND_SHUTDOWN_START) {
			dotnet::context.SetAcceptsTunnels (false);
#if ((!defined(WIN32) && !defined(QT_GUI_LIB) && !defined(ANDROID)) || defined(ANDROID_BINARY))
			Daemon.gracefulShutdownInterval = 10*60;
#elif defined(WIN32_APP)
			dotnet::win32::GracefulShutdown ();
#endif
		} else if (cmd == HTTP_COMMAND_SHUTDOWN_CANCEL) {
			dotnet::context.SetAcceptsTunnels (true);
#if ((!defined(WIN32) && !defined(QT_GUI_LIB) && !defined(ANDROID))  || defined(ANDROID_BINARY))
			Daemon.gracefulShutdownInterval = 0;
#elif defined(WIN32_APP)
			dotnet::win32::StopGracefulShutdown ();
#endif
		} else if (cmd == HTTP_COMMAND_SHUTDOWN_NOW) {
#ifndef WIN32_APP
			Daemon.running = false;
#else
			dotnet::win32::StopWin32App ();
#endif
		} else if (cmd == HTTP_COMMAND_LOGLEVEL){
			std::string level = params["level"];
			SetLogLevel (level);
		} else {
			res.code = 400;
			ShowError(s, "Unknown command: " + cmd);
			return;
		}
		std::string webroot; dotnet::config::GetOption("http.webroot", webroot);
		std::string redirect = "5; url=" + webroot + "?page=commands";
		s << "<b>SUCCESS</b>:&nbsp;Command accepted<br><br>\r\n";
		s << "<a href=\"" << webroot << "?page=commands\">Back to commands list</a><br>\r\n";
		s << "<p>You will be redirected in 5 seconds</b>";
		res.add_header("Refresh", redirect.c_str());
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
		m_Acceptor (m_Service, boost::asio::ip::tcp::endpoint (boost::asio::ip::address::from_string(address), port)),
		m_Hostname(address)
	{
	}

	HTTPServer::~HTTPServer ()
	{
		Stop ();
	}

	void HTTPServer::Start ()
	{
		bool needAuth;    dotnet::config::GetOption("http.auth", needAuth);
		std::string user; dotnet::config::GetOption("http.user", user);
		std::string pass; dotnet::config::GetOption("http.pass", pass);
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
			dotnet::config::SetOption("http.pass", pass);
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
		auto conn = std::make_shared<HTTPConnection> (m_Hostname, newSocket);
		conn->Receive ();
	}
} // http
} // dotnet
