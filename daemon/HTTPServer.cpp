/*
* Copyright (c) 2013-2024, The PurpleI2P Project
*
* This file is part of Purple i2pd project and licensed under BSD3
*
* See full license text in LICENSE file at top of project tree
*/

#include <iomanip>
#include <sstream>
#include <thread>
#include <memory>

#include <boost/asio.hpp>
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
#include "ECIESX25519AEADRatchetSession.h"
#include "I18N.h"

#ifdef WIN32_APP
#include "Win32App.h"
#endif

// For image, style and info
#include "version.h"
#include "HTTPServerResources.h"

namespace i2p {
namespace http {
	static void LoadExtCSS ()
	{
		std::stringstream s;
		std::string styleFile = i2p::fs::DataDirPath ("webconsole/style.css");
		if (i2p::fs::Exists(styleFile)) {
			std::ifstream f(styleFile, std::ifstream::binary);
			s << f.rdbuf();
			externalCSS = s.str();
		} else if (externalCSS.length() != 0) { // clean up external style if file was removed
			externalCSS = "";
		}
	}

	static void GetStyles (std::stringstream& s)
	{
		if (externalCSS.length() != 0)
			s << "<style>\r\n" << externalCSS << "</style>\r\n";
		else
			s << internalCSS;
	}

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
	const char HTTP_COMMAND_RELOAD_TUNNELS_CONFIG[] = "reload_tunnels_config";
	const char HTTP_COMMAND_LOGLEVEL[] = "set_loglevel";
	const char HTTP_COMMAND_KILLSTREAM[] = "closestream";
	const char HTTP_COMMAND_LIMITTRANSIT[] = "limittransit";
	const char HTTP_COMMAND_GET_REG_STRING[] = "get_reg_string";
	const char HTTP_COMMAND_SETLANGUAGE[] = "setlanguage";
	const char HTTP_COMMAND_RELOAD_CSS[] = "reload_css";
	const char HTTP_COMMAND_EXPIRELEASE[] = "expirelease";

	static std::string ConvertTime (uint64_t time)
	{
		lldiv_t divTime = lldiv(time, 1000);
		time_t t = divTime.quot;
		struct tm *tm = localtime(&t);
		char date[128];
		snprintf(date, sizeof(date), "%02d/%02d/%d %02d:%02d:%02d.%03lld", tm->tm_mday, tm->tm_mon + 1, tm->tm_year + 1900, tm->tm_hour, tm->tm_min, tm->tm_sec, divTime.rem);
		return date;
	}

	static void ShowUptime (std::stringstream& s, int seconds)
	{
		int num;

		if ((num = seconds / 86400) > 0) {
			s << ntr("%d day", "%d days", num, num) << ", ";
			seconds -= num * 86400;
		}
		if ((num = seconds / 3600) > 0) {
			s << ntr("%d hour", "%d hours", num, num) << ", ";
			seconds -= num * 3600;
		}
		if ((num = seconds / 60) > 0) {
			s << ntr("%d minute", "%d minutes", num, num) << ", ";
			seconds -= num * 60;
		}
		s << ntr("%d second", "%d seconds", seconds, seconds);
	}

	static void ShowTraffic (std::stringstream& s, uint64_t bytes)
	{
		s << std::fixed << std::setprecision(2);
		auto numKBytes = (double) bytes / 1024;
		if (numKBytes < 1024)
			s << tr(/* tr: Kibibyte */ "%.2f KiB", numKBytes);
		else if (numKBytes < 1024 * 1024)
			s << tr(/* tr: Mebibyte */ "%.2f MiB", numKBytes / 1024);
		else
			s << tr(/* tr: Gibibyte */ "%.2f GiB", numKBytes / 1024 / 1024);
	}

	static void ShowTunnelDetails (std::stringstream& s, enum i2p::tunnel::TunnelState eState, bool explr, int bytes)
	{
		std::string state, stateText;
		switch (eState) 
		{
			case i2p::tunnel::eTunnelStateBuildReplyReceived :
			case i2p::tunnel::eTunnelStatePending     : state = "building";    break;
			case i2p::tunnel::eTunnelStateBuildFailed : state = "failed"; stateText = "declined"; break;
			case i2p::tunnel::eTunnelStateTestFailed  : state = "failed"; stateText = "test failed";  break;
			case i2p::tunnel::eTunnelStateFailed      : state = "failed";      break;
			case i2p::tunnel::eTunnelStateExpiring    : state = "expiring";    break;
			case i2p::tunnel::eTunnelStateEstablished : state = "established"; break;
			default: state = "unknown"; break;
		}
		if (stateText.empty ()) stateText = tr(state);
		
		s << "<span class=\"tunnel " << state << "\"> " << stateText << ((explr) ? " (" + tr("exploratory") + ")" : "") << "</span>, ";
		ShowTraffic(s, bytes);
		s << "\r\n";
	}

	static void SetLogLevel (const std::string& level)
	{
		if (level == "none" || level == "critical" || level == "error" || level == "warn" || level == "info" || level == "debug")
			i2p::log::Logger().SetLogLevel(level);
		else {
			LogPrint(eLogError, "HTTPServer: Unknown loglevel set attempted");
			return;
		}
		i2p::log::Logger().Reopen ();
	}

	static void ShowPageHead (std::stringstream& s)
	{
		std::string webroot; i2p::config::GetOption("http.webroot", webroot);

		// Page language
		std::string currLang = i2p::client::context.GetLanguage ()->GetLanguage(); // get current used language
		auto it = i2p::i18n::languages.find(currLang);
		std::string langCode = it->second.ShortCode;

		s <<
			"<!DOCTYPE html>\r\n"
			"<html lang=\"" << langCode << "\">\r\n"
			"  <head>\r\n" /* TODO: Find something to parse html/template system. This is horrible. */
			"  <meta charset=\"UTF-8\">\r\n"
			"  <meta name=\"viewport\" content=\"width=device-width, initial-scale=1.0\">\r\n"
			"  <link rel=\"shortcut icon\" href=\"" << itoopieFavicon << "\">\r\n"
			"  <title>" << tr(/* tr: Webconsole page title */ "Purple I2P Webconsole") << "</title>\r\n";
		GetStyles(s);
		s <<
			"</head>\r\n"
			"<body>\r\n"
			"<div class=\"header\">" << tr("<b>i2pd</b> webconsole") << "</div>\r\n"
			"<div class=\"wrapper\">\r\n"
			"<div class=\"menu\">\r\n"
			"  <a href=\"" << webroot << "\">" << tr("Main page") << "</a><br><br>\r\n"
			"  <a href=\"" << webroot << "?page=" << HTTP_PAGE_COMMANDS << "\">" << tr("Router commands") << "</a><br>\r\n"
			"  <a href=\"" << webroot << "?page=" << HTTP_PAGE_LOCAL_DESTINATIONS << "\">" << tr("Local Destinations") << "</a><br>\r\n";
		if (i2p::context.IsFloodfill ())
			s << "  <a href=\"" << webroot << "?page=" << HTTP_PAGE_LEASESETS << "\">" << tr("LeaseSets") << "</a><br>\r\n";
		s <<
			"  <a href=\"" << webroot << "?page=" << HTTP_PAGE_TUNNELS << "\">" << tr("Tunnels") << "</a><br>\r\n";
		if (i2p::context.AcceptsTunnels () || i2p::tunnel::tunnels.CountTransitTunnels())
			s << "  <a href=\"" << webroot << "?page=" << HTTP_PAGE_TRANSIT_TUNNELS << "\">" << tr("Transit Tunnels") << "</a><br>\r\n";
		s <<
			"  <a href=\"" << webroot << "?page=" << HTTP_PAGE_TRANSPORTS << "\">" << tr("Transports") << "</a><br>\r\n"
			"  <a href=\"" << webroot << "?page=" << HTTP_PAGE_I2P_TUNNELS << "\">" << tr("I2P tunnels") << "</a><br>\r\n";
		if (i2p::client::context.GetSAMBridge ())
			s << "  <a href=\"" << webroot << "?page=" << HTTP_PAGE_SAM_SESSIONS << "\">" << tr("SAM sessions") << "</a><br>\r\n";
		s <<
			"</div>\r\n"
			"<div class=\"content\">";
	}

	static void ShowPageTail (std::stringstream& s)
	{
		s <<
			"</div>\r\n</div>\r\n"
			"</body>\r\n"
			"</html>\r\n";
	}

	static void ShowError(std::stringstream& s, const std::string& string)
	{
		s << "<b>" << tr("ERROR") << ":</b>&nbsp;" << string << "<br>\r\n";
	}

	static void ShowNetworkStatus (std::stringstream& s, RouterStatus status, bool testing, RouterError error)
	{
		switch (status)
		{
			case eRouterStatusOK: s << tr("OK"); break;
			case eRouterStatusFirewalled: s << tr("Firewalled"); break;
			case eRouterStatusUnknown: s << tr("Unknown"); break;
			case eRouterStatusProxy: s << tr("Proxy"); break;
			case eRouterStatusMesh: s << tr("Mesh"); break;
			default: s << tr("Unknown");
		}
		if (testing)
			s << " (" << tr("Testing") << ")";
		if (error != eRouterErrorNone)
		{
			switch (error)
			{
				case eRouterErrorClockSkew:
					s << " - " << tr("Clock skew");
				break;
				case eRouterErrorOffline:
					s << " - " << tr("Offline");
				break;
				case eRouterErrorSymmetricNAT:
					s << " - " << tr("Symmetric NAT");
				break;
				case eRouterErrorFullConeNAT:
					s << " - " << tr("Full cone NAT");
				break;
				case eRouterErrorNoDescriptors:
					s << " - " << tr("No Descriptors");
				break;
				default: ;
			}
		}
	}

	void ShowStatus (std::stringstream& s, bool includeHiddenContent, i2p::http::OutputFormatEnum outputFormat)
	{
		s << "<b>" << tr("Uptime") << ":</b> ";
		ShowUptime(s, i2p::context.GetUptime ());
		s << "<br>\r\n";
		s << "<b>" << tr("Network status") << ":</b> ";
		ShowNetworkStatus (s, i2p::context.GetStatus (), i2p::context.GetTesting(), i2p::context.GetError ());
		s << "<br>\r\n";
		if (i2p::context.SupportsV6 ())
		{
			s << "<b>" << tr("Network status v6") << ":</b> ";
			ShowNetworkStatus (s, i2p::context.GetStatusV6 (), i2p::context.GetTestingV6(), i2p::context.GetErrorV6 ());
			s << "<br>\r\n";
		}
#if ((!defined(WIN32) && !defined(QT_GUI_LIB) && !defined(ANDROID)) || defined(ANDROID_BINARY))
		if (auto remains = Daemon.gracefulShutdownInterval) {
			s << "<b>" << tr("Stopping in") << ":</b> ";
			ShowUptime(s, remains);
			s << "<br>\r\n";
		}
#elif defined(WIN32_APP)
		if (i2p::win32::g_GracefulShutdownEndtime != 0) {
			uint16_t remains = (i2p::win32::g_GracefulShutdownEndtime - GetTickCount()) / 1000;
			s << "<b>" << tr("Stopping in") << ":</b> ";
			ShowUptime(s, remains);
			s << "<br>\r\n";
		}
#endif
		auto family = i2p::context.GetFamily ();
		if (family.length () > 0)
			s << "<b>"<< tr("Family") << ":</b> " << family << "<br>\r\n";
		s << "<b>" << tr("Tunnel creation success rate") << ":</b> " << i2p::tunnel::tunnels.GetTunnelCreationSuccessRate () << "%<br>\r\n";
		bool isTotalTCSR;
		i2p::config::GetOption("http.showTotalTCSR", isTotalTCSR);
		if (isTotalTCSR) {
			s << "<b>" << tr("Total tunnel creation success rate") << ":</b> " << i2p::tunnel::tunnels.GetTotalTunnelCreationSuccessRate() << "%<br/>\r\n";
		}
		s << "<b>" << tr("Received") << ":</b> ";
		ShowTraffic (s, i2p::transport::transports.GetTotalReceivedBytes ());
		s << " (" << tr(/* tr: Kibibyte/s */ "%.2f KiB/s", (double) i2p::transport::transports.GetInBandwidth15s () / 1024) << ")<br>\r\n";
		s << "<b>" << tr("Sent") << ":</b> ";
		ShowTraffic (s, i2p::transport::transports.GetTotalSentBytes ());
		s << " (" << tr(/* tr: Kibibyte/s */ "%.2f KiB/s", (double) i2p::transport::transports.GetOutBandwidth15s () / 1024) << ")<br>\r\n";
		s << "<b>" << tr("Transit") << ":</b> ";
		ShowTraffic (s, i2p::transport::transports.GetTotalTransitTransmittedBytes ());
		s << " (" << tr(/* tr: Kibibyte/s */ "%.2f KiB/s", (double) i2p::transport::transports.GetTransitBandwidth15s () / 1024) << ")<br>\r\n";
		s << "<b>" << tr("Data path") << ":</b> " << i2p::fs::GetUTF8DataDir() << "<br>\r\n";
		s << "<div class='slide'>";
		if ((outputFormat == OutputFormatEnum::forWebConsole) || !includeHiddenContent) {
			s << "<label for=\"slide-info\">" << tr("Hidden content. Press on text to see.") << "</label>\r\n<input type=\"checkbox\" id=\"slide-info\" />\r\n<div class=\"slidecontent\">\r\n";
		}
		if (includeHiddenContent)
		{
			s << "<b>" << tr("Router Ident") << ":</b> " << i2p::context.GetRouterInfo().GetIdentHashBase64() << "<br>\r\n";
			if (!i2p::context.GetRouterInfo().GetProperty("family").empty())
				s << "<b>" << tr("Router Family") << ":</b> " << i2p::context.GetRouterInfo().GetProperty("family") << "<br>\r\n";
			s << "<b>" << tr("Router Caps") << ":</b> " << i2p::context.GetRouterInfo().GetProperty("caps") << "<br>\r\n";
			s << "<b>" << tr("Version") << ":</b> " VERSION "<br>\r\n";
			s << "<b>"<< tr("Our external address") << ":</b>" << "<br>\r\n<table class=\"extaddr\"><tbody>\r\n";
			auto addresses = i2p::context.GetRouterInfo().GetAddresses ();
			if (addresses)
			{
				for (const auto& address : *addresses)
				{
					if (!address) continue;
					s << "<tr>\r\n<td>";
					switch (address->transportStyle)
					{
						case i2p::data::RouterInfo::eTransportNTCP2:
							s << "NTCP2";
						break;
						case i2p::data::RouterInfo::eTransportSSU2:
							s << "SSU2";
						break;
						default:
							s << tr("Unknown");
					}
					bool v6 = address->IsV6 ();
					if (v6)
					{
						if (address->IsV4 ()) s << "v4";
						s << "v6";
					}
					s << "</td>\r\n";
					if (address->published)
						s << "<td>" << (v6 ? "[" : "") << address->host.to_string() << (v6 ? "]:" : ":") << address->port << "</td>\r\n";
					else
					{
						s << "<td>" << tr(/* tr: Shown when router doesn't publish itself and have "Firewalled" state */ "supported");
						if (address->port)
							s << " :" << address->port;
						s << "</td>\r\n";
					}
					s << "</tr>\r\n";
				}
			}
			s << "</tbody></table>\r\n";
		}
		s << "</div>\r\n</div>\r\n";
		if (outputFormat == OutputFormatEnum::forQtUi) {
			s << "<br>";
		}
		s << "<b>" << tr("Routers") << ":</b> " << i2p::data::netdb.GetNumRouters () << " ";
		s << "<b>" << tr("Floodfills") << ":</b> " << i2p::data::netdb.GetNumFloodfills () << " ";
		s << "<b>" << tr("LeaseSets") << ":</b> " << i2p::data::netdb.GetNumLeaseSets () << "<br>\r\n";

		size_t clientTunnelCount = i2p::tunnel::tunnels.CountOutboundTunnels();
		clientTunnelCount += i2p::tunnel::tunnels.CountInboundTunnels();
		size_t transitTunnelCount = i2p::tunnel::tunnels.CountTransitTunnels();

		s << "<b>" << tr("Client Tunnels") << ":</b> " << std::to_string(clientTunnelCount) << " ";
		s << "<b>" << tr("Transit Tunnels") << ":</b> " << std::to_string(transitTunnelCount) << "<br>\r\n<br>\r\n";

		if (outputFormat==OutputFormatEnum::forWebConsole) {
			bool httpproxy  = i2p::client::context.GetHttpProxy ()         ? true : false;
			bool socksproxy = i2p::client::context.GetSocksProxy ()        ? true : false;
			bool bob        = i2p::client::context.GetBOBCommandChannel () ? true : false;
			bool sam        = i2p::client::context.GetSAMBridge ()         ? true : false;
			bool i2cp       = i2p::client::context.GetI2CPServer ()        ? true : false;
			bool i2pcontrol;  i2p::config::GetOption("i2pcontrol.enabled", i2pcontrol);
			s << "<table class=\"services\"><caption>" << tr("Services") << "</caption><tbody>\r\n";
			s << "<tr><td>" << "HTTP " << tr("Proxy")  << "</td><td class='" << (httpproxy  ? "enabled" : "disabled") << "'>" << (httpproxy  ? tr("Enabled") : tr("Disabled")) << "</td></tr>\r\n";
			s << "<tr><td>" << "SOCKS " << tr("Proxy") << "</td><td class='" << (socksproxy ? "enabled" : "disabled") << "'>" << (socksproxy ? tr("Enabled") : tr("Disabled")) << "</td></tr>\r\n";
			s << "<tr><td>" << "BOB"                   << "</td><td class='" << (bob        ? "enabled" : "disabled") << "'>" << (bob        ? tr("Enabled") : tr("Disabled")) << "</td></tr>\r\n";
			s << "<tr><td>" << "SAM"                   << "</td><td class='" << (sam        ? "enabled" : "disabled") << "'>" << (sam        ? tr("Enabled") : tr("Disabled")) << "</td></tr>\r\n";
			s << "<tr><td>" << "I2CP"                  << "</td><td class='" << (i2cp       ? "enabled" : "disabled") << "'>" << (i2cp       ? tr("Enabled") : tr("Disabled")) << "</td></tr>\r\n";
			s << "<tr><td>" << "I2PControl"            << "</td><td class='" << (i2pcontrol ? "enabled" : "disabled") << "'>" << (i2pcontrol ? tr("Enabled") : tr("Disabled")) << "</td></tr>\r\n";
			s << "</tbody></table>\r\n";
		}
	}

	void ShowLocalDestinations (std::stringstream& s)
	{
		std::string webroot; i2p::config::GetOption("http.webroot", webroot);
		s << "<b>" << tr("Local Destinations") << ":</b><br>\r\n<div class=\"list\">\r\n";
		for (auto& it: i2p::client::context.GetDestinations ())
		{
			auto ident = it.second->GetIdentHash ();
			s << "<div class=\"listitem\"><a href=\"" << webroot << "?page=" << HTTP_PAGE_LOCAL_DESTINATION << "&b32=" << ident.ToBase32 () << "\">";
			s << i2p::client::context.GetAddressBook ().ToAddress(ident) << "</a></div>\r\n" << std::endl;
		}
		s << "</div>\r\n";

		auto i2cpServer = i2p::client::context.GetI2CPServer ();
		if (i2cpServer && !(i2cpServer->GetSessions ().empty ()))
		{
			s << "<br><b>I2CP "<< tr("Local Destinations") << ":</b><br>\r\n<div class=\"list\">\r\n";
			for (auto& it: i2cpServer->GetSessions ())
			{
				auto dest = it.second->GetDestination ();
				if (dest)
				{
					auto ident = dest->GetIdentHash ();
					auto& name = dest->GetNickname ();
					s << "<div class=\"listitem\"><a href=\"" << webroot << "?page=" << HTTP_PAGE_I2CP_LOCAL_DESTINATION << "&i2cp_id=" << it.first << "\">[ ";
					s << name << " ]</a> &#8660; " << i2p::client::context.GetAddressBook ().ToAddress(ident) <<"</div>\r\n" << std::endl;
				}
			}
			s << "</div>\r\n";
		}
	}

	static void ShowHop(std::stringstream& s, const i2p::data::IdentityEx& ident)
	{
		auto identHash = ident.GetIdentHash();
		auto router = i2p::data::netdb.FindRouter(identHash);
		s << i2p::data::GetIdentHashAbbreviation(identHash);
		if (router)
			s << "<small style=\"color:gray\"> " << router->GetBandwidthCap() << "</small>";
	}

	static void ShowLeaseSetDestination (std::stringstream& s, std::shared_ptr<const i2p::client::LeaseSetDestination> dest, uint32_t token)
	{
		s << "<b>Base32:</b><br>\r\n<textarea readonly cols=\"80\" rows=\"1\">";
		s << dest->GetIdentHash ().ToBase32 () << "</textarea><br>\r\n<br>\r\n";

		s << "<b>Base64:</b><br>\r\n<textarea readonly cols=\"80\" rows=\"8\">";
		s << dest->GetIdentity ()->ToBase64 () << "</textarea><br>\r\n<br>\r\n";

		if (dest->IsEncryptedLeaseSet ())
		{
			i2p::data::BlindedPublicKey blinded (dest->GetIdentity (), dest->IsPerClientAuth ());
			s << "<div class='slide'><label for='slide-b33'><b>" << tr("Encrypted B33 address") << ":</b></label>\r\n<input type=\"checkbox\" id=\"slide-b33\" />\r\n<div class=\"slidecontent\">\r\n";
			s << blinded.ToB33 () << ".b32.i2p<br>\r\n";
			s << "</div>\r\n</div>\r\n";
		}

		if (dest->IsPublic() && token && !dest->IsEncryptedLeaseSet ())
		{
			std::string webroot; i2p::config::GetOption("http.webroot", webroot);
			s << "<div class='slide'><label for='slide-regaddr'><b>" << tr("Address registration line") << "</b></label>\r\n<input type=\"checkbox\" id=\"slide-regaddr\" />\r\n<div class=\"slidecontent\">\r\n"
			     "<form method=\"get\" action=\"" << webroot << "\">\r\n"
			     "  <input type=\"hidden\" name=\"cmd\" value=\"" << HTTP_COMMAND_GET_REG_STRING << "\">\r\n"
			     "  <input type=\"hidden\" name=\"token\" value=\"" << token << "\">\r\n"
			     "  <input type=\"hidden\" name=\"b32\" value=\"" << dest->GetIdentHash ().ToBase32 () << "\">\r\n"
			     "  <b>" << tr("Domain") << ":</b>\r\n<input type=\"text\" maxlength=\"67\" name=\"name\" placeholder=\"domain.i2p\" required>\r\n"
			     "  <button type=\"submit\">" << tr("Generate") << "</button>\r\n"
			     "</form>\r\n<small>" << tr("<b>Note:</b> result string can be used only for registering 2LD domains (example.i2p). For registering subdomains please use i2pd-tools.") << "</small>\r\n</div>\r\n</div>\r\n<br>\r\n";
		}

		if (dest->GetNumRemoteLeaseSets())
		{
			s << "<div class='slide'><label for='slide-lease'><b>" << tr("LeaseSets") << ":</b> <i>" << dest->GetNumRemoteLeaseSets ()
			  << "</i></label>\r\n<input type=\"checkbox\" id=\"slide-lease\" />\r\n<div class=\"slidecontent\">\r\n"
			  << "<table><thead>"
			  << "<th>" << tr("Address") << "</th>"
			  << "<th style=\"width:5px;\">&nbsp;</th>" // LeaseSet expiration button column
			  << "<th>" << tr("Type") << "</th>"
			  << "<th>" << tr("EncType") << "</th>"
			  << "</thead><tbody class=\"tableitem\">";
			for(auto& it: dest->GetLeaseSets ())
			{
				s << "<tr>"
				  << "<td>" << it.first.ToBase32 () << "</td>"
				  << "<td><a class=\"button\" href=\"/?cmd=" << HTTP_COMMAND_EXPIRELEASE<< "&b32=" << dest->GetIdentHash ().ToBase32 ()
				  << "&lease=" << it.first.ToBase32 () << "&token=" << token << "\" title=\"" << tr("Expire LeaseSet") << "\"> &#10008; </a></td>"
				  << "<td>" << (int)it.second->GetStoreType () << "</td>"
				  << "<td>" << (int)it.second->GetEncryptionType () <<"</td>"
				  << "</tr>\r\n";
			}
			s << "</tbody></table>\r\n</div>\r\n</div>\r\n<br>\r\n";
		} else
			s << "<b>" << tr("LeaseSets") << ":</b> <i>0</i><br>\r\n<br>\r\n";

		auto pool = dest->GetTunnelPool ();
		if (pool)
		{
			s << "<b>" << tr("Inbound tunnels") << ":</b><br>\r\n<div class=\"list\">\r\n";
			for (auto & it : pool->GetInboundTunnels ()) {
				s << "<div class=\"listitem\">";
				// for each tunnel hop if not zero-hop
				if (it->GetNumHops ())
				{
					it->VisitTunnelHops(
						[&s](std::shared_ptr<const i2p::data::IdentityEx> hopIdent)
						{
							s << "&#8658; ";
							ShowHop(s, *hopIdent);
							s << " ";
						}
					);
				}
				s << "&#8658; " << it->GetTunnelID () << ":me";
				if (it->LatencyIsKnown())
					s << " ( " << tr(/* tr: Milliseconds */ "%dms", it->GetMeanLatency()) << " )";
				ShowTunnelDetails(s, it->GetState (), false, it->GetNumReceivedBytes ());
				s << "</div>\r\n";
			}
			s << "<br>\r\n";
			s << "<b>" << tr("Outbound tunnels") << ":</b><br>\r\n<div class=\"list\">\r\n";
			for (auto & it : pool->GetOutboundTunnels ()) {
				s << "<div class=\"listitem\">";
				s << it->GetTunnelID () << ":me &#8658;";
				// for each tunnel hop if not zero-hop
				if (it->GetNumHops ())
				{
					it->VisitTunnelHops(
						[&s](std::shared_ptr<const i2p::data::IdentityEx> hopIdent)
						{
							s << " ";
							ShowHop(s, *hopIdent);
							s << " &#8658;";
						}
					);
				}
				if (it->LatencyIsKnown())
					s << " ( " << tr("%dms", it->GetMeanLatency()) << " )";
				ShowTunnelDetails(s, it->GetState (), false, it->GetNumSentBytes ());
				s << "</div>\r\n";
			}
		}
		s << "<br>\r\n";

		s << "<b>" << tr("Tags") << "</b><br>\r\n"
		  << tr("Incoming") << ": <i>" << dest->GetNumIncomingTags () << "</i><br>\r\n";
		if (!dest->GetSessions ().empty ()) {
			std::stringstream tmp_s; uint32_t out_tags = 0;
			for (const auto& it: dest->GetSessions ()) {
				tmp_s << "<tr><td>" << i2p::client::context.GetAddressBook ().ToAddress(it.first) << "</td><td>" << it.second->GetNumOutgoingTags () << "</td></tr>\r\n";
				out_tags += it.second->GetNumOutgoingTags ();
			}
			s << "<div class='slide'><label for='slide-tags'>" << tr("Outgoing") << ": <i>" << out_tags << "</i></label>\r\n"
			  << "<input type=\"checkbox\" id=\"slide-tags\" />\r\n"
			  << "<div class=\"slidecontent\">\r\n"
			  << "<table>\r\n<thead><th>" << tr("Destination") << "</th><th>" << tr("Amount") << "</th></thead>\r\n"
			  << "<tbody class=\"tableitem\">\r\n" << tmp_s.str () << "</tbody></table>\r\n</div>\r\n</div>\r\n";
		} else
			s << tr("Outgoing") << ": <i>0</i><br>\r\n";
		s << "<br>\r\n";

		auto numECIESx25519Tags = dest->GetNumIncomingECIESx25519Tags ();
		if (numECIESx25519Tags > 0) {
			s << "<b>ECIESx25519</b><br>\r\n" << tr("Incoming Tags") << ": <i>" << numECIESx25519Tags << "</i><br>\r\n";
			if (!dest->GetECIESx25519Sessions ().empty ())
			{
				std::stringstream tmp_s; uint32_t ecies_sessions = 0;
				for (const auto& it: dest->GetECIESx25519Sessions ()) {
					tmp_s << "<tr><td>" << i2p::client::context.GetAddressBook ().ToAddress(it.second->GetDestination ()) << "</td><td>" << it.second->GetState () << "</td></tr>\r\n";
					ecies_sessions++;
				}
				s << "<div class='slide'><label for='slide-ecies-sessions'>" << tr("Tags sessions") << ": <i>" << ecies_sessions << "</i></label>\r\n"
				  << "<input type=\"checkbox\" id=\"slide-ecies-sessions\" />\r\n"
				  << "<div class=\"slidecontent\">\r\n<table>\r\n"
				  << "<thead><th>" << tr("Destination") << "</th><th>" << tr("Status") << "</th></thead>\r\n"
				  << "<tbody class=\"tableitem\">\r\n" << tmp_s.str () << "</tbody></table>\r\n</div>\r\n</div>\r\n";
			} else
				s << tr("Tags sessions") << ": <i>0</i><br>\r\n";
			s << "<br>\r\n";
		}
	}

	void ShowLocalDestination (std::stringstream& s, const std::string& b32, uint32_t token)
	{
		s << "<b>" << tr("Local Destination") << ":</b><br>\r\n<br>\r\n";
		i2p::data::IdentHash ident;
		ident.FromBase32 (b32);
		auto dest = i2p::client::context.FindLocalDestination (ident);

		if (dest)
		{
			ShowLeaseSetDestination (s, dest, token);

			// Print table with streams information
			s << "<table>\r\n<caption>"
			  << tr("Streams")
			  << "</caption>\r\n<thead>\r\n<tr>"
			  << "<th style=\"width:25px;\">StreamID</th>"
			  << "<th style=\"width:5px;\">&nbsp;</th>" // Stream closing button column
			  << "<th class=\"streamdest\">Destination</th>"
			  << "<th>Sent</th>"
			  << "<th>Received</th>"
			  << "<th>Out</th>"
			  << "<th>In</th>"
			  << "<th>Buf</th>"
			  << "<th>RTT</th>"
			  << "<th>Window</th>"
			  << "<th>Status</th>"
			  << "</tr>\r\n</thead>\r\n<tbody class=\"tableitem\">\r\n";

			for (const auto& it: dest->GetAllStreams ())
			{
				auto streamDest = i2p::client::context.GetAddressBook ().ToAddress(it->GetRemoteIdentity ());
				std::string streamDestShort = streamDest.substr(0,12) + "&hellip;.b32.i2p";
				s << "<tr>";
				s << "<td>" << it->GetRecvStreamID () << "</td>";
				if (it->GetRecvStreamID ()) {
					s << "<td><a class=\"button\" href=\"/?cmd=" << HTTP_COMMAND_KILLSTREAM << "&b32=" << b32 << "&streamID="
					  << it->GetRecvStreamID () << "&token=" << token << "\" title=\"" << tr("Close stream") << "\"> &#10008; </a></td>";
				} else {
					s << "<td \\>";
				}
				s << "<td class=\"streamdest\" title=\"" << streamDest << "\">" << streamDestShort << "</td>";
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
			s << "</tbody>\r\n</table>";
		}
		else
			ShowError(s, tr("Such destination is not found"));
	}

	void ShowI2CPLocalDestination (std::stringstream& s, const std::string& id)
	{
		auto i2cpServer = i2p::client::context.GetI2CPServer ();
		if (i2cpServer)
		{
			s << "<b>I2CP " << tr("Local Destination") << ":</b><br>\r\n<br>\r\n";
			auto it = i2cpServer->GetSessions ().find (std::stoi (id));
			if (it != i2cpServer->GetSessions ().end ())
				ShowLeaseSetDestination (s, it->second->GetDestination (), 0);
			else
				ShowError(s, tr("I2CP session not found"));
		}
		else
			ShowError(s, tr("I2CP is not enabled"));
	}

	void ShowLeasesSets(std::stringstream& s)
	{
		if (i2p::data::netdb.GetNumLeaseSets ())
		{
			s << "<b>" << tr("LeaseSets") << ":</b><br>\r\n<div class=\"list\">\r\n";
			int counter = 1;
			// for each lease set
			i2p::data::netdb.VisitLeaseSets(
				[&s, &counter](const i2p::data::IdentHash dest, std::shared_ptr<i2p::data::LeaseSet> leaseSet)
				{
					// create copy of lease set so we extract leases
					auto storeType = leaseSet->GetStoreType ();
					std::unique_ptr<i2p::data::LeaseSet> ls;
					if (storeType == i2p::data::NETDB_STORE_TYPE_LEASESET)
						ls.reset (new i2p::data::LeaseSet (leaseSet->GetBuffer(), leaseSet->GetBufferLen()));
					else
					{
						ls.reset (new i2p::data::LeaseSet2 (storeType));
						ls->Update (leaseSet->GetBuffer(), leaseSet->GetBufferLen(), false);
					}
					if (!ls) return;
					s << "<div class=\"leaseset listitem";
					if (ls->IsExpired())
						s << " expired"; // additional css class for expired
					s << "\">\r\n";
					if (!ls->IsValid())
						s << "<div class=\"invalid\">!! " << tr("Invalid") << " !! </div>\r\n";
					s << "<div class=\"slide\"><label for=\"slide" << counter << "\">" << dest.ToBase32() << "</label>\r\n";
					s << "<input type=\"checkbox\" id=\"slide" << (counter++) << "\" />\r\n<div class=\"slidecontent\">\r\n";
					s << "<b>" << tr("Store type") << ":</b> " << (int)storeType << "<br>\r\n";
					s << "<b>" << tr("Expires") << ":</b> " << ConvertTime(ls->GetExpirationTime()) << "<br>\r\n";
					if (storeType == i2p::data::NETDB_STORE_TYPE_LEASESET || storeType == i2p::data::NETDB_STORE_TYPE_STANDARD_LEASESET2)
					{
						// leases information is available
						auto leases = ls->GetNonExpiredLeases();
						s << "<b>" << tr("Non Expired Leases") << ": " << leases.size() << "</b><br>\r\n";
						for ( auto & l : leases )
						{
							s << "<b>" << tr("Gateway") << ":</b> " << l->tunnelGateway.ToBase64() << "<br>\r\n";
							s << "<b>" << tr("TunnelID") << ":</b> " << l->tunnelID << "<br>\r\n";
							s << "<b>" << tr("EndDate") << ":</b> " << ConvertTime(l->endDate) << "<br>\r\n";
						}
					}
					s << "</div>\r\n</div>\r\n</div>\r\n";
				}
			);
			// end for each lease set
		}
		else if (!i2p::context.IsFloodfill ())
		{
			s << "<b>" << tr("LeaseSets") << ":</b> " << tr(/* Message on LeaseSets page */ "floodfill mode is disabled") << ".<br>\r\n";
		}
		else
		{
			s << "<b>" << tr("LeaseSets") << ":</b> 0<br>\r\n";
		}
	}

	void ShowTunnels (std::stringstream& s)
	{
		s << "<b>" << tr("Tunnels") << ":</b><br>\r\n";
		s << "<b>" << tr("Queue size") << ":</b> " << i2p::tunnel::tunnels.GetQueueSize () << "<br>\r\n<br>\r\n";

		auto ExplPool = i2p::tunnel::tunnels.GetExploratoryPool ();

		s << "<b>" << tr("Inbound tunnels") << ":</b><br>\r\n<div class=\"list\">\r\n";
		for (auto & it : i2p::tunnel::tunnels.GetInboundTunnels ()) {
			s << "<div class=\"listitem\">";
			if (it->GetNumHops ())
			{
				it->VisitTunnelHops(
					[&s](std::shared_ptr<const i2p::data::IdentityEx> hopIdent)
					{
						s << "&#8658; ";
						ShowHop(s, *hopIdent);
						s << " ";
					}
				);
			}
			s << "&#8658; " << it->GetTunnelID () << ":me";
			if (it->LatencyIsKnown())
			s << " ( " << tr("%dms", it->GetMeanLatency()) << " )";
			ShowTunnelDetails(s, it->GetState (), (it->GetTunnelPool () == ExplPool), it->GetNumReceivedBytes ());
			s << "</div>\r\n";
		}
		s << "</div>\r\n<br>\r\n";
		s << "<b>" << tr("Outbound tunnels") << ":</b><br>\r\n<div class=\"list\">\r\n";
		for (auto & it : i2p::tunnel::tunnels.GetOutboundTunnels ()) {
			s << "<div class=\"listitem\">";
			s << it->GetTunnelID () << ":me &#8658;";
			// for each tunnel hop if not zero-hop
			if (it->GetNumHops ())
			{
				it->VisitTunnelHops(
					[&s](std::shared_ptr<const i2p::data::IdentityEx> hopIdent)
					{
						s << " ";
						ShowHop(s, *hopIdent);
						s << " &#8658;";
					}
				);
			}
			if (it->LatencyIsKnown())
			s << " ( " << tr("%dms", it->GetMeanLatency()) << " )";
			ShowTunnelDetails(s, it->GetState (), (it->GetTunnelPool () == ExplPool), it->GetNumSentBytes ());
			s << "</div>\r\n";
		}
		s << "</div>\r\n";
	}

	static void ShowCommands (std::stringstream& s, uint32_t token)
	{
		std::string webroot; i2p::config::GetOption("http.webroot", webroot);

		s << "<b>" << tr("Router commands") << "</b><br>\r\n<br>\r\n<div class=\"commands\">\r\n";
		s << "  <a href=\"" << webroot << "?cmd=" << HTTP_COMMAND_RUN_PEER_TEST << "&token=" << token << "\">" << tr("Run peer test") << "</a><br>\r\n";
		s << "  <a href=\"" << webroot << "?cmd=" << HTTP_COMMAND_RELOAD_TUNNELS_CONFIG << "&token=" << token << "\">" << tr("Reload tunnels configuration") << "</a><br>\r\n";

		if (i2p::context.AcceptsTunnels ())
			s << "  <a href=\"" << webroot << "?cmd=" << HTTP_COMMAND_DISABLE_TRANSIT << "&token=" << token << "\">" << tr("Decline transit tunnels") << "</a><br>\r\n";
		else
			s << "  <a href=\"" << webroot << "?cmd=" << HTTP_COMMAND_ENABLE_TRANSIT << "&token=" << token << "\">" << tr("Accept transit tunnels") << "</a><br>\r\n";

#if ((!defined(WIN32) && !defined(QT_GUI_LIB) && !defined(ANDROID)) || defined(ANDROID_BINARY))
		if (Daemon.gracefulShutdownInterval)
			s << "  <a href=\"" << webroot << "?cmd=" << HTTP_COMMAND_SHUTDOWN_CANCEL << "&token=" << token << "\">" << tr("Cancel graceful shutdown") << "</a><br>\r\n";
		else
			s << "  <a href=\"" << webroot << "?cmd=" << HTTP_COMMAND_SHUTDOWN_START << "&token=" << token << "\">" << tr("Start graceful shutdown") << "</a><br>\r\n";
#elif defined(WIN32_APP)
		if (i2p::util::DaemonWin32::Instance().isGraceful)
			s << "  <a href=\"" << webroot << "?cmd=" << HTTP_COMMAND_SHUTDOWN_CANCEL << "&token=" << token << "\">" << tr("Cancel graceful shutdown") << "</a><br>\r\n";
		else
			s << "  <a href=\"" << webroot << "?cmd=" << HTTP_COMMAND_SHUTDOWN_START << "&token=" << token << "\">" << tr("Start graceful shutdown") << "</a><br>\r\n";
#endif

		s << "  <a href=\"" << webroot << "?cmd=" << HTTP_COMMAND_SHUTDOWN_NOW << "&token=" << token << "\">" << tr("Force shutdown") << "</a><br><br>\r\n";
		s << "  <a href=\"" << webroot << "?cmd=" << HTTP_COMMAND_RELOAD_CSS << "&token=" << token << "\">" << tr("Reload external CSS styles") << "</a>\r\n";
		s << "</div>";

		s << "<br>\r\n<small>" << tr("<b>Note:</b> any action done here are not persistent and not changes your config files.") << "</small>\r\n<br>\r\n";

		auto loglevel = i2p::log::Logger().GetLogLevel();
		s << "<b>" << tr("Logging level") << "</b><br>\r\n";
		s << "  <a class=\"button" << (loglevel == eLogNone     ? " selected" : "") << "\" href=\"" << webroot << "?cmd=" << HTTP_COMMAND_LOGLEVEL << "&level=none&token=" << token << "\"> none </a> \r\n";
		s << "  <a class=\"button" << (loglevel == eLogCritical ? " selected" : "") << "\" href=\"" << webroot << "?cmd=" << HTTP_COMMAND_LOGLEVEL << "&level=critical&token=" << token << "\"> critical </a> \r\n";
		s << "  <a class=\"button" << (loglevel == eLogError    ? " selected" : "") << "\" href=\"" << webroot << "?cmd=" << HTTP_COMMAND_LOGLEVEL << "&level=error&token=" << token << "\"> error </a> \r\n";
		s << "  <a class=\"button" << (loglevel == eLogWarning  ? " selected" : "") << "\" href=\"" << webroot << "?cmd=" << HTTP_COMMAND_LOGLEVEL << "&level=warn&token=" << token << "\"> warn </a> \r\n";
		s << "  <a class=\"button" << (loglevel == eLogInfo     ? " selected" : "") << "\" href=\"" << webroot << "?cmd=" << HTTP_COMMAND_LOGLEVEL << "&level=info&token=" << token << "\"> info </a> \r\n";
		s << "  <a class=\"button" << (loglevel == eLogDebug    ? " selected" : "") << "\" href=\"" << webroot << "?cmd=" << HTTP_COMMAND_LOGLEVEL << "&level=debug&token=" << token << "\"> debug </a><br>\r\n<br>\r\n";

		uint32_t maxTunnels = i2p::tunnel::tunnels.GetMaxNumTransitTunnels ();
		s << "<b>" << tr("Transit tunnels limit") << "</b><br>\r\n";
		s << "<form method=\"get\" action=\"" << webroot << "\">\r\n";
		s << "  <input type=\"hidden\" name=\"cmd\" value=\"" << HTTP_COMMAND_LIMITTRANSIT << "\">\r\n";
		s << "  <input type=\"hidden\" name=\"token\" value=\"" << token << "\">\r\n";
		s << "  <input type=\"number\" min=\"0\" max=\"" << TRANSIT_TUNNELS_LIMIT <<"\" name=\"limit\" value=\"" << maxTunnels << "\">\r\n";
		s << "  <button type=\"submit\">" << tr("Change") << "</button>\r\n";
		s << "</form>\r\n<br>\r\n";

		// get current used language
		std::string currLang = i2p::client::context.GetLanguage ()->GetLanguage();

		s << "<b>"
		  << tr("Change language")
		  << "</b><br>\r\n"
		  << "<form method=\"get\" action=\"" << webroot << "\">\r\n"
		  << "  <input type=\"hidden\" name=\"cmd\" value=\"" << HTTP_COMMAND_SETLANGUAGE << "\">\r\n"
		  << "  <input type=\"hidden\" name=\"token\" value=\"" << token << "\">\r\n"
		  << "  <select name=\"lang\" id=\"lang\">\r\n";

		for (const auto& it: i2p::i18n::languages)
			s << "    <option value=\"" << it.first << "\"" << ((it.first.compare(currLang) == 0) ? " selected" : "") << ">" << it.second.LocaleName << "</option>\r\n";

		s << "  </select>\r\n"
		  << "  <button type=\"submit\">"
		  << tr("Change")
		  << "</button>\r\n"
		  << "</form>\r\n<br>\r\n";

	}

	void ShowTransitTunnels (std::stringstream& s)
	{
		if (i2p::tunnel::tunnels.CountTransitTunnels())
		{
			s << "<b>" << tr("Transit Tunnels") << ":</b><br>\r\n";
			s << "<table><thead><th>&#8658;</th><th>ID</th><th>&#8658;</th><th>" << tr("Amount") << "</th></thead><tbody class=\"tableitem\">";
			for (const auto& it: i2p::tunnel::tunnels.GetTransitTunnels ())
			{
				if (std::dynamic_pointer_cast<i2p::tunnel::TransitTunnelGateway>(it))
					s << "<tr><td></td><td>" << it->GetTunnelID () << "</td><td>&#8658;</td><td>";
				else if (std::dynamic_pointer_cast<i2p::tunnel::TransitTunnelEndpoint>(it))
					s << "<tr><td>&#8658;</td><td>" << it->GetTunnelID () << "</td><td></td><td>";
				else
					s << "<tr><td>&#8658;</td><td>" << it->GetTunnelID () << "</td><td>&#8658;</td><td>";
				ShowTraffic(s, it->GetNumTransmittedBytes ());
				s << "</td></tr>\r\n";
			}
			s << "</tbody></table>\r\n";
		}
		else
		{
			s << "<b>" << tr("Transit Tunnels") << ":</b> " << tr(/* Message on transit tunnels page */ "no transit tunnels currently built") << ".<br>\r\n";
		}
	}

	template<typename Sessions>
	static void ShowTransportSessions (std::stringstream& s, const Sessions& sessions, const std::string name)
	{
		auto comp = [](typename Sessions::mapped_type a, typename Sessions::mapped_type b)
			{ return a->GetRemoteEndpoint() < b->GetRemoteEndpoint(); };
		std::set<typename Sessions::mapped_type, decltype(comp)> sortedSessions(comp);
		for (const auto& it : sessions)
		{
			auto ret = sortedSessions.insert(it.second);
			if (!ret.second)
				LogPrint(eLogError, "HTTPServer: Duplicate remote endpoint detected: ", (*ret.first)->GetRemoteEndpoint());
		}
		std::stringstream tmp_s, tmp_s6; uint16_t cnt = 0, cnt6 = 0;
		for (const auto& it: sortedSessions)
		{
			auto endpoint = it->GetRemoteEndpoint ();
			if (it && it->IsEstablished () && endpoint.address ().is_v4 ())
			{
				tmp_s << "<div class=\"listitem\">\r\n";
				if (it->IsOutgoing ()) tmp_s << " &#8658; ";
				tmp_s << i2p::data::GetIdentHashAbbreviation (it->GetRemoteIdentity ()->GetIdentHash ()) << ": "
					<< endpoint.address ().to_string () << ":" << endpoint.port ();
				if (!it->IsOutgoing ()) tmp_s << " &#8658; ";
				tmp_s << " [" << it->GetNumSentBytes () << ":" << it->GetNumReceivedBytes () << "]";
				if (it->GetRelayTag ())
					tmp_s << " [itag:" << it->GetRelayTag () << "]";
				if (it->GetSendQueueSize () > 0)
					tmp_s << " [queue:" << it->GetSendQueueSize () << "]";
				if (it->IsSlow ()) tmp_s << " [slow]";
				tmp_s << "</div>\r\n" << std::endl;
				cnt++;
			}
			if (it && it->IsEstablished () && endpoint.address ().is_v6 ())
			{
				tmp_s6 << "<div class=\"listitem\">\r\n";
				if (it->IsOutgoing ()) tmp_s6 << " &#8658; ";
				tmp_s6 << i2p::data::GetIdentHashAbbreviation (it->GetRemoteIdentity ()->GetIdentHash ()) << ": "
					<< "[" << endpoint.address ().to_string () << "]:" << endpoint.port ();
				if (!it->IsOutgoing ()) tmp_s6 << " &#8658; ";
				tmp_s6 << " [" << it->GetNumSentBytes () << ":" << it->GetNumReceivedBytes () << "]";
				if (it->GetRelayTag ())
					tmp_s6 << " [itag:" << it->GetRelayTag () << "]";
				if (it->GetSendQueueSize () > 0)
					tmp_s6 << " [queue:" << it->GetSendQueueSize () << "]";
				tmp_s6 << "</div>\r\n" << std::endl;
				cnt6++;
			}
		}
		if (!tmp_s.str ().empty ())
		{
			s << "<div class='slide'><label for='slide_" << boost::algorithm::to_lower_copy(name) << "'><b>" << name
			  << "</b> ( " << cnt << " )</label>\r\n<input type=\"checkbox\" id=\"slide_" << boost::algorithm::to_lower_copy(name) << "\" />\r\n<div class=\"slidecontent list\">"
			  << tmp_s.str () << "</div>\r\n</div>\r\n";
		}
		if (!tmp_s6.str ().empty ())
		{
			s << "<div class='slide'><label for='slide_" << boost::algorithm::to_lower_copy(name) << "v6'><b>" << name
			  << "v6</b> ( " << cnt6 << " )</label>\r\n<input type=\"checkbox\" id=\"slide_" << boost::algorithm::to_lower_copy(name) << "v6\" />\r\n<div class=\"slidecontent list\">"
			  << tmp_s6.str () << "</div>\r\n</div>\r\n";
		}
	}

	void ShowTransports (std::stringstream& s)
	{
		s << "<b>" << tr("Transports") << ":</b><br>\r\n";
		auto ntcp2Server = i2p::transport::transports.GetNTCP2Server ();
		if (ntcp2Server)
		{
			auto sessions = ntcp2Server->GetNTCP2Sessions ();
			if (!sessions.empty ())
				ShowTransportSessions (s, sessions, "NTCP2");
		}
		auto ssu2Server = i2p::transport::transports.GetSSU2Server ();
		if (ssu2Server)
		{
			auto sessions = ssu2Server->GetSSU2Sessions ();
			if (!sessions.empty ())
				ShowTransportSessions (s, sessions, "SSU2");
		}
	}

	void ShowSAMSessions (std::stringstream& s)
	{
		std::string webroot; i2p::config::GetOption("http.webroot", webroot);
		auto sam = i2p::client::context.GetSAMBridge ();
		if (!sam)
		{
			ShowError(s, tr("SAM disabled"));
			return;
		}

		if (sam->GetSessions ().size ())
		{
			s << "<b>" << tr("SAM sessions") << ":</b><br>\r\n<div class=\"list\">\r\n";
			for (auto& it: sam->GetSessions ())
			{
				auto& name = it.second->GetLocalDestination ()->GetNickname ();
				s << "<div class=\"listitem\"><a href=\"" << webroot << "?page=" << HTTP_PAGE_SAM_SESSION << "&sam_id=" << it.first << "\">";
				s << name << " (" << it.first << ")</a></div>\r\n" << std::endl;
			}
			s << "</div>\r\n";
		}
		else
			s << "<b>" << tr("SAM sessions") << ":</b> " << tr(/* Message on SAM sessions page */ "no sessions currently running") << ".<br>\r\n";
	}

	void ShowSAMSession (std::stringstream& s, const std::string& id)
	{
		auto sam = i2p::client::context.GetSAMBridge ();
		if (!sam) {
			ShowError(s, tr("SAM disabled"));
			return;
		}

		auto session = sam->FindSession (id);
		if (!session) {
			ShowError(s, tr("SAM session not found"));
			return;
		}

		std::string webroot; i2p::config::GetOption("http.webroot", webroot);
		s << "<b>" << tr("SAM Session") << ":</b><br>\r\n<div class=\"list\">\r\n";
		auto& ident = session->GetLocalDestination ()->GetIdentHash();
		s << "<div class=\"listitem\"><a href=\"" << webroot << "?page=" << HTTP_PAGE_LOCAL_DESTINATION << "&b32=" << ident.ToBase32 () << "\">";
		s << i2p::client::context.GetAddressBook ().ToAddress(ident) << "</a></div>\r\n";
		s << "<br>\r\n";
		s << "<b>" << tr("Streams") << ":</b><br>\r\n<div class=\"list\">\r\n";
		for (const auto& it: sam->ListSockets(id))
		{
			s << "<div class=\"listitem\">";
			switch (it->GetSocketType ())
			{
				case i2p::client::eSAMSocketTypeSession  : s << "session";  break;
				case i2p::client::eSAMSocketTypeStream   : s << "stream";   break;
				case i2p::client::eSAMSocketTypeAcceptor : s << "acceptor"; break;
				case i2p::client::eSAMSocketTypeForward  : s << "forward";  break;
				default: s << "unknown"; break;
			}
			s << " [" << it->GetSocket ().remote_endpoint() << "]";
			s << "</div>\r\n";
		}
		s << "</div>\r\n";
	}

	void ShowI2PTunnels (std::stringstream& s)
	{
		std::string webroot; i2p::config::GetOption("http.webroot", webroot);

		auto& clientTunnels = i2p::client::context.GetClientTunnels ();
		auto httpProxy = i2p::client::context.GetHttpProxy ();
		auto socksProxy = i2p::client::context.GetSocksProxy ();
		if (!clientTunnels.empty () || httpProxy || socksProxy)
		{
			s << "<b>" << tr("Client Tunnels") << ":</b><br>\r\n<div class=\"list\">\r\n";
			if (!clientTunnels.empty ())
			{
				for (auto& it: clientTunnels)
				{
					auto& ident = it.second->GetLocalDestination ()->GetIdentHash();
					s << "<div class=\"listitem\"><a href=\"" << webroot << "?page=" << HTTP_PAGE_LOCAL_DESTINATION << "&b32=" << ident.ToBase32 () << "\">";
					s << it.second->GetName () << "</a> &#8656; ";
					s << i2p::client::context.GetAddressBook ().ToAddress(ident);
					s << "</div>\r\n"<< std::endl;
				}
			}
			if (httpProxy)
			{
				auto& ident = httpProxy->GetLocalDestination ()->GetIdentHash();
				s << "<div class=\"listitem\"><a href=\"" << webroot << "?page=" << HTTP_PAGE_LOCAL_DESTINATION << "&b32=" << ident.ToBase32 () << "\">";
				s << "HTTP " << tr("Proxy") << "</a> &#8656; ";
				s << i2p::client::context.GetAddressBook ().ToAddress(ident);
				s << "</div>\r\n"<< std::endl;
			}
			if (socksProxy)
			{
				auto& ident = socksProxy->GetLocalDestination ()->GetIdentHash();
				s << "<div class=\"listitem\"><a href=\"" << webroot << "?page=" << HTTP_PAGE_LOCAL_DESTINATION << "&b32=" << ident.ToBase32 () << "\">";
				s << "SOCKS " << tr("Proxy") << "</a> &#8656; ";
				s << i2p::client::context.GetAddressBook ().ToAddress(ident);
				s << "</div>\r\n"<< std::endl;
			}
			s << "</div>\r\n";
		}

		auto& serverTunnels = i2p::client::context.GetServerTunnels ();
		if (!serverTunnels.empty ()) {
			s << "<br>\r\n<b>" << tr("Server Tunnels") << ":</b><br>\r\n<div class=\"list\">\r\n";
			for (auto& it: serverTunnels)
			{
				auto& ident = it.second->GetLocalDestination ()->GetIdentHash();
				s << "<div class=\"listitem\"><a href=\"" << webroot << "?page=" << HTTP_PAGE_LOCAL_DESTINATION << "&b32=" << ident.ToBase32 () << "\">";
				s << it.second->GetName () << "</a> &#8658; ";
				s << i2p::client::context.GetAddressBook ().ToAddress(ident);
				s << ":" << it.second->GetLocalPort ();
				s << "</a></div>\r\n"<< std::endl;
			}
			s << "</div>\r\n";
		}

		auto& clientForwards = i2p::client::context.GetClientForwards ();
		if (!clientForwards.empty ())
		{
			s << "<br>\r\n<b>" << tr("Client Forwards") << ":</b><br>\r\n<div class=\"list\">\r\n";
			for (auto& it: clientForwards)
			{
				auto& ident = it.second->GetLocalDestination ()->GetIdentHash();
				s << "<div class=\"listitem\"><a href=\"" << webroot << "?page=" << HTTP_PAGE_LOCAL_DESTINATION << "&b32=" << ident.ToBase32 () << "\">";
				s << it.second->GetName () << "</a> &#8656; ";
				s << i2p::client::context.GetAddressBook ().ToAddress(ident);
				s << "</div>\r\n"<< std::endl;
			}
			s << "</div>\r\n";
		}
		auto& serverForwards = i2p::client::context.GetServerForwards ();
		if (!serverForwards.empty ())
		{
			s << "<br>\r\n<b>" << tr("Server Forwards") << ":</b><br>\r\n<div class=\"list\">\r\n";
			for (auto& it: serverForwards)
			{
				auto& ident = it.second->GetLocalDestination ()->GetIdentHash();
				s << "<div class=\"listitem\"><a href=\"" << webroot << "?page=" << HTTP_PAGE_LOCAL_DESTINATION << "&b32=" << ident.ToBase32 () << "\">";
				s << it.second->GetName () << "</a> &#8656; ";
				s << i2p::client::context.GetAddressBook ().ToAddress(ident);
				s << "</div>\r\n"<< std::endl;
			}
			s << "</div>\r\n";
		}
	}

	HTTPConnection::HTTPConnection (std::string hostname, std::shared_ptr<boost::asio::ip::tcp::socket> socket):
		m_Socket (socket), m_BufferLen (0), expected_host(hostname)
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

	bool HTTPConnection::CheckAuth (const HTTPReq & req)
	{
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
			std::string expected = "Basic " + i2p::data::ToBase64Standard (user + ":" + pass);
			if (expected == provided) return true;
		}

		LogPrint(eLogWarning, "HTTPServer: Auth failure from ", m_Socket->remote_endpoint().address ());
		return false;
	}

	void HTTPConnection::HandleRequest (const HTTPReq & req)
	{
		std::stringstream s;
		std::string content;
		HTTPRes res;

		LogPrint(eLogDebug, "HTTPServer: Request: ", req.uri);

		if (needAuth && !CheckAuth(req)) {
			res.code = 401;
			res.add_header("WWW-Authenticate", "Basic realm=\"WebAdmin\"");
			SendReply(res, content);
			return;
		}

		bool strictheaders;
		i2p::config::GetOption("http.strictheaders", strictheaders);
		if (strictheaders)
		{
			std::string http_hostname;
			i2p::config::GetOption("http.hostname", http_hostname);
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

		// HTML head start
		ShowPageHead (s);
		if (req.uri.find("page=") != std::string::npos) {
			HandlePage (req, res, s);
		} else if (req.uri.find("cmd=") != std::string::npos) {
			HandleCommand (req, res, s);
		} else {
			ShowStatus (s, true, i2p::http::OutputFormatEnum::forWebConsole);
			res.add_header("Refresh", "10");
		}
		ShowPageTail (s);

		res.code = 200;
		content = s.str ();
		SendReply (res, content);
	}

	std::map<uint32_t, uint32_t> HTTPConnection::m_Tokens;

	uint32_t HTTPConnection::CreateToken ()
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
		return token;
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
		{
			uint32_t token = CreateToken ();
			ShowCommands (s, token);
		}
		else if (page == HTTP_PAGE_TRANSIT_TUNNELS)
			ShowTransitTunnels (s);
		else if (page == HTTP_PAGE_LOCAL_DESTINATIONS)
			ShowLocalDestinations (s);
		else if (page == HTTP_PAGE_LOCAL_DESTINATION)
		{
			uint32_t token = CreateToken ();
			ShowLocalDestination (s, params["b32"], token);
		}
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
			ShowError(s, tr("Unknown page") + ": " + page);
			return;
		}
	}

	void HTTPConnection::HandleCommand (const HTTPReq& req, HTTPRes& res, std::stringstream& s)
	{
		std::map<std::string, std::string> params;
		URL url;

		url.parse(req.uri);
		url.parse_query(params);

		std::string webroot; i2p::config::GetOption("http.webroot", webroot);
		std::string redirect = std::to_string(COMMAND_REDIRECT_TIMEOUT) + "; url=" + webroot + "?page=commands";
		std::string token = params["token"];

		if (token.empty () || m_Tokens.find (std::stoi (token)) == m_Tokens.end ())
		{
			ShowError(s, tr("Invalid token"));
			return;
		}

		std::string cmd = params["cmd"];
		if (cmd == HTTP_COMMAND_RUN_PEER_TEST)
			i2p::transport::transports.PeerTest ();
		else if (cmd == HTTP_COMMAND_RELOAD_TUNNELS_CONFIG)
			i2p::client::context.ReloadConfig ();
		else if (cmd == HTTP_COMMAND_ENABLE_TRANSIT)
			i2p::context.SetAcceptsTunnels (true);
		else if (cmd == HTTP_COMMAND_DISABLE_TRANSIT)
			i2p::context.SetAcceptsTunnels (false);
		else if (cmd == HTTP_COMMAND_SHUTDOWN_START)
		{
			i2p::context.SetAcceptsTunnels (false);
#if ((!defined(WIN32) && !defined(QT_GUI_LIB) && !defined(ANDROID)) || defined(ANDROID_BINARY))
			Daemon.gracefulShutdownInterval = 10*60;
#elif defined(WIN32_APP)
			i2p::win32::GracefulShutdown ();
#endif
		}
		else if (cmd == HTTP_COMMAND_SHUTDOWN_CANCEL)
		{
			i2p::context.SetAcceptsTunnels (true);
#if ((!defined(WIN32) && !defined(QT_GUI_LIB) && !defined(ANDROID)) || defined(ANDROID_BINARY))
			Daemon.gracefulShutdownInterval = 0;
#elif defined(WIN32_APP)
			i2p::win32::StopGracefulShutdown ();
#endif
		}
		else if (cmd == HTTP_COMMAND_SHUTDOWN_NOW)
		{
#ifndef WIN32_APP
			Daemon.running = false;
#else
			i2p::win32::StopWin32App ();
#endif
		}
		else if (cmd == HTTP_COMMAND_LOGLEVEL)
		{
			std::string level = params["level"];
			SetLogLevel (level);
		}
		else if (cmd == HTTP_COMMAND_KILLSTREAM)
		{
			std::string b32 = params["b32"];
			uint32_t streamID = std::stoul(params["streamID"], nullptr);

			i2p::data::IdentHash ident;
			ident.FromBase32 (b32);
			auto dest = i2p::client::context.FindLocalDestination (ident);

			if (streamID)
			{
				if (dest)
				{
					if (dest->DeleteStream (streamID))
						s << "<b>" << tr("SUCCESS") << "</b>:&nbsp;" << tr("Stream closed") << "<br>\r\n<br>\r\n";
					else
						s << "<b>" << tr("ERROR") << "</b>:&nbsp;" << tr("Stream not found or already was closed") << "<br>\r\n<br>\r\n";
				}
				else
					s << "<b>" << tr("ERROR") << "</b>:&nbsp;" << tr("Destination not found") << "<br>\r\n<br>\r\n";
			}
			else
				s << "<b>" << tr("ERROR") << "</b>:&nbsp;" << tr("StreamID can't be null") << "<br>\r\n<br>\r\n";

			s << "<a href=\"" << webroot << "?page=local_destination&b32=" << b32 << "\">" << tr("Return to destination page") << "</a><br>\r\n";
			s << "<p>" << tr("You will be redirected in %d seconds", COMMAND_REDIRECT_TIMEOUT) << "</b>";
			redirect = std::to_string(COMMAND_REDIRECT_TIMEOUT) + "; url=" + webroot + "?page=local_destination&b32=" + b32;
			res.add_header("Refresh", redirect.c_str());
			return;
		}
		else if (cmd == HTTP_COMMAND_EXPIRELEASE)
		{
			std::string b32 = params["b32"];
			std::string lease = params["lease"];

			i2p::data::IdentHash ident, leaseident;
			ident.FromBase32 (b32);
			leaseident.FromBase32 (lease);
			auto dest = i2p::client::context.FindLocalDestination (ident);

			if (dest)
			{
				auto leaseset = dest->FindLeaseSet (leaseident);
				if (leaseset)
				{
					leaseset->ExpireLease ();
					s << "<b>" << tr("SUCCESS") << "</b>:&nbsp;" << tr("LeaseSet expiration time updated") << "<br>\r\n<br>\r\n";
				}
				else
					s << "<b>" << tr("ERROR") << "</b>:&nbsp;" << tr("LeaseSet is not found or already expired") << "<br>\r\n<br>\r\n";
			}
			else
				s << "<b>" << tr("ERROR") << "</b>:&nbsp;" << tr("Destination not found") << "<br>\r\n<br>\r\n";

			s << "<a href=\"" << webroot << "?page=local_destination&b32=" << b32 << "\">" << tr("Return to destination page") << "</a><br>\r\n";
			s << "<p>" << tr("You will be redirected in %d seconds", COMMAND_REDIRECT_TIMEOUT) << "</b>";
			redirect = std::to_string(COMMAND_REDIRECT_TIMEOUT) + "; url=" + webroot + "?page=local_destination&b32=" + b32;
			res.add_header("Refresh", redirect.c_str());
			return;
		}
		else if (cmd == HTTP_COMMAND_LIMITTRANSIT)
		{
			uint32_t limit = std::stoul(params["limit"], nullptr);
			if (limit > 0 && limit <= TRANSIT_TUNNELS_LIMIT)
				i2p::tunnel::tunnels.SetMaxNumTransitTunnels (limit);
			else {
				s << "<b>" << tr("ERROR") << "</b>:&nbsp;" << tr("Transit tunnels count must not exceed %d", TRANSIT_TUNNELS_LIMIT) << "\r\n<br>\r\n<br>\r\n";
				s << "<a href=\"" << webroot << "?page=commands\">" << tr("Back to commands list") << "</a>\r\n<br>\r\n";
				s << "<p>" << tr("You will be redirected in %d seconds", COMMAND_REDIRECT_TIMEOUT) << "</b>";
				res.add_header("Refresh", redirect.c_str());
				return;
			}
		}
		else if (cmd == HTTP_COMMAND_GET_REG_STRING)
		{
			std::string b32 = params["b32"];
			std::string name = i2p::http::UrlDecode(params["name"]);

			i2p::data::IdentHash ident;
			ident.FromBase32 (b32);
			auto dest = i2p::client::context.FindLocalDestination (ident);

			if (dest)
			{
				std::size_t pos;
				pos = name.find (".i2p");
				if (pos == (name.length () - 4))
				{
					pos = name.find (".b32.i2p");
					if (pos == std::string::npos)
					{
						auto signatureLen = dest->GetIdentity ()->GetSignatureLen ();
						uint8_t * signature = new uint8_t[signatureLen];
						char * sig = new char[signatureLen*2];
						std::stringstream out;

						out << name << "=" << dest->GetIdentity ()->ToBase64 ();
						dest->Sign ((uint8_t *)out.str ().c_str (), out.str ().length (), signature);
						auto len = i2p::data::ByteStreamToBase64 (signature, signatureLen, sig, signatureLen*2);
						sig[len] = 0;
						out << "#!sig=" << sig;
						s << "<b>" << tr("SUCCESS") << "</b>:<br>\r\n<form action=\"http://shx5vqsw7usdaunyzr2qmes2fq37oumybpudrd4jjj4e4vk4uusa.b32.i2p/add\" method=\"post\" rel=\"noreferrer\" target=\"_blank\">\r\n"
						     "<textarea readonly name=\"record\" cols=\"80\" rows=\"10\">" << out.str () << "</textarea>\r\n<br>\r\n<br>\r\n"
						     "<b>" << tr("Register at reg.i2p") << ":</b>\r\n<br>\r\n"
						     "<b>" << tr("Description") << ":</b>\r\n<input type=\"text\" maxlength=\"64\" name=\"desc\" placeholder=\"" << tr("A bit information about service on domain") << "\">\r\n"
						     "<input type=\"submit\" value=\"" << tr("Submit") << "\">\r\n"
						     "</form>\r\n<br>\r\n";
						delete[] signature;
						delete[] sig;
					}
					else
						s << "<b>" << tr("ERROR") << "</b>:&nbsp;" << tr("Domain can't end with .b32.i2p") << "\r\n<br>\r\n<br>\r\n";
				}
				else
					s << "<b>" << tr("ERROR") << "</b>:&nbsp;" << tr("Domain must end with .i2p") << "\r\n<br>\r\n<br>\r\n";
			}
			else
				s << "<b>" << tr("ERROR") << "</b>:&nbsp;" << tr("Such destination is not found") << "\r\n<br>\r\n<br>\r\n";

			s << "<a href=\"" << webroot << "?page=local_destination&b32=" << b32 << "\">" << tr("Return to destination page") << "</a>\r\n";
			return;
		}
		else if (cmd == HTTP_COMMAND_SETLANGUAGE)
		{
			std::string lang = params["lang"];
			std::string currLang = i2p::client::context.GetLanguage ()->GetLanguage();

			if (currLang.compare(lang) != 0)
				i2p::i18n::SetLanguage(lang);
		}
		else if (cmd == HTTP_COMMAND_RELOAD_CSS)
		{
			LoadExtCSS();
		}
		else
		{
			res.code = 400;
			ShowError(s, tr("Unknown command") + ": " + cmd);
			return;
		}

		s << "<b>" << tr("SUCCESS") << "</b>:&nbsp;" << tr("Command accepted") << "<br><br>\r\n";
		s << "<a href=\"" << webroot << "?page=commands\">" << tr("Back to commands list") << "</a><br>\r\n";
		s << "<p>" << tr("You will be redirected in %d seconds", COMMAND_REDIRECT_TIMEOUT) << "</b>";
		res.add_header("Refresh", redirect.c_str());
	}

	void HTTPConnection::SendReply (HTTPRes& reply, std::string& content)
	{
		reply.add_header("X-Frame-Options", "SAMEORIGIN");
		reply.add_header("X-Content-Type-Options", "nosniff");
		reply.add_header("X-XSS-Protection", "1; mode=block");
		reply.add_header("Content-Type", "text/html");
		reply.body = content;

		m_SendBuffer = reply.to_string();
		boost::asio::async_write (*m_Socket, boost::asio::buffer(m_SendBuffer), boost::asio::transfer_all (), 
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
			LogPrint(eLogInfo, "HTTPServer: Password set to ", pass);
		}

		m_IsRunning = true;
		m_Thread.reset (new std::thread (std::bind (&HTTPServer::Run, this)));
		m_Acceptor.listen ();
		Accept ();

		LoadExtCSS();
	}

	void HTTPServer::Stop ()
	{
		m_IsRunning = false;

		boost::system::error_code ec;
		m_Acceptor.cancel(ec);
		if (ec)
			LogPrint (eLogDebug, "HTTPServer: Error while cancelling operations on acceptor: ", ec.message ());
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
		i2p::util::SetThreadName("Webconsole");

		while (m_IsRunning)
		{
			try
			{
				m_Service.run ();
			}
			catch (std::exception& ex)
			{
				LogPrint (eLogError, "HTTPServer: Runtime exception: ", ex.what ());
			}
		}
	}

	void HTTPServer::Accept ()
	{
		auto newSocket = std::make_shared<boost::asio::ip::tcp::socket> (m_Service);
		m_Acceptor.async_accept (*newSocket, std::bind (&HTTPServer::HandleAccept, this,
			std::placeholders::_1, newSocket));
	}

	void HTTPServer::HandleAccept(const boost::system::error_code& ecode,
		std::shared_ptr<boost::asio::ip::tcp::socket> newSocket)
	{
		if (!ecode)
			CreateConnection(newSocket);
		else
		{
			if (newSocket) newSocket->close();
			LogPrint(eLogError, "HTTP Server: Error handling accept: ", ecode.message());
		}
		Accept ();
	}

	void HTTPServer::CreateConnection(std::shared_ptr<boost::asio::ip::tcp::socket> newSocket)
	{
		auto conn = std::make_shared<HTTPConnection> (m_Hostname, newSocket);
		conn->Receive ();
	}
} // http
} // i2p
