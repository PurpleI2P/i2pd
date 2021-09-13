/*
* Copyright (c) 2013-2020, The PurpleI2P Project
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

	const char HTTP_PAGE_TUNNEL_SUMMARY[] = "tunnel_summary";
	const char HTTP_PAGE_LOCAL_TUNNELS[] = "local_tunnels";
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
	const char HTTP_COMMAND_LOGLEVEL[] = "set_loglevel";
	const char HTTP_COMMAND_KILLSTREAM[] = "closestream";
	const char HTTP_COMMAND_LIMITTRANSIT[] = "limittransit";
	const char HTTP_COMMAND_GET_REG_STRING[] = "get_reg_string";
	const char HTTP_COMMAND_SETLANGUAGE[] = "setlanguage";
	const char HTTP_COMMAND_RELOAD_CSS[] = "reload_css";
	const char HTTP_PARAM_SAM_SESSION_ID[] = "id";
	const char HTTP_PARAM_ADDRESS[] = "address";

	static std::string ConvertTime (uint64_t time)
	{
		lldiv_t divTime = lldiv(time, 1000);
		time_t t = divTime.quot;
		struct tm *tm = localtime(&t);
		char date[128];
		snprintf(date, sizeof(date), "%02d/%02d/%d %02d:%02d:%02d.%03lld",
			tm->tm_mday, tm->tm_mon + 1, tm->tm_year + 1900, tm->tm_hour, tm->tm_min, tm->tm_sec, divTime.rem);
		return date;
	}

	static void ShowUptime (std::stringstream& s, int seconds)
	{
		int num;

		if ((num = seconds / 86400) > 0) {
			s << num << " " << tr("day", "days", num) << ", ";
			seconds -= num * 86400;
		}
		if ((num = seconds / 3600) > 0) {
			s << num << " " << tr("hour", "hours", num) << ", ";
			seconds -= num * 3600;
		}
		if ((num = seconds / 60) > 0) {
			s << num << " " << tr("minute", "minutes", num) << ", ";
			seconds -= num * 60;
		}
		s << seconds << " " << tr("second", "seconds", seconds);
	}

	static void ShowTraffic (std::stringstream& s, uint64_t bytes)
	{
		s << std::fixed << std::setprecision(0);
		auto numKBytes = (double) bytes / 1024;
		if (numKBytes < 1) {
			s << std::fixed << std::setprecision(2);
			s << numKBytes * 1024 << "&#8239;" << tr(/* tr: Byte */ "B");
		} else if (numKBytes < 1024) {
			s << numKBytes << "&#8239;" << tr(/* tr: Kibibit */ "K");
		} else if (numKBytes < 1024 * 1024) {
			s << std::fixed << std::setprecision(1);
			s << numKBytes / 1024 << "&#8239;" << tr(/* tr: Mebibit */ "M");
		} else if (numKBytes < 1024 * 1024 * 1024) {
			s << std::fixed << std::setprecision(2);
			s << numKBytes / 1024 / 1024 << "&#8239;" << tr(/* tr: Gibibit */ "G");
		} else {
			s << numKBytes / 1024 / 1024 / 1024 << "&#8239;" << tr(/* tr: Tibibit */ "T");
		}
	}

	static void ShowTunnelDetails (std::stringstream& s, enum i2p::tunnel::TunnelState eState, bool explr, double bytes)
	{
		std::string state, stateText;
		switch (eState) {
			case i2p::tunnel::eTunnelStateBuildReplyReceived :
			case i2p::tunnel::eTunnelStatePending     : state = "building";    break;
			case i2p::tunnel::eTunnelStateBuildFailed :
			case i2p::tunnel::eTunnelStateTestFailed  :
			case i2p::tunnel::eTunnelStateFailed      : state = "failed";      break;
			case i2p::tunnel::eTunnelStateExpiring    : state = "expiring";    break;
			case i2p::tunnel::eTunnelStateEstablished : state = "established"; break;
			default: state = "unknown"; break;
		}

		if      (state == "building")    stateText = tr("building");
		else if (state == "failed")      stateText = tr("failed");
		else if (state == "expiring")    stateText = tr("expiring");
		else if (state == "established") stateText = tr("established");
		else stateText = tr("unknown");

		s << "<span class=\"tunnel " << state << ((explr) ? " exploratory" : "")
		  << "\" data-tooltip=\"" << stateText << ((explr) ? " (" + tr("exploratory") + ")" : "") << "\">"
		  << stateText << ((explr) ? " (" + tr("exploratory") + ")" : "") << "</span>";
		s << std::fixed << std::setprecision(0);
		if (bytes > 1024 * 1024 * 1024) {
			s << std::fixed << std::setprecision(2);
			s << " <span class=\"transferred\">" << (double) (bytes / 1024 / 1024 / 1024) << "G</span>\r\n";
		} else if (bytes > 1024 * 1024) {
			s << std::fixed << std::setprecision(1);
			s << " <span class=\"transferred\">" << (double) (bytes / 1024 / 1024) << "M</span>\r\n";
		} else if (bytes > 1024) {
			s << " <span class=\"transferred\">" << (int) (bytes / 1024) << "K</span>\r\n";
		} else {
			s << " <span class=\"transferred\">" << (int) (bytes) << "B</span>\r\n";
		}
	}

	static void SetLogLevel (const std::string& level)
	{
		if (level == "none" || level == "error" || level == "warn" || level == "info" || level == "debug")
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
		// SAM
		auto sam = i2p::client::context.GetSAMBridge ();

		std::map<std::string, std::string> params;
		std::string page("");
		URL url;
		url.parse_query(params);
		page = params["page"];
		std::string token = params["token"];

		s << "<!DOCTYPE html>\r\n"
			 "<html lang=\"" << langCode << "\">\r\n"
			 "<head>\r\n" /* TODO: Find something to parse html/template system. This is horrible. */
			 "<meta charset=\"UTF-8\">\r\n"
			 "<meta name=\"viewport\" content=\"width=device-width, initial-scale=1.0\">\r\n"
			 "<link rel=\"shortcut icon\" href=\"" << i2pdfavicon << "\">\r\n"
			 "<title>Purple I2P | " VERSION "</title>\r\n";
		GetStyles(s);
		s << "</head>\r\n"
			 "<body>\r\n"
			 "<div class=\"wrapper\">\r\n<table id=\"main\">\r\n"
			 "<tr id=\"header\"><td class=\"center\" colspan=\"2\"><span class=\"header\">"
			 "<a id=\"home\" href=\"" << webroot << "\">" << tr("Main page") << "</a> "
			 // TODO placeholder for graceful shutdown button (requires token)
			 "<a id=\"shutdownbutton\" href=\"" << webroot << "?cmd="
		  << HTTP_COMMAND_SHUTDOWN_START << "&amp;token=" << token << "\" data-tooltip=\""
		  << tr("Start graceful shutdown") << "\">Shutdown</a>";
		// placeholder for toggle transit (requires token)
		if (i2p::context.AcceptsTunnels ()) {
			s << "<a id=\"disabletransit\" href=\"" << webroot << "?cmd="
			  << HTTP_COMMAND_DISABLE_TRANSIT << "&amp;token=" << token
			  << "\" data-tooltip=\"" << tr("Decline transit tunnels")
			  << "\">No transit</a>";
		} else {
			s << "<a id=\"enabletransit\" href=\"" << webroot << "?cmd="
			  << HTTP_COMMAND_ENABLE_TRANSIT << "&amp;token=" << token
			  << "\" data-tooltip=\"" << tr("Accept transit tunnels")
			  << "\">Accept transit</a>";
		}
		s << "</span></td></tr>\r\n"
		  << "<tr id=\"nav\"><td id=\"navlinks\" class=\"center\" colspan=\"2\">\r\n";
		if (i2p::context.IsFloodfill ())
			s << "<a href=\"" << webroot << "?page=" << HTTP_PAGE_LEASESETS << "\">" << tr("LeaseSets") << "</a>\r\n";
		s << "<a title=\"" << tr("Local destinations currently active") << "\" href=\"" << webroot << "?page="
		  << HTTP_PAGE_LOCAL_DESTINATIONS << "\">" << tr("Destinations") << "</a>\r\n"
//			 "<a title=\"" << tr("Local Service Tunnels") << "\" href=\"" << webroot << "?page=" << HTTP_PAGE_I2P_TUNNELS << "\">" << tr("Services") << "</a>\r\n"
//			 "<a title=\"" << tr("Active Transit Tunnels") << "\" href=\"" << webroot << "?page=" << HTTP_PAGE_TRANSIT_TUNNELS << "\">" << tr("Transit") << "</a>\r\n"
			 "<a title=\"" << tr("Router Transports and associated connections") << "\" href=\"" << webroot <<
			 "?page=" << HTTP_PAGE_TRANSPORTS << "\">" << tr ("Transports") << "</a>\r\n"
			 "<a title=\"" << tr("All active tunnels") << "\" href=\"" << webroot << "?page="
		  << HTTP_PAGE_TUNNEL_SUMMARY << "\">" << tr("Tunnels") << "</a>\r\n";
		if (sam && sam->GetSessions ().size ()) {
			s << "<a title=\"" << tr("Current SAM sessions") << "\" href=\"" << webroot << "?page="
			  << HTTP_PAGE_SAM_SESSIONS << "\">" << tr("SAM Sessions") << "</a>\r\n";
		}
		s << "<a title=\"" << tr("Router control and temporary configuration") << "\" href=\"" << webroot
		  << "?page=" << HTTP_PAGE_COMMANDS << "\">" << tr("Control") << "</a>\r\n</td></tr>\r\n";
	}

	static void ShowPageTail (std::stringstream& s)
	{
		s << "</table>\r\n"
			 "</div>\r\n"
			 "</body>\r\n"
			 "</html>\r\n";
	}

	static void ShowError(std::stringstream& s, const std::string& string)
	{
		s << "<tr class=\"toast\"><td class=\"center error\" colspan=\"2\"><span class=\"container\"><span id=\"warning\"></span>\r\n<b>" << tr("ERROR")
		  << ":</b>&nbsp;" << string << "</span></td></tr>\r\n";
	}

	static void ShowNetworkStatus (std::stringstream& s, RouterStatus status)
	{
		switch (status)
		{
			case eRouterStatusOK: s << tr("OK"); break;
			case eRouterStatusTesting: s << tr("Testing"); break;
			case eRouterStatusFirewalled: s << tr("Firewalled"); break;
			case eRouterStatusUnknown: s << tr("Unknown"); break;
			case eRouterStatusProxy: s << tr("Proxy"); break;
			case eRouterStatusMesh: s << tr("Mesh"); break;
			case eRouterStatusError:
			{
				s << tr("Error");
				switch (i2p::context.GetError ())
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
					default: ;
				}
				break;
			}
			default: s << tr("Unknown");
		}
	}

	void ShowStatus (std::stringstream& s, bool includeHiddenContent, i2p::http::OutputFormatEnum outputFormat)
	{
		s << "<tr><td>" << tr("Network Status") << "</td><td id=\"netstatus\">";
		ShowNetworkStatus (s, i2p::context.GetStatus ());
		if (i2p::context.SupportsV6 ()) {
			s << "<span class=\"badge\">" << tr("IPv6") << "</span> ";
			ShowNetworkStatus (s, i2p::context.GetStatusV6 ());
		}
		s << "</td></tr>\r\n";
#if ((!defined(WIN32) && !defined(QT_GUI_LIB) && !defined(ANDROID)) || defined(ANDROID_BINARY))
		if (auto remains = Daemon.gracefulShutdownInterval) {
			s << "<tr><td>" << tr("Shutdown") << "</td><td>";
			ShowUptime(s, remains);
			s << "&hellip;</td></tr>\r\n";
		}
#elif defined(WIN32_APP)
		if (i2p::win32::g_GracefulShutdownEndtime != 0) {
			uint16_t remains = (i2p::win32::g_GracefulShutdownEndtime - GetTickCount()) / 1000;
			s << "<tr><td>" << tr("Shutdown") << "</td><td>";
			ShowUptime(s, remains);
			s << "&hellip;</td></tr>\r\n";
		}
#endif
		s << "<tr><td>" << tr("Bandwidth") << "</td><td><span class=\"router recvd\">";
		s << std::fixed << std::setprecision(0);
		if (i2p::transport::transports.GetInBandwidth () > 1024*1024*1024 ||
			i2p::transport::transports.GetInBandwidth () < 10240 &&
			i2p::transport::transports.GetInBandwidth () > 0)
			s << std::fixed << std::setprecision(2);
		else if (i2p::transport::transports.GetInBandwidth () > 1024*1024)
			s << std::fixed << std::setprecision(1);
		s << (double) i2p::transport::transports.GetInBandwidth () / 1024 << "&#8239;" << tr(/* tr: Kibibit/s */ "K/s");
		s << "</span> <span class=\"hide\">/</span> <span class=\"router sent\">";
		s << std::fixed << std::setprecision(0);
		if (i2p::transport::transports.GetOutBandwidth () > 1024*1024*1024 ||
			i2p::transport::transports.GetOutBandwidth () < 10240 &&
			i2p::transport::transports.GetOutBandwidth () > 0)
			s << std::fixed << std::setprecision(2);
		else if (i2p::transport::transports.GetOutBandwidth () > 1024*1024)
			s << std::fixed << std::setprecision(1);
		s << (double) i2p::transport::transports.GetOutBandwidth () / 1024 << "&#8239;" << tr(/* tr: Kibibit/s */ "K/s");
		s << "</span>";

		if ((i2p::context.AcceptsTunnels() || i2p::tunnel::tunnels.CountTransitTunnels()) &&
			(i2p::transport::transports.GetTotalReceivedBytes () > 0)) {
			s << std::fixed << std::setprecision(0);
			if (i2p::transport::transports.GetTransitBandwidth () > 1024*1024*1024 ||
				i2p::transport::transports.GetTransitBandwidth () < 10240 &&
				i2p::transport::transports.GetTransitBandwidth () > 0)
				s << std::fixed << std::setprecision(2);
			else if (i2p::transport::transports.GetTransitBandwidth () > 1024*1024)
				s << std::fixed << std::setprecision(1);
			s << " <span class=\"hide\">/</span> <span class=\"transit sent\" data-tooltip=\"";
			s << tr("Transit bandwidth usage") << "\">";
			s << (double) i2p::transport::transports.GetTransitBandwidth () / 1024;
			s << "&#8239;" << tr(/* tr: Kibibit/s */ "K/s") << "</span>";
		}

		s << "</td></tr>\r\n";
		s << "<tr><td>" << tr("Transferred") << "</td><td><span class=\"router recvd\">";
		s << std::fixed << std::setprecision(0);
		if (i2p::transport::transports.GetTotalReceivedBytes () > 1024*1024*1024)
			s << std::fixed << std::setprecision(2);
		else if (i2p::transport::transports.GetTotalReceivedBytes () > 1024*1024)
			s << std::fixed << std::setprecision(1);
		ShowTraffic (s, i2p::transport::transports.GetTotalReceivedBytes ());
		s << "</span> <span class=\"hide\">/</span> <span class=\"router sent\">";
		s << std::fixed << std::setprecision(0);
		if (i2p::transport::transports.GetTotalSentBytes () > 1024*1024*1024)
			s << std::fixed << std::setprecision(2);
		else if (i2p::transport::transports.GetTotalSentBytes () > 1024*1024)
			s << std::fixed << std::setprecision(1);
		ShowTraffic (s, i2p::transport::transports.GetTotalSentBytes ());
		s << "</span>";

		if ((i2p::context.AcceptsTunnels() || i2p::tunnel::tunnels.CountTransitTunnels()) &&
			(i2p::transport::transports.GetTotalReceivedBytes () > 0)) {
			s << " <span class=\"hide\">/</span> <span class=\"transit sent\" data-tooltip=\"";
			s << tr("Total transit data transferred") << "\">";
			s << std::fixed << std::setprecision(0); // should set 0 bytes to no decimal places, but doesn't!
			if (i2p::transport::transports.GetTotalTransitTransmittedBytes () > 1024*1024*1024)
				s << std::fixed << std::setprecision(2);
			else if (i2p::transport::transports.GetTotalTransitTransmittedBytes () > 1024*1024)
				s << std::fixed << std::setprecision(1);
			ShowTraffic (s, i2p::transport::transports.GetTotalTransitTransmittedBytes ());
			s << "</span>";
		}
		s << "</td></tr>\r\n";
		s << "<tr><td>" << tr("Build Success") << "</td><td>";
		s << i2p::tunnel::tunnels.GetTunnelCreationSuccessRate () << "%</td></tr>\r\n";
		s << "<tr><td>" << tr("Routers") << "</td><td>" << i2p::data::netdb.GetNumRouters () << "</td></tr>\r\n";
		s << "<tr><td>" << tr("Floodfills") << "</td><td>" << i2p::data::netdb.GetNumFloodfills () << "</td></tr>\r\n";
		s << "<tr><td>" << tr("LeaseSets") << "</td><td>" << i2p::data::netdb.GetNumLeaseSets () << "</td></tr>\r\n";

		size_t clientTunnelCount = i2p::tunnel::tunnels.CountOutboundTunnels();
		clientTunnelCount += i2p::tunnel::tunnels.CountInboundTunnels();
		std::string webroot; i2p::config::GetOption("http.webroot", webroot);

		if (!(i2p::context.AcceptsTunnels () || i2p::tunnel::tunnels.CountTransitTunnels()))
			s << "<tr id=\"last\">";
		else
			s << "<tr>";
		s << "<td>" << tr("Local Tunnels") << "</td><td>" << std::to_string(clientTunnelCount) << "</td></tr>\r\n";
		if (i2p::context.AcceptsTunnels () || i2p::tunnel::tunnels.CountTransitTunnels()) {
			s << "<tr id=\"last\"><td>" << tr("Transit Tunnels") << "</td><td>"
			  << std::to_string(i2p::tunnel::tunnels.CountTransitTunnels()) << "</td></tr>\r\n";
		}

		if(outputFormat==OutputFormatEnum::forWebConsole) {
			bool httpproxy  = i2p::client::context.GetHttpProxy ()         ? true : false;
			bool socksproxy = i2p::client::context.GetSocksProxy ()        ? true : false;
			bool bob        = i2p::client::context.GetBOBCommandChannel () ? true : false;
			bool sam        = i2p::client::context.GetSAMBridge ()         ? true : false;
			bool i2cp       = i2p::client::context.GetI2CPServer ()        ? true : false;
			bool i2pcontrol;  i2p::config::GetOption("i2pcontrol.enabled", i2pcontrol);
			if (httpproxy || socksproxy || bob || sam || i2cp || i2pcontrol) {
				s << "<tr class=\"center sectiontitle configuration\">"
				  << "<th colspan=\"2\"><span>" << tr("Router Services") << "</span>\r\n";
				s << "<div id=\"routerservices\" class=\"center\">";
				if (httpproxy)
					s << " <span class=\"routerservice\">HTTP " << tr("Proxy") << "</span> ";
				if (socksproxy)
					s << " <span class=\"routerservice\">SOCKS " << tr("Proxy") << "</span> ";
				if (bob)
					s << " <span class=\"routerservice\">BOB</span> ";
				if (sam)
					s << " <span class=\"routerservice\">SAM</span> ";
				if (i2cp)
					s << " <span class=\"routerservice\">I2CP</span> ";
				if (i2pcontrol)
					s << " <span class=\"routerservice\">I2PControl</span>";
				s << "</div>\r\n</th></tr>\r\n";
			}
		}

			s << "</tbody>\r\n";
	}

	void ShowLocalDestinations (std::stringstream& s)
	{
		std::string webroot; i2p::config::GetOption("http.webroot", webroot);
		s << "<tr class=\"sectiontitle\"><th colspan=\"2\"><span>" << tr("Client Destinations")
		  << "</span></th></tr>\r\n<tr><td class=\"center nopadding\" colspan=\"2\"><div class=\"list\">\r\n";
		for (auto& it: i2p::client::context.GetDestinations ())
		{
			auto ident = it.second->GetIdentHash ();
			s << "<div class=\"listitem\"><a href=\"" << webroot << "?page=" << HTTP_PAGE_LOCAL_DESTINATION << "&b32=" << ident.ToBase32 () << "\">";
			s << i2p::client::context.GetAddressBook ().ToAddress(ident) << "</a></div>\r\n" << std::endl;
		}
		s << "</div>\r\n</td></tr>\r\n";

		auto i2cpServer = i2p::client::context.GetI2CPServer ();
		if (i2cpServer && !(i2cpServer->GetSessions ().empty ()))
		{
			s << "<tr class=\"sectiontitle\"><th colspan=\"2\"><span>I2CP " << tr("Server Destinations")
			  << "</span></th></tr>\r\n<tr><td class=\"center nopadding i2cp\" colspan=\"2\"><div class=\"list\">\r\n";
			for (auto& it: i2cpServer->GetSessions ())
			{
				auto dest = it.second->GetDestination ();
				if (dest)
				{
					auto ident = dest->GetIdentHash ();
					auto& name = dest->GetNickname ();
					s << "<div class=\"listitem\"><a href=\"" << webroot << "?page=" << HTTP_PAGE_I2CP_LOCAL_DESTINATION << "&i2cp_id=" << it.first << "\">[ ";
					s << name << " ]</a> <span class=\"arrowleftright\">&#8660;</span> <span class=\"b32\">"
					  << i2p::client::context.GetAddressBook ().ToAddress(ident) <<"</span></div>\r\n" << std::endl;
				}
			}
			s << "</div>\r\n</td></tr>\r\n";
		}
	}

	static void ShowLeaseSetDestination (std::stringstream& s, std::shared_ptr<const i2p::client::LeaseSetDestination> dest, uint32_t token)
	{
		s << "<tr><td class=\"center nopadding\" colspan=\"2\">\r\n";
		s << "<div class=\"slide\"><input hidden type=\"checkbox\" class=\"toggle\" id=\"slide_b64\" />\r\n"
		  << "<label for=\"slide_b64\">" << tr("Base64 Address") << "</label>\r\n";
		s << "<div class=\"slidecontent\">\r\n<div id=\"b64\">";
		s << dest->GetIdentity ()->ToBase64 () << "</div>\r\n</div>\r\n</div>\r\n</td></tr>\r\n";
		if (dest->IsEncryptedLeaseSet ())
		{
			i2p::data::BlindedPublicKey blinded (dest->GetIdentity (), dest->IsPerClientAuth ());
			s << "<tr><th colspan=\"2\">" << tr("Encrypted B33 Address") << "</td</th>\r\n";
			s << "<tr><td colspan=\"2\">" << blinded.ToB33 () << ".b32.i2p</td></tr>\r\n";
		}

		if(dest->IsPublic())
		{
			std::string webroot; i2p::config::GetOption("http.webroot", webroot);
			auto base32 = dest->GetIdentHash ().ToBase32 ();
			s << "<tr><th class=\"left\" colspan=\"2\">" << tr("Address Registration String") << "</th></tr>\r\n"
				 "<tr><td colspan=\"2\"><form class=\"register\" method=\"get\" action=\"" << webroot << "\">\r\n"
				 "  <input type=\"hidden\" name=\"cmd\" value=\"" << HTTP_COMMAND_GET_REG_STRING << "\">\r\n"
				 "  <input type=\"hidden\" name=\"token\" value=\"" << token << "\">\r\n"
				 "  <input type=\"hidden\" name=\"b32\" value=\"" << base32 << "\">\r\n"
				 "  <input type=\"text\" maxlength=\"67\" name=\"name\" placeholder=\"domain.i2p\" required>\r\n"
				 "  <button type=\"submit\">" << tr("Generate") << "</button>\r\n"
				 "</form>\r\n<div class=\"note\">";
			  s << tr("<b>Note:</b> Result string can be used only for registering 2LD domains (example.i2p).")
			    << " " << tr("For registering subdomains, please use i2pd-tools.");
			  s << "</div>\r\n</td></tr>\r\n";
		}

		if(dest->GetNumRemoteLeaseSets())
		{
			s << "<tr><td class=\"center nopadding\" colspan=\"2\">\r\n";
			s << "<div class=\"slide\">\r\n<input hidden type=\"checkbox\" class=\"toggle\" id=\"slide_leasesets\" />\r\n"
			  << "<label for=\"slide_leasesets\">" << tr("LeaseSets")
			  << " <span class=\"hide\">[</span><span class=\"badge\">" << dest->GetNumRemoteLeaseSets ()
			  << "</span><span class=\"hide\">]</span></label>\r\n";
			s << "<div class=\"slidecontent\">\r\n<table>\r\n<thead>\r\n<tr>"
			  << "<th class=\"left\">" << tr("Address") << "</th>"
			  << "<th class=\"thin\">" << tr("Type") << "</th>"
			  << "<th class=\"thin\">" << tr("EncType") << "</th>"
			  << "</thead>\r\n<tbody class=\"tableitem\">\r\n";
			for(auto& it: dest->GetLeaseSets ())
				s << "<tr><td class=\"left\"><span class=\"b32\">" << it.first.ToBase32 () << "</span></td>\r\n"
				  << "<td class=\"center thin\">" << (int)it.second->GetStoreType () << "</td>"
				  << "<td class=\"center thin\">" << (int)it.second->GetEncryptionType () <<"</td>"
				  << "</tr>\r\n";
			s << "</tbody>\r\n</table>\r\n</div>\r\n</div>\r\n</td></tr>\r\n";
		} else
			s << "<tr><th colspan=\"2\">" << tr("No LeaseSets currently active") << "</th><tr>\r\n";

		auto pool = dest->GetTunnelPool ();
		if (pool)
		{
			s << "<tr><td class=\"center nopadding\" colspan=\"2\">\r\n";
			s << "<div class=\"slide\">\r\n<input hidden type=\"checkbox\" class=\"toggle\" id=\"slide_tunnels\" />\r\n"
			  << "<label for=\"slide_tunnels\">" << tr("Tunnels") << "</label>\r\n";
			s << "<div class=\"slidecontent\">\r\n<div class=\"list\">\r\n";
			for (auto & it : pool->GetInboundTunnels ()) { // inbound tunnels
				s << "<div class=\"listitem in\">"
				  << "<span class=\"arrowdown\" data-tooltip=\"" << tr("Inbound") << "\">[" << tr("In") << "] </span>"
				  << "<span class=\"chain inbound\">";
				it->Print(s);
				if(it->LatencyIsKnown()) {
					s << " <span class=\"latency\" data-tooltip=\"" << tr("Average tunnel latency") << "\">";
					if (it->GetMeanLatency() >= 1000) {
						s << std::fixed << std::setprecision(2);
						s << (double) it->GetMeanLatency() / 1000 << tr(/* tr: seconds */ "s") << "</span> ";
					} else {
						s << it->GetMeanLatency() << tr(/* tr: Milliseconds */ "ms") << "</span> ";
					}
				} else { // placeholder for alignment
					s << " <span class=\"latency unknown\" data-tooltip=\"" << tr("Unknown tunnel latency") << "\">---&nbsp;</span> ";
				}
				ShowTunnelDetails(s, it->GetState (), false, it->GetNumReceivedBytes ());
				s << "</span></div>\r\n";
			}
			for (auto & it : pool->GetOutboundTunnels ()) { // outbound tunnels
				s << "<div class=\"listitem out\">"
				  << "<span class=\"arrowup\" data-tooltip=\"" << tr("Outbound") << "\">[" << tr("Out") << "] </span>"
				  << "<span class=\"chain outbound\">";
				it->Print(s);
				if(it->LatencyIsKnown()) {
					s << " <span class=\"latency\" data-tooltip=\"" << tr("Average tunnel latency") << "\">";
					if (it->GetMeanLatency() >= 1000) {
						s << std::fixed << std::setprecision(2);
						s << (double) it->GetMeanLatency() / 1000 << tr(/* tr: seconds */ "s") << "</span> ";
					} else {
						s << it->GetMeanLatency() << tr(/* tr: Milliseconds */ "ms") << "</span> ";
					}
				} else { // placeholder for alignment
					s << " <span class=\"latency unknown\" data-tooltip=\"" << tr("Unknown tunnel latency") << "\">---&nbsp;</span> ";
				}
				ShowTunnelDetails(s, it->GetState (), false, it->GetNumSentBytes ());
				s << "</span></div>\r\n";
			}
		}
		s << "</div>\r\n</div>\r\n</div>\r\n</td></tr>\r\n";

		if (dest->GetNumIncomingTags () > 0) {
			s << "<tr><th colspan=\"2\">" << tr("Incoming Session Tags")
			  << " <span class=\"hide\">[</span><span class=\"badge\">"
			  << dest->GetNumIncomingTags () << "</span><span class=\"hide\">]</span></th></tr>\r\n";
		} else {
			s << "<tr><th colspan=\"2\">" << tr("No Incoming Session Tags") << "</th></tr>\r\n";
		}
		if (!dest->GetSessions ().empty ()) {
			std::stringstream tmp_s; uint32_t out_tags = 0;
			s << "<tr><td class=\"center nopadding\" colspan=\"2\">";
			for (const auto& it: dest->GetSessions ()) {
				tmp_s << "<tr><td class=\"left\">" << i2p::client::context.GetAddressBook ().ToAddress(it.first)
					  << "</td><td class=\"center thin\">" << it.second->GetNumOutgoingTags () << "</td></tr>\r\n";
				out_tags += it.second->GetNumOutgoingTags ();
			}
			s << "<tr class=\"sectiontitle\"><th colspan=\"2\"><span>" << tr("Outgoing Session Tags")
			  << " <span class=\"hide\">[</span><span class=\"badge\">" << out_tags
			  << "</span><span class=\"hide\">]</span></th></tr>\r\n"
			  << "<tr><td class=\"center nopadding\" colspan=\"2\"><table>\r\n"
			  << "<thead>\r\n<tr><th class=\"left\">" << tr("Destination") << "</th><th class=\"thin\">" << tr("Count")
			  << "</th></thead>\r\n<tbody class=\"tableitem\">\r\n" << tmp_s.str () << "</tbody></table>\r\n</td></tr>\r\n";
		} else
			s << "<tr><th colspan=\"2\">" << tr("No Outgoing Session Tags") << "</th></tr>\r\n";

		auto numECIESx25519Tags = dest->GetNumIncomingECIESx25519Tags ();
		if (numECIESx25519Tags > 0) {
			s << "<tr class=\"sectiontitle\"><th colspan=\"2\"><span>ECIESx25519</span></th></tr>";
			s << "<tr><th colspan=\"2\">" << tr("Incoming Tags")
			  << " <span class=\"hide\">[</span><span class=\"badge\">" << numECIESx25519Tags
			  << "</span><span class=\"hide\">]</span></th></tr>\r\n";
			if (!dest->GetECIESx25519Sessions ().empty ())
			{
				std::stringstream tmp_s; uint32_t ecies_sessions = 0;
				for (const auto& it: dest->GetECIESx25519Sessions ()) {
					tmp_s << "<tr><td class=\"left\">"
					      << i2p::client::context.GetAddressBook ().ToAddress(it.second->GetDestination ())
					      << "</td><td class=\"center thin\">" << it.second->GetState () << "</td></tr>\r\n";
					ecies_sessions++;
				}
				s << "<tr><td class=\"center nopadding\" colspan=\"2\">\r\n"
				  << "<div class=\"slide\"><input hidden type=\"checkbox\" class=\"toggle\" id=\"slide-ecies-sessions\" />\r\n"
				  << "<label for=\"slide-ecies-sessions\">" << tr("Tag Sessions")
				  << " <span class=\"hide\">[</span><span class=\"badge\">" << ecies_sessions
				  << "</span><span class=\"hide\">]</span></label>\r\n"
				  << "<div class=\"slidecontent\">\r\n<table>\r\n<thead><th class=\"left\">" << tr("Destination") << "</th><th>"
				  << tr("Status") << "</th></thead>\r\n<tbody class=\"tableitem\">\r\n" << tmp_s.str () << "</tbody></table>\r\n</div>\r\n</div>\r\n";
			} else
				s << "<tr><th coslpan=\"2\">" << tr("No Tag Sessions") << "</th></tr>\r\n";
		}
	}

	void ShowLocalDestination (std::stringstream& s, const std::string& b32, uint32_t token)
	{
		i2p::data::IdentHash ident;
		ident.FromBase32 (b32);
		auto dest = i2p::client::context.FindLocalDestination (ident);
		if (dest) {
			std::string b32Short = b32.substr(0,6);
			s << "<tr class=\"sectiontitle\"><th colspan=\"2\"><span>" << tr("Local Destination")
			  << " <span class=\"hide\">[</span><span class=\"badge\">" << b32Short
			  << "</span><span class=\"hide\">]</span></th></tr>\r\n";
		} else
			s << "<tr class=\"sectiontitle\"><th colspan=\"2\"><span>" << tr("Local Destination")
			  << " <span class=\"hide\">[</span><span class=\"badge\">" << tr("Not Found")
			  << "</span><span class=\"hide\">]</span></th></tr>\r\n";

		if (dest)
		{
			ShowLeaseSetDestination (s, dest, token);
			// Print table with streams information
			s << "<tr><td class=\"center nopadding\" colspan=\"2\">\r\n";
			s << "<div class=\"slide\">\r\n<input hidden type=\"checkbox\" class=\"toggle\" id=\"slide-streams\" />\r\n"
			  << "<label for=\"slide-streams\">" << tr("Streams") << "</label>\r\n";
			s << "<div class=\"slidecontent\">\r\n<table>\r\n<thead>\r\n<tr>";
			s << "<th class=\"streamid\">ID</th>";
			s << "<th class=\"streamdest\">Destination</th>";
			s << "<th>TX</th>";
			s << "<th>RX</th>";
			s << "<th>Out</th>";
			s << "<th>In</th>";
			s << "<th>Buf</th>";
			s << "<th>RTT</th>";
			s << "<th>Win</th>";
			s << "<th>Status</th>";
			s << "</tr>\r\n</thead>\r\n";
			s << "<tbody class=\"tableitem\">\r\n";

			for (const auto& it: dest->GetAllStreams ())
			{
				auto streamDest = i2p::client::context.GetAddressBook ().ToAddress(it->GetRemoteIdentity ());
				std::string streamDestShort = streamDest.substr(0,10) + "&hellip;b32.i2p";
				s << "<tr>";
				s << "<td class=\"center nopadding streamid\">"
				  << "<a class=\"button\" href=\"/?cmd=" << HTTP_COMMAND_KILLSTREAM << "&b32=" << b32 << "&streamID="
				  << it->GetRecvStreamID () << "&token=" << token << "\" title=\"" << tr("Close stream")
				  << "\"><span class=\"close\">&#10005;</span> " << it->GetRecvStreamID () << "</a></td>";
				s << "<td class=\"streamdest\" title=\"" << streamDest << "\">" << streamDestShort << "</td>";
				s << std::fixed << std::setprecision(0);
				if (it->GetNumSentBytes () > 1024 * 1024 * 1024) {
					s << std::fixed << std::setprecision(2);
					s << "<td>" << (double) it->GetNumSentBytes ()  / 1024 / 1024 / 1024 << "G</td>";
				} else if (it->GetNumSentBytes () > 1024 * 1024) {
					s << std::fixed << std::setprecision(2);
					s << "<td>" << (double) it->GetNumSentBytes ()  / 1024 / 1024 << "M</td>";
				} else {
					s << "<td>" << it->GetNumSentBytes () / 1024 << "K</td>";
				}
				if (it->GetNumReceivedBytes () > 1024 * 1024 * 1024) {
					s << std::fixed << std::setprecision(2);
					s << "<td>" << (double) it->GetNumReceivedBytes ()  / 1024 / 1024 / 1024 << "G</td>";
				} else if (it->GetNumReceivedBytes () > 1024 * 1024) {
					s << std::fixed << std::setprecision(1);
					s << "<td>" << (double) it->GetNumReceivedBytes ()  / 1024 / 1024 << "M</td>";
				} else {
					s << "<td>" << it->GetNumReceivedBytes () / 1024 << "K</td>";
				}
				s << "<td>" << it->GetSendQueueSize () << "</td>";
				s << "<td>" << it->GetReceiveQueueSize () << "</td>";
				s << "<td>" << it->GetSendBufferSize () << "</td>";
				s << "<td>" << it->GetRTT () << "</td>";
				s << "<td>" << it->GetWindowSize () << "</td>";
				s << "<td class=\"center\">" << (int) it->GetStatus () << "</td>";
				s << "</tr>\r\n";
			}
			s << "</tbody>\r\n</table>\r\n</div>\r\n</div>\r\n</td></tr>";
		}
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
			s << "<tr><th class=\"nopadding\" colspan=\"2\">" << tr("LeaseSets") << "</th><tr>\r\n<tr><td class=\"center nopadding\"><div class=\"list\">\r\n";
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
						ls.reset (new i2p::data::LeaseSet2 (storeType, leaseSet->GetBuffer(), leaseSet->GetBufferLen()));
					if (!ls) return;
					s << "<div class=\"leaseset listitem";
					if (ls->IsExpired())
						s << " expired"; // additional css class for expired
					s << "\">\r\n";
					if (!ls->IsValid())
						s << "<div class=\"invalid\">!! " << tr("Invalid") << " !! </div>\r\n";
					s << "<div class=\"slide\"><input hidden type=\"checkbox\" class=\"toggle\" id=\"slide" << (counter++) << "\" />\r\n"
					  << "<label for=\"slide" << counter << "\">" << dest.ToBase32() << "</label>\r\n";
					s << "<div class=\"slidecontent\">\r\n";
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
			s << "</td></tr>\r\n";
			// end for each lease set
		}
		else if (!i2p::context.IsFloodfill ())
		{
			s << "<tr><th colspan=\"2\">" << tr("No LeaseSets") << " (" << tr("not floodfill") << ")</th</tr>\r\n";
		}
		else
		{
			s << "<tr><th colspan=\"2\">" << tr("No LeaseSets") << "</th</tr>\r\n";
		}
	}

	void ShowTunnels (std::stringstream& s)
	{
		s << "<tr class=\"sectiontitle\"><th colspan=\"2\"><span>" << tr("Local Tunnels") << "</span></th><tr>\r\n";
		s << "<tr><th colspan=\"2\">" << tr("Queue size") << ": " << i2p::tunnel::tunnels.GetQueueSize () << "</th></tr>\r\n";

		auto ExplPool = i2p::tunnel::tunnels.GetExploratoryPool ();

		s << "<tr><td class=\"center nopadding\" colspan=\"2\">\r\n";
		s << "<div class=\"slide\">\r\n<input hidden type=\"checkbox\" class=\"toggle\" id=\"slide_tunnels_exploratory\" />\r\n"
		  << "<label for=\"slide_tunnels_exploratory\">" << tr("Exploratory Tunnels") << " <span class=\"hide\">[</span><span class=\"badge\">" << "in/out"
			  << "</span><span class=\"hide\">]</span></label>\r\n"; // TODO: separate client & exploratory tunnels into sections and flag individual services?
		s << "<div class=\"slidecontent\">\r\n<div class=\"list\">\r\n";
		for (auto & it : i2p::tunnel::tunnels.GetInboundTunnels ()) {
			if (it->GetTunnelPool () == ExplPool) {
				s << "<div class=\"listitem in\">"
				  << "<span class=\"arrowdown\" data-tooltip=\"" << tr("Inbound") << "\">[" << tr("In") << "] </span>"
				  << "<span class=\"chain inbound\">";
				it->Print(s);
				if(it->LatencyIsKnown()) {
					s << " <span class=\"latency\" data-tooltip=\"" << tr("Average tunnel latency") << "\">";
					if (it->GetMeanLatency() >= 1000) {
						s << std::fixed << std::setprecision(2);
						s << (double) it->GetMeanLatency() / 1000 << tr(/* tr: seconds */ "s") << "</span> ";
					} else {
						s << it->GetMeanLatency() << tr(/* tr: Milliseconds */ "ms") << "</span> ";
					}
				} else { // placeholder for alignment
					s << " <span class=\"latency unknown\" data-tooltip=\"" << tr("Unknown tunnel latency") << "\">---&nbsp;</span> ";
				}
				ShowTunnelDetails(s, it->GetState (), (it->GetTunnelPool () == ExplPool), it->GetNumReceivedBytes ());
				s << "</span></div>\r\n";
			}
		}
		for (auto & it : i2p::tunnel::tunnels.GetOutboundTunnels ()) {
			if (it->GetTunnelPool () == ExplPool) {
				s << "<div class=\"listitem out\">"
				  << "<span class=\"arrowup\" data-tooltip=\"" << tr("Outbound") << "\">[" << tr("Out") << "] </span>"
				  << "<span class=\"chain outbound\">";
				it->Print(s);
				if(it->LatencyIsKnown()) {
					s << " <span class=\"latency\" data-tooltip=\"" << tr("Average tunnel latency") << "\">";
					if (it->GetMeanLatency() >= 1000) {
						s << std::fixed << std::setprecision(2);
						s << (double) it->GetMeanLatency() / 1000 << tr(/* tr: seconds */ "s") << "</span> ";
					} else {
						s << it->GetMeanLatency() << tr(/* tr: Milliseconds */ "ms") << "</span> ";
					}
				} else { // placeholder for alignment
					s << " <span class=\"latency unknown\" data-tooltip=\"" << tr("Unknown tunnel latency") << "\">---&nbsp;</span> ";
				}
				ShowTunnelDetails(s, it->GetState (), (it->GetTunnelPool () == ExplPool), it->GetNumSentBytes ());
				s << "</span>\r\n</div>\r\n";
			}
		}
		s << "</div>\r\n</div>\r\n</div>\r\n";


		s << "<div class=\"slide\">\r\n<input hidden type=\"checkbox\" class=\"toggle\" id=\"slide_tunnels_service\" />\r\n"
		  << "<label for=\"slide_tunnels_service\">" << tr("Service Tunnels") << " <span class=\"hide\">[</span><span class=\"badge\">" << "in/out"
			  << "</span><span class=\"hide\">]</span></label>\r\n"; // TODO: flag individual services by name
		s << "<div class=\"slidecontent\">\r\n<div class=\"list\">\r\n";
		for (auto & it : i2p::tunnel::tunnels.GetInboundTunnels ()) {
			if (it->GetTunnelPool () != ExplPool) {
				s << "<div class=\"listitem in\">"
				  << "<span class=\"arrowdown\" data-tooltip=\"" << tr("Inbound") << "\">[" << tr("In") << "] </span>"
				  << "<span class=\"chain inbound\">";
				it->Print(s);
				if(it->LatencyIsKnown()) {
					s << " <span class=\"latency\" data-tooltip=\"" << tr("Average tunnel latency") << "\">";
					if (it->GetMeanLatency() >= 1000) {
						s << std::fixed << std::setprecision(2);
						s << (double) it->GetMeanLatency() / 1000 << tr(/* tr: seconds */ "s") << "</span> ";
					} else {
						s << it->GetMeanLatency() << tr(/* tr: Milliseconds */ "ms") << "</span> ";
					}
				} else { // placeholder for alignment
					s << " <span class=\"latency unknown\" data-tooltip=\"" << tr("Unknown tunnel latency") << "\">---&nbsp;</span> ";
				}
				ShowTunnelDetails(s, it->GetState (), (it->GetTunnelPool () == ExplPool), it->GetNumReceivedBytes ());
				s << "</span></div>\r\n";
			}
		}
		for (auto & it : i2p::tunnel::tunnels.GetOutboundTunnels ()) {
			if (it->GetTunnelPool () != ExplPool) {
				s << "<div class=\"listitem out\">"
				  << "<span class=\"arrowup\" data-tooltip=\"" << tr("Outbound") << "\">[" << tr("Out") << "] </span>"
				  << "<span class=\"chain outbound\">";
				it->Print(s);
				if(it->LatencyIsKnown()) {
					s << " <span class=\"latency\" data-tooltip=\"" << tr("Average tunnel latency") << "\">";
					if (it->GetMeanLatency() >= 1000) {
						s << std::fixed << std::setprecision(2);
						s << (double) it->GetMeanLatency() / 1000 << tr(/* tr: seconds */ "s") << "</span> ";
					} else {
						s << it->GetMeanLatency() << tr(/* tr: Milliseconds */ "ms") << "</span> ";
					}
				} else { // placeholder for alignment
					s << " <span class=\"latency unknown\" data-tooltip=\"" << tr("Unknown tunnel latency") << "\">---&nbsp;</span> ";
				}
				ShowTunnelDetails(s, it->GetState (), (it->GetTunnelPool () == ExplPool), it->GetNumSentBytes ());
				s << "</span>\r\n</div>\r\n";
			}
		}
		s << "</div>\r\n</div>\r\n</div>\r\n</td></tr>\r\n";
	}

	void ShowTunnelSummary (std::stringstream& s) {
		std::string webroot; i2p::config::GetOption("http.webroot", webroot);
        size_t localInCount = i2p::tunnel::tunnels.CountInboundTunnels();
        size_t localOutCount = i2p::tunnel::tunnels.CountOutboundTunnels();
		size_t transitCount = i2p::tunnel::tunnels.CountTransitTunnels();
		s << "<tr class=\"sectiontitle\"><th colspan=\"2\"><span>" << tr("Tunnel Summary") << "</span></th></tr>\r\n";
		s << "<tr><td class=\"center nopadding\" colspan=\"2\">\r\n";
		s << "<table id=\"tunnelsummary\">\r\n<thead>"
		  << "<tr><th>" << tr("Type") << "</th>"
		  << "<th class=\"in\">" << tr("Inbound") << "</th><th class=\"out\">" << tr("Outbound") << "</th>"
		  << "<th>" << tr("View Details") << "</th></tr></thead>\r\n";
		s << "<tr><td>" << tr("Local") << "</td><td class=\"in\">" << localInCount << "</td><td class=\"out\">" << localOutCount << "</td>"
		  << "<td><a class=\"button\" href=\"" << webroot << "?page=" << HTTP_PAGE_LOCAL_TUNNELS << "\">View</a></td></tr>\r\n";
		if (transitCount > 0) {
		s << "<tr><td>" << tr("Transit") << "</td><td colspan=\"2\">" << transitCount << "</td>"
		  << "<td><a class=\"button\" href=\"" << webroot << "?page=" << HTTP_PAGE_TRANSIT_TUNNELS << "\">View</a></td></tr>\r\n";
		}
		s << "</table>\r\n";
		s << "<tr><td class=\"center nopadding\" colspan=\"2\">";
		ShowI2PTunnels (s);
		s << "</td></tr>\r\n";
	}

	static void ShowCommands (std::stringstream& s, uint32_t token)
	{
		s << "<tr><td class=\"center nopadding\" colspan=\"2\">\r\n";
		s << "<div class=\"slide\">\r\n<input hidden type=\"checkbox\" class=\"toggle\" id=\"slide_routerinfo\" />\r\n"
		  << "<label for=\"slide_routerinfo\">i2pd " VERSION "</label>\r\n";
		s << "<div class=\"slidecontent\">\r\n<table id=\"routerinfos\">\r\n";
		s << "<tr><td>" << tr("Router Identity") << "</td><td class=\"nopadding\"><span id=\"rid\">"
		  << i2p::context.GetRouterInfo().GetIdentHashBase64() << "</span></td></tr>\r\n";
		s << "<tr><td>" << tr("Router Caps") << "</td><td>" << i2p::context.GetRouterInfo().GetProperty("caps") << "</td></tr>\r\n";
		if (!i2p::context.GetRouterInfo().GetProperty("family").empty())
			s << "<tr><td>" << tr("Router Family") << "</td><td>"
			  << i2p::context.GetRouterInfo().GetProperty("family") << "</td></tr>\r\n";
		auto family = i2p::context.GetFamily ();
		if (family.length () > 0)
			s << "<tr><td>"<< tr("Family") << "</td><td>" << family << "<br>\r\n";
		for (const auto& address : i2p::context.GetRouterInfo().GetAddresses())
		{
			s << "<tr>\r\n";
			if (address->IsNTCP2 () && !address->IsPublishedNTCP2 ())
			{
				s << "<td>NTCP2";
				if (address->host.is_v6 ()) s << "v6";
				s << "</td><td><span class=\"enabled fixedsize\">" << tr("supported") << "</span></td>\r\n</tr>\r\n";
				continue;
			}
			switch (address->transportStyle)
			{
				case i2p::data::RouterInfo::eTransportNTCP:
				{
					s << "<td>NTCP";
					if (address->IsPublishedNTCP2 ()) s << "2";
					if (address->host.is_v6 ()) s << "v6";
					s << "</td>\r\n";
					break;
				}
				case i2p::data::RouterInfo::eTransportSSU:
				{
					s << "<td>SSU";
					if (address->host.is_v6 ())
						s << "v6";
					s << "</td>\r\n";
					break;
				}
				default:
					s << "<td>" << tr("Unknown") << "</td>\r\n";
			}
			s << "<td>" << address->host.to_string() << ":" << address->port << "</td>\r\n</tr>\r\n";
		}
		s << "<tr><td>" << tr("Uptime") << "</td><td>";
		ShowUptime(s, i2p::context.GetUptime ());
		s << "</td></tr>\r\n";
		s << "<tr><td>" << tr("Data path") << "</td><td>" << i2p::fs::GetUTF8DataDir() << "</td></tr>\r\n";
		s << "</table>\r\n</div>\r\n</div>\r\n</td></tr>\r\n";


		std::string webroot; i2p::config::GetOption("http.webroot", webroot);
		s << "<tr class=\"sectiontitle\"><th colspan=\"2\"><span>" << tr("Router Commands") << "</span>"
		  << "<div id=\"commands\" class=\"chrome\">\r\n";

		std::string styleFile = i2p::fs::DataDirPath ("webconsole/style.css");
		if (i2p::fs::Exists(styleFile)) {
		s << "<a id=\"reloadcss\" class=\"cmd\" href=\"" << webroot << "?cmd="
		  << HTTP_COMMAND_RELOAD_CSS << "&token=" << token
		  << "\" data-tooltip=\"" << tr("Reload external CSS stylesheet") << "\">"
		  << tr("Reload external CSS stylesheet") << "</a>";
		}

		s << "  <a id=\"testpeer\" class=\"cmd\" href=\"" << webroot << "?cmd="
		  << HTTP_COMMAND_RUN_PEER_TEST << "&token=" << token
		  << "\" data-tooltip=\"" << tr("Run peer test") << "\">"
		  << tr("Run peer test") << "</a><br>\r\n";

		// s << "  <a href=\"/?cmd=" << HTTP_COMMAND_RELOAD_CONFIG << "\">Reload config</a><br>\r\n";

		if (i2p::context.AcceptsTunnels ())
			s << "  <a id=\"transitdecline\" class=\"cmd\" href=\"" << webroot << "?cmd="
			  << HTTP_COMMAND_DISABLE_TRANSIT << "&token=" << token
			  << "\" data-tooltip=\"" << tr("Decline transit tunnels") << "\">"
			  << tr("Decline transit tunnels") << "</a><br>\r\n";
		else
			s << "  <a id=\"transitaccept\" class=\"cmd\" href=\"" << webroot << "?cmd="
			  << HTTP_COMMAND_ENABLE_TRANSIT << "&token=" << token
			  << "\" data-tooltip=\"" << tr("Accept transit tunnels") << "\">"
			  << tr("Accept transit tunnels") << "</a><br>\r\n";

		if (i2p::tunnel::tunnels.CountTransitTunnels()) {
#if ((!defined(WIN32) && !defined(QT_GUI_LIB) && !defined(ANDROID)) || defined(ANDROID_BINARY))
			if (Daemon.gracefulShutdownInterval)
				s << "  <a id=\"shutdowncancel\" class=\"cmd\" href=\"" << webroot << "?cmd="
				  << HTTP_COMMAND_SHUTDOWN_CANCEL << "&token=" << token
				  << "\" data-tooltip=\"" << tr("Cancel graceful shutdown") << "\">"
				  << tr("Cancel graceful shutdown") << "</a><br>\r\n";
			else
				s << "  <a id=\"shutdowngraceful\" class=\"cmd\" href=\"" << webroot << "?cmd="
				  << HTTP_COMMAND_SHUTDOWN_START << "&token=" << token
				  << "\" data-tooltip=\"" << tr("Start graceful shutdown") << "\">"
				  << tr("Start graceful shutdown") << "</a><br>\r\n";
#elif defined(WIN32_APP)
			if (i2p::util::DaemonWin32::Instance().isGraceful)
				s << "  <a id=\"shutdowncancel\" class=\"cmd\" href=\"" << webroot << "?cmd="
				  << HTTP_COMMAND_SHUTDOWN_CANCEL << "&token=" << token
				  << "\" data-tooltip=\"" << tr("Cancel graceful shutdown") << "\">"
				  << tr("Cancel graceful shutdown") << "</a><br>\r\n";
			else
				s << "  <a id=\"shutdowngraceful\" class=\"cmd\" href=\"" << webroot << "?cmd="
				  << HTTP_COMMAND_SHUTDOWN_START << "&token=" << token
				  << "\" data-tooltip=\"" << tr("Start graceful shutdown") << "\">"
				  << tr("Start graceful shutdown") << "</a><br>\r\n";
#endif
			s << "  <a id=\"shutdownforce\" class=\"cmd\" href=\"" << webroot << "?cmd="
			  << HTTP_COMMAND_SHUTDOWN_NOW << "&token=" << token
			  << "\" data-tooltip=\"" << tr("Force shutdown") << "\">"
			  << tr("Force shutdown") << "</a></th></tr>\r\n";

/* TODO graceful shutdown button in header with .notify dialog if transit tunnels
   active to offer option to shutdown immediately
   only one option? displayed in the header
*/
		} else {
			s << "  <a id=\"shutdownforce\" class=\"cmd\" href=\"" << webroot << "?cmd="
			  << HTTP_COMMAND_SHUTDOWN_NOW << "&token=" << token
			  << "\" data-tooltip=\"" << tr("Shutdown") << "\">"
			  << tr("Shutdown") << "</a>";
		}
		s << "</div></th></tr>\r\n";
		s << "<tr class=\"chrome notice\"><td class=\"center\" colspan=\"2\">\r\n<div class=\"note\">"
		  << tr("<b>Note:</b> Configuration changes made here persist for the duration of the router session and will not be saved to your config file.")
		  << "</div>\r\n</td></tr>";

		const LogLevel loglevel = i2p::log::Logger().GetLogLevel();
		s << "<tr class=\"sectiontitle\"><th colspan=\"2\"><span>" << tr("Logging Level") << "</span>\r\n";
		s << "<div id=\"loglevel\" class=\"chrome\">";
		s << "<a class=\"button" << (loglevel == 0 ? " selected" : "")
		  << "\" href=\"" << webroot << "?cmd=" << HTTP_COMMAND_LOGLEVEL << "&level=none&token=" << token << "\">none</a>\r\n";
		s << "<a class=\"button" << (loglevel == 1 ? " selected" : "")
		  << "\" href=\"" << webroot << "?cmd=" << HTTP_COMMAND_LOGLEVEL << "&level=error&token=" << token << "\">error</a>\r\n";
		s << "<a class=\"button" << (loglevel == 2 ? " selected" : "")
		  << "\" href=\"" << webroot << "?cmd=" << HTTP_COMMAND_LOGLEVEL << "&level=warn&token=" << token << "\">warn</a>\r\n";
		s << "<a class=\"button" << (loglevel == 3 ? " selected" : "")
		  << "\" href=\"" << webroot << "?cmd=" << HTTP_COMMAND_LOGLEVEL << "&level=info&token=" << token << "\">info</a>\r\n";
		s << "<a class=\"button" << (loglevel == 4 ? " selected" : "")
		  << "\" href=\"" << webroot << "?cmd=" << HTTP_COMMAND_LOGLEVEL << "&level=debug&token=" << token << "\">debug</a>"
		  << "</div>\r\n</th></tr>\r\n";

		if (i2p::context.AcceptsTunnels ()) {
			uint16_t maxTunnels = GetMaxNumTransitTunnels ();
			s << "<tr class=\"sectiontitle\"><th colspan=\"2\"><span>" << tr("Maximum Transit Tunnels") << "</span>\r\n";
			s << "<div id=\"maxtransit\" class=\"chrome\">\r\n";
			s << "<form method=\"get\" action=\"" << webroot << "\">\r\n";
			s << "  <input type=\"hidden\" name=\"cmd\" value=\"" << HTTP_COMMAND_LIMITTRANSIT << "\">\r\n";
			s << "  <input type=\"hidden\" name=\"token\" value=\"" << token << "\">\r\n";
			s << "  <input type=\"number\" min=\"0\" max=\"65535\" name=\"limit\" value=\"" << maxTunnels << "\">\r\n";
			s << "  <button class=\"apply\" type=\"submit\">" << tr("Change") << "</button>\r\n";
			s << "</form>\r\n</div>\r\n</th></tr>\r\n";
		}

		std::string currLang = i2p::client::context.GetLanguage ()->GetLanguage(); // get current used language
		s << "<tr class=\"sectiontitle\"><th colspan=\"2\"><span>" << tr("Console Display Language") << "</span>\r\n";
		s << "<div id=\"consolelang\" class=\"chrome\">\r\n";
		s << "<form method=\"get\" action=\"" << webroot << "\">\r\n";
		s << "  <input type=\"hidden\" name=\"cmd\" value=\"" << HTTP_COMMAND_SETLANGUAGE << "\">\r\n";
		s << "  <input type=\"hidden\" name=\"token\" value=\"" << token << "\">\r\n";
		s << "  <select name=\"lang\" id=\"lang\">\r\n";
		for (const auto& it: i2p::i18n::languages)
			s << "    <option value=\"" << it.first << "\"" << ((it.first.compare(currLang) == 0) ? " selected" : "") << ">" << it.second.LocaleName << "</option>\r\n";
		s << "  </select>\r\n";
		s << "  <button class=\"apply\" type=\"submit\">" << tr("Change") << "</button>\r\n";
		s << "</form>\r\n</div>\r\n</th></tr>\r\n";

	}

	void ShowTransitTunnels (std::stringstream& s)
	{
		if(i2p::tunnel::tunnels.CountTransitTunnels())
		{
			int count = i2p::tunnel::tunnels.GetTransitTunnels().size();
			s << "<tr class=\"sectiontitle configuration\"><th colspan=\"2\"><span>" << tr("Transit Tunnels");
			s << " <span class=\"hide\">[</span><span class=\"badge\">" << count << "</span><span class=\"hide\">]</span>"
			  << "</span></th></tr>";
			s << "<tr><td class=\"center nopadding\" colspan=\"2\">\r\n";
			s << "<div ";
			if (count > 7)
				s << "id=\"transit\" ";
			s << "class=\"list\">\r\n";
			for (const auto& it: i2p::tunnel::tunnels.GetTransitTunnels ())
			{
				const auto& expiry = i2p::tunnel::tunnels.GetTransitTunnelsExpirationTimeout ();
				s << "<div class=\"listitem\"><span class=\"chain transit\">";

				double bytes = it->GetNumTransmittedBytes ();
				s << std::fixed << std::setprecision(0);
				if (bytes > 1024 * 1024 * 1024) {
					s << std::fixed << std::setprecision(2);
					s << "<span class=\"sent\">" << (double) (bytes / 1024 / 1024 / 1024) << "G</span> ";
				} else if (bytes > 1024 * 1024) {
					s << std::fixed << std::setprecision(1);
					s << "<span class=\"sent\">" << (double) (bytes / 1024 / 1024) << "M</span> ";
				} else if (bytes > 1024) {
					s << "<span class=\"sent\">" << (int) (bytes / 1024) << "K</span> ";
				} else {
					s << "<span class=\"sent\">" << (int) (bytes) << "B</span> ";
				}
				// TODO: tunnel expiry per tunnel, not most recent
				//s << "<span class=\"expiry\">" << expiry << tr("s" /* translation: seconds */) << "</span> ";
				s << "<span class=\"tunnelid\">" << it->GetTunnelID () << "</span> ";
				if (std::dynamic_pointer_cast<i2p::tunnel::TransitTunnelGateway>(it))
					s << "<span class=\"role ibgw\" data-tooltip=\"" << tr("inbound gateway") << "\">"
					  << tr("inbound gateway") << "</span>";
				else if (std::dynamic_pointer_cast<i2p::tunnel::TransitTunnelEndpoint>(it))
					s << "<span class=\"role obep\"data-tooltip=\"" << tr("outbound endpoint") << "\">"
					  << tr("outbound endpoint") << "</span>";
				else
					s << "<span class=\"role ptcp\" data-tooltip=\"" << tr("participant") << "\">"
					  << tr("participant") << "</span>";
				s << "</div>\r\n";
			}
			s << "</span></div></td></tr>\r\n";
		}
		else
		{
			s << "<tr><th colspan=\"2\">" << tr("No active transit tunnels") << "</th></tr>\r\n";
		}
	}

	template<typename Sessions>
	static void ShowNTCPTransports (std::stringstream& s, const Sessions& sessions, const std::string name)
	{
		std::stringstream tmp_s, tmp_s6; uint16_t cnt = 0, cnt6 = 0;
		for (const auto& it: sessions )
		{
			if (it.second && it.second->IsEstablished () && !it.second->GetRemoteEndpoint ().address ().is_v6 ())
			{
				tmp_s << "<div class=\"listitem\">";
				if (it.second->IsOutgoing ())
					tmp_s << "<span class=\"arrowup\">&#8657;</span>";
				else
					tmp_s << "<span class=\"arrowdown\">&#8659;</span>";
				tmp_s << " <span class=\"chain\">";
				tmp_s << "<span class=\"hop\">" << i2p::data::GetIdentHashAbbreviation (it.second->GetRemoteIdentity ()->GetIdentHash ()) << "</span>"
					  << " <a target=\"_blank\" href=\"https://gwhois.org/"
					  << it.second->GetRemoteEndpoint ().address ().to_string () << "\" data-tooltip=\""
					  << tr("Lookup address on gwhois.org") << "\"><span class=\"host\">"
					  << it.second->GetRemoteEndpoint ().address ().to_string () << "</span></a>";
				tmp_s << std::fixed << std::setprecision(0);
				if (it.second->GetNumSentBytes () > 1024 * 1024) {
					tmp_s << std::fixed << std::setprecision(1);
					tmp_s << " <span class=\"sent\">" << (double) it.second->GetNumSentBytes () / 1024 / 1024 << "M</span>";
				} else {
					tmp_s << " <span class=\"sent\">" << (double) it.second->GetNumSentBytes () / 1024 << "K</span>";
				}
				tmp_s << std::fixed << std::setprecision(0);
				if (it.second->GetNumReceivedBytes () > 1024 * 1024) {
					tmp_s << std::fixed << std::setprecision(1);
					tmp_s << " <span class=\"recvd\">" << (double) it.second->GetNumReceivedBytes () / 1024 / 1024 << "M</span>";
				} else {
					tmp_s << " <span class=\"recvd\">" << (double) it.second->GetNumReceivedBytes () / 1024 << "K</span>";
				}
				tmp_s << "</span></div>\r\n" << std::endl;
				cnt++;
			}
			if (it.second && it.second->IsEstablished () && it.second->GetRemoteEndpoint ().address ().is_v6 ())
			{
				tmp_s6 << "<div class=\"listitem\">";
				if (it.second->IsOutgoing ())
					tmp_s6 << "<span class=\"arrowup\">&#8657;</span>";
				else
					tmp_s6 << "<span class=\"arrowdown\">&#8659;</span>";
				tmp_s6 << " <span class=\"chain\">";
				tmp_s6 << "<span class=\"hop\">" << i2p::data::GetIdentHashAbbreviation (it.second->GetRemoteIdentity ()->GetIdentHash ()) << "</span>"
					   << " <a target=\"_blank\" href=\"https://gwhois.org/"
					   << it.second->GetRemoteEndpoint ().address ().to_string () << "\" data-tooltip=\""
					   << tr("Lookup address on gwhois.org") << "\"><span class=\"host\">"
					   << it.second->GetRemoteEndpoint ().address ().to_string () << "</span></a>";
				tmp_s6 << std::fixed << std::setprecision(0);
				if (it.second->GetNumSentBytes () > 1024 * 1024) {
					tmp_s6 << std::fixed << std::setprecision(1);
					tmp_s6 << " <span class=\"sent\">" << (double) it.second->GetNumSentBytes () / 1024 / 1024 << "M</span>";
				} else {
					tmp_s6 << " <span class=\"sent\">" << (double) it.second->GetNumSentBytes () / 1024 << "K</span>";
				}
				tmp_s6 << " <span class=\"hide\">/</span>";
				tmp_s6 << std::fixed << std::setprecision(0);
				if (it.second->GetNumReceivedBytes () > 1024 * 1024) {
					tmp_s6 << std::fixed << std::setprecision(1);
					tmp_s6 << " <span class=\"recvd\">" << (double) it.second->GetNumReceivedBytes () / 1024 / 1024 << "M</span>";
				} else {
					tmp_s6 << " <span class=\"recvd\">" << (double) it.second->GetNumReceivedBytes () / 1024 << "K</span>";
				}
				tmp_s6 << "</span></div>\r\n" << std::endl;
				cnt6++;
			}
		}
		if (!tmp_s.str ().empty ())
		{
			s << "<div class=\"slide\"><input hidden type=\"checkbox\" class=\"toggle\" id=\"slide_" << boost::algorithm::to_lower_copy(name)
			  << "\" />\r\n<label for=\"slide_" << boost::algorithm::to_lower_copy(name) << "\">" << name
			  << " <span class=\"hide\">[</span><span class=\"badge\">" << cnt
			  << "</span><span class=\"hide\">]</span></label>\r\n<div class=\"slidecontent list\">"
			  << tmp_s.str () << "</div>\r\n</div>\r\n";
		}
		if (!tmp_s6.str ().empty ())
		{
			s << "<div class=\"slide\"><input hidden type=\"checkbox\" class=\"toggle\" id=\"slide_" << boost::algorithm::to_lower_copy(name) << "v6\" />\r\n"
			  << "<label for=\"slide_" << boost::algorithm::to_lower_copy(name) << "v6\">" << name
			  << "v6 <span class=\"hide\">[</span><span class=\"badge\">" << cnt6
			  << "</span><span class=\"hide\">]</span></label>\r\n<div class=\"slidecontent list\">"
			  << tmp_s6.str () << "</div>\r\n</div>\r\n";
		}
	}

	void ShowTransports (std::stringstream& s)
	{
		s << "<tr class=\"sectiontitle\"><th colspan=\"2\"><span>" << tr("Transports") << "</span></th></tr>\r\n"
		  << "<tr><td id=\"transports\" class=\"center nopadding\" colspan=\"2\">";
		auto ntcp2Server = i2p::transport::transports.GetNTCP2Server ();
		if (ntcp2Server)
		{
			auto sessions = ntcp2Server->GetNTCP2Sessions ();
			if (!sessions.empty ())
				ShowNTCPTransports (s, sessions, "NTCP2");
		}
		auto ssuServer = i2p::transport::transports.GetSSUServer ();
		if (ssuServer)
		{
			auto sessions = ssuServer->GetSessions ();
			if (!sessions.empty ())
			{
				s << "<div class=\"slide\"><input hidden type=\"checkbox\" class=\"toggle\" id=\"slide_ssu\" />\r\n"
				  << "<label for=\"slide_ssu\">SSU <span class=\"hide\">[</span><span class=\"badge\">"
				  << (int) sessions.size() << "</span><span class=\"hide\">]</span></label>\r\n"
				  << "<div class=\"slidecontent list\">\r\n";
				for (const auto& it: sessions)
				{
					s << "<div class=\"listitem SSU\">";
					if (it.second->IsOutgoing ())
						s << "<span class=\"arrowup\">&#8657;</span>";
					else
						s << "<span class=\"arrowdown\">&#8659;</span>";
					s << " <span class=\"chain\">";
					auto endpoint = it.second->GetRemoteEndpoint ();
//					s << " <span class=\"host\">" << endpoint.address ().to_string () << ":" << endpoint.port () << "</span>";
					s << " <a target=\"_blank\" href=\"https://gwhois.org/"
					  << endpoint.address ().to_string () << "\" data-tooltip=\""
					  << tr("Lookup address on gwhois.org") << "\"><span class=\"host\">"
					  << endpoint.address ().to_string () << ":" << endpoint.port () << "</span></a>";
					s << std::fixed << std::setprecision(0);
					if (it.second->GetNumSentBytes () > 1024 * 1024) {
						s << std::fixed << std::setprecision(1);
						s << " <span class=\"sent\">" << (double) it.second->GetNumSentBytes () / 1024 / 1024 << "M</span>";
					} else {
						s << " <span class=\"sent\">" << (double) it.second->GetNumSentBytes () / 1024 << "K</span>";
					}
					s << " <span class=\"hide\">/</span>";
					s << std::fixed << std::setprecision(0);
					if (it.second->GetNumReceivedBytes () > 1024 * 1024) {
						s << std::fixed << std::setprecision(1);
						s << " <span class=\"recvd\">" << (double) it.second->GetNumReceivedBytes () / 1024 / 1024 << "M</span>";
					} else {
						s << " <span class=\"recvd\">" << (double) it.second->GetNumReceivedBytes () / 1024 << "K</span>";
					}
					if (it.second->GetRelayTag ())
						s << " <span class=\"itag\" data-tooltip=\"itag\">" << it.second->GetRelayTag () << "</span>";
					s << "</span></div>\r\n" << std::endl;
				}
				s << "</div>\r\n</div>\r\n";
			}
			auto sessions6 = ssuServer->GetSessionsV6 ();
			if (!sessions6.empty ())
			{
				s << "<div class=\"slide\">\r\n<input hidden type=\"checkbox\" class=\"toggle\" id=\"slide_ssuv6\" />\r\n"
				  << "<label for=\"slide_ssuv6\">SSUv6 <span class=\"hide\">[</span><span class=\"badge\">"
				  << (int) sessions6.size() << "</span><span class=\"hide\">]</span></label>\r\n"
				  << "<div class=\"slidecontent list\">\r\n";
				for (const auto& it: sessions6)
				{
					s << "<div class=\"listitem SSU\">";
					if (it.second->IsOutgoing ())
						s << "<span class=\"arrowup\">&#8657;</span>";
					else
						s << "<span class=\"arrowdown\">&#8659;</span>";
					s << " <span class=\"chain\">";
					auto endpoint = it.second->GetRemoteEndpoint ();
					s << " <span class=\"host\">" << endpoint.address ().to_string () << ":" << endpoint.port () << "</span>";
					s << std::fixed << std::setprecision(0);

					if (it.second->GetNumSentBytes () > 1024 * 1024) {
						s << std::fixed << std::setprecision(1);
						s << " <span class=\"sent\">" << (double) it.second->GetNumSentBytes () / 1024 / 1024 << "M</span>";
					} else {
						s << " <span class=\"sent\">" << (double) it.second->GetNumSentBytes () / 1024 << "K</span>";
					}
					s << " <span class=\"hide\">/</span>";
					s << std::fixed << std::setprecision(0);
					if (it.second->GetNumReceivedBytes () > 1024 * 1024) {
						s << std::fixed << std::setprecision(1);
						s << " <span class=\"recvd\">" << (double) it.second->GetNumReceivedBytes () / 1024 / 1024 << "M</span>";
					} else {
						s << " <span class=\"recvd\">" << (double) it.second->GetNumReceivedBytes () / 1024 << "K</span>";
					}
					if (it.second->GetRelayTag ())
						s << " <span class=\"itag\" data-tooltip=\"itag\">" << it.second->GetRelayTag () << "</span>";
					s << "</span>\r\n</div>\r\n" << std::endl;
				}
				s << "</div>\r\n</div>\r\n</td></tr>\r\n";
			}
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
			s << "<tr class=\"sectiontitle\"><th colspan=\"2\"><span>" << tr("SAM sessions")
			  << "</span></th><tr>\r\n<tr><td class=\"center nopadding\">\r\n<div class=\"list\">\r\n";
			for (auto& it: sam->GetSessions ())
			{
				auto& name = it.second->GetLocalDestination ()->GetNickname ();
				s << "<div class=\"listitem\"><a href=\"" << webroot << "?page=" << HTTP_PAGE_SAM_SESSION << "&sam_id=" << it.first << "\">";
				s << name << " (" << it.first << ")</a></div>\r\n" << std::endl;
			}
			s << "</div>\r\n</td></tr>\r\n";
		}
		else
			s << "<tr><th colspan=\"2\">" << tr("No active SAM sessions") << "</th></tr>\r\n";
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
		s << "<tr><th colspan=\"2\">" << tr("SAM Session") << "</th><tr>\r\n<tr><td class=\"center nopadding\">\r\n<div class=\"list\">\r\n";
		auto& ident = session->GetLocalDestination ()->GetIdentHash();
		s << "<div class=\"listitem\"><a href=\"" << webroot << "?page=" << HTTP_PAGE_LOCAL_DESTINATION << "&b32=" << ident.ToBase32 () << "\">";
		s << i2p::client::context.GetAddressBook ().ToAddress(ident) << "</a></div>\r\n";
		s << "<br>\r\n";
		s << "<tr><th colspan=\"2\">" << tr("Streams") << "</th><tr>\r\n<div class=\"list\">\r\n";
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
		s << "</div></td></tr>\r\n";
	}

	void ShowI2PTunnels (std::stringstream& s)
	{
		std::string webroot; i2p::config::GetOption("http.webroot", webroot);
		s << "<tr class=\"sectiontitle\"><th colspan=\"4\"><span>" << tr("Service Tunnels") << "</span></th></tr>";
		s << "<tr><td class=\"center nopadding i2ptunnels\" colspan=\"4\">\r\n";
		s << "<div class=\"slide\">\r\n<input hidden type=\"checkbox\" class=\"toggle\" id=\"slide_client_tunnels\" />\r\n"
		  << "<label for=\"slide_client_tunnels\">" << tr("Client Tunnels") << " <span class=\"hide\">[</span><span class=\"badge\">"
		  << "in / out" << "</span><span class=\"hide\">]</span></label>\r\n";
		s << "<div id=\"client_tunnels\" class=\"slidecontent list\">\r\n";
		s << "<div class=\"list\">\r\n";
		for (auto& it: i2p::client::context.GetClientTunnels ())
		{
			auto& ident = it.second->GetLocalDestination ()->GetIdentHash();
			s << "<div class=\"listitem\"><a href=\"" << webroot << "?page=" << HTTP_PAGE_LOCAL_DESTINATION << "&b32=" << ident.ToBase32 () << "\">";
			s << it.second->GetName () << "</a> <span class=\"arrowleft\">&#8656;</span> <span class=\"b32\">";
			s << i2p::client::context.GetAddressBook ().ToAddress(ident);
			s << "</span></div>\r\n"<< std::endl;
		}
		auto httpProxy = i2p::client::context.GetHttpProxy ();
		if (httpProxy)
		{
			auto& ident = httpProxy->GetLocalDestination ()->GetIdentHash();
			s << "<div class=\"listitem\"><a href=\"" << webroot << "?page=" << HTTP_PAGE_LOCAL_DESTINATION << "&b32=" << ident.ToBase32 () << "\">";
			s << "HTTP " << tr("Proxy") << "</a> <span class=\"arrowleft\">&#8656;</span> <span class=\"b32\">";
			s << i2p::client::context.GetAddressBook ().ToAddress(ident);
			s << "</span></div>\r\n"<< std::endl;
		}
		auto socksProxy = i2p::client::context.GetSocksProxy ();
		if (socksProxy)
		{
			auto& ident = socksProxy->GetLocalDestination ()->GetIdentHash();
			s << "<div class=\"listitem\"><a href=\"" << webroot << "?page=" << HTTP_PAGE_LOCAL_DESTINATION << "&b32=" << ident.ToBase32 () << "\">";
			s << "SOCKS " << tr("Proxy") << "</a> <span class=\"arrowleft\">&#8656;</span> <span class=\"b32\">";
			s << i2p::client::context.GetAddressBook ().ToAddress(ident);
			s << "</span></div>\r\n" << std::endl;
		}
		s << "</div>\r\n</div>\r\n</div>\r\n";

		auto& serverTunnels = i2p::client::context.GetServerTunnels ();
		if (!serverTunnels.empty ()) {
			s << "\r\n</td></tr>\r\n<tr><td class=\"center nopadding i2ptunnels\" colspan=\"4\">\r\n";
			s << "<div class=\"slide\">\r\n<input hidden type=\"checkbox\" class=\"toggle\" id=\"slide_server_tunnels\" />\r\n"
			  << "<label for=\"slide_server_tunnels\">" << tr("Server Tunnels") << " <span class=\"hide\">[</span><span class=\"badge\">"
			  << "in / out" << "</span><span class=\"hide\">]</span></label>\r\n";
			s << "<div id=\"server_tunnels\" class=\"slidecontent list\">\r\n";
			s << "<div class=\"list\">\r\n";
			for (auto& it: serverTunnels)
			{
				auto& ident = it.second->GetLocalDestination ()->GetIdentHash();
				s << "<div class=\"listitem\"><a href=\"" << webroot << "?page=" << HTTP_PAGE_LOCAL_DESTINATION << "&b32=" << ident.ToBase32 () << "\">";
				s << it.second->GetName () << "</a> <span class=\"arrowright\">&#8658;</span> <span class=\"b32\">";
				s << i2p::client::context.GetAddressBook ().ToAddress(ident);
				s << ":" << it.second->GetLocalPort ();
				s << "</span></div>\r\n" << std::endl;
			}
			s << "</div>\r\n</div>\r\n</div>\r\n</td></tr>\r\n";
		}

		auto& clientForwards = i2p::client::context.GetClientForwards ();
		if (!clientForwards.empty ())
		{
		s << "\r\n</td></tr>\r\n<tr><td class=\"center nopadding i2ptunnels\" colspan=\"4\">\r\n";
		s << "<div class=\"slide\">\r\n<input hidden type=\"checkbox\" class=\"toggle\" id=\"slide_client_forwards\" />\r\n"
		  << "<label for=\"slide_client_forwards\">" << tr("Client Forwards") << " <span class=\"hide\">[</span><span class=\"badge\">"
		  << "in / out" << "</span><span class=\"hide\">]</span></label>\r\n";
		s << "<div id=\"client_forwards\" class=\"slidecontent list\">\r\n";
		s << "<div class=\"list\">\r\n";
			for (auto& it: clientForwards)
			{
				auto& ident = it.second->GetLocalDestination ()->GetIdentHash();
				s << "<div class=\"listitem\"><a href=\"" << webroot << "?page=" << HTTP_PAGE_LOCAL_DESTINATION << "&b32=" << ident.ToBase32 () << "\">";
				s << it.second->GetName () << "</a> <span class=\"arrowleft\">&#8656;</span> <span class=\"b32\">";
				s << i2p::client::context.GetAddressBook ().ToAddress(ident);
				s << "</span></div>\r\n"<< std::endl;
			}
			s << "</div>\r\n</div>\r\n</div>\r\n</td></tr>\r\n";
		}
		auto& serverForwards = i2p::client::context.GetServerForwards ();
		if (!serverForwards.empty ())
		{
		s << "\r\n</td></tr>\r\n<tr><td class=\"center nopadding i2ptunnels\" colspan=\"4\">\r\n";
		s << "<div class=\"slide\">\r\n<input hidden type=\"checkbox\" class=\"toggle\" id=\"slide_server_forwards\" />\r\n"
		  << "<label for=\"slide_server_forwards\">" << tr("Server Forwards") << " <span class=\"hide\">[</span><span class=\"badge\">"
		  << "in / out" << "</span><span class=\"hide\">]</span></label>\r\n";
		s << "<div id=\"server_forwards\" class=\"slidecontent list\">\r\n";
		s << "<div class=\"list\">\r\n";
			for (auto& it: serverForwards)
			{
				auto& ident = it.second->GetLocalDestination ()->GetIdentHash();
				s << "<div class=\"listitem\"><a href=\"" << webroot << "?page=" << HTTP_PAGE_LOCAL_DESTINATION << "&b32=" << ident.ToBase32 () << "\">";
				s << it.second->GetName () << "</a> <span class=\"arrowleft\">&#8656;</span> <span class=\"b32\">";
				s << i2p::client::context.GetAddressBook ().ToAddress(ident);
				s << "</span></div>\r\n"<< std::endl;
			}
			s << "</div>\r\n</div>\r\n</div>\r\n</td></tr>\r\n";
		}
//		s << "</div></table>\r\n";
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
		if (req.uri.find("summary") != std::string::npos ||
			req.uri.find("commands") != std::string::npos ||
			(req.uri.find("local_destinations") != std::string::npos &&
			 req.uri.find("b32") == std::string::npos))
			res.add_header("Refresh", "10");
		if (req.uri.find("page=") != std::string::npos) {
			HandlePage (req, res, s);
		} else if (req.uri.find("cmd=") != std::string::npos) {
			HandleCommand (req, res, s);
		} else {
			ShowStatus (s, true, i2p::http::OutputFormatEnum::forWebConsole);
			res.add_header("Refresh", "5");
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

		if (page == HTTP_PAGE_TRANSPORTS) {
			ShowTransports (s);
		} else if (page == HTTP_PAGE_TUNNEL_SUMMARY) {
			ShowTunnelSummary (s);
/*
			ShowTunnels (s);
			ShowI2PTunnels (s);
			ShowTransitTunnels (s);
*/
		} else if (page == HTTP_PAGE_COMMANDS) {
			uint32_t token = CreateToken ();
			ShowCommands (s, token);
		} else if (page == HTTP_PAGE_TRANSIT_TUNNELS) {
			ShowTransitTunnels (s);
		} else if (page == HTTP_PAGE_LOCAL_DESTINATIONS) {
			ShowLocalDestinations (s);
		} else if (page == HTTP_PAGE_LOCAL_DESTINATION) {
			uint32_t token = CreateToken ();
			ShowLocalDestination (s, params["b32"], token);
		} else if (page == HTTP_PAGE_I2CP_LOCAL_DESTINATION) {
			ShowI2CPLocalDestination (s, params["i2cp_id"]);
		} else if (page == HTTP_PAGE_SAM_SESSIONS) {
			ShowSAMSessions (s);
		} else if (page == HTTP_PAGE_SAM_SESSION) {
			ShowSAMSession (s, params["sam_id"]);
		} else if (page == HTTP_PAGE_LOCAL_TUNNELS) {
			ShowTunnels (s);
		} else if (page == HTTP_PAGE_LEASESETS) {
			ShowLeasesSets(s);
		} else {
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
		std::string redirect = "2; url=" + webroot + "?page=commands";
		std::string token = params["token"];

		if (token.empty () || m_Tokens.find (std::stoi (token)) == m_Tokens.end ())
		{
			ShowError(s, tr("Invalid token"));
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
#if ((!defined(WIN32) && !defined(QT_GUI_LIB) && !defined(ANDROID))  || defined(ANDROID_BINARY))
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
					if(dest->DeleteStream (streamID))
						s << "<tr class=\"toast\"><td class=\"notify center\" colspan=\2\">"
						  << "<span class=\"container\"><span id=\"success\"></span><b>" << tr("SUCCESS") << "</b>:&nbsp;"
						  << tr("Stream closed") << "</span></td></tr>\r\n";
					else
						s << "<tr class=\"toast\"><td class=\"notify error center\" colspan=\2\">"
						  << "<span class=\"container\"><span id=\"warning\"></span>"
						  << tr("ERROR") << "</b>:&nbsp;"
						  << tr("Stream not found or already was closed") << "</span></td></tr>\r\n";
				}
				else
					s << "<tr class=\"toast\"><td class=\"notify error center\" colspan=\2\">"
					  << "<span class=\"container\"><span id=\"warning\"></span>"
					  << tr("ERROR") << "</b>:&nbsp;"
					  << tr("Destination not found") << "</span></td></tr>\r\n";
			}
			else
				s << "<tr class=\"toast\"><td class=\"notify error center\" colspan=\2\">"
				  << "<span class=\"container\"><span id=\"warning\"></span>" << tr("ERROR") << "</b>:&nbsp;"
				  << tr("StreamID can't be null") << "</span></td></tr>\r\n";

			redirect = "2; url=" + webroot + "?page=local_destination&b32=" + b32;
			res.add_header("Refresh", redirect.c_str());
			return;
		}
		else if (cmd == HTTP_COMMAND_LIMITTRANSIT)
		{
			uint32_t limit = std::stoul(params["limit"], nullptr);
			if (limit > 0 && limit <= 65535)
				SetMaxNumTransitTunnels (limit);
			else {
				s << "<tr class=\"toast\"><td class=\"notify error center\" colspan=\2\">"
				  << "<span class=\"container\"><span id=\"warning\"></span>"
				  << tr("ERROR") << "</b>:&nbsp;"
				  << tr("Transit tunnels count must not exceed 65535") << "</span></td></tr>\r\n";
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
						s << "<tr class=\"toast\"><td class=\"notify center\" colspan=\"2\"><span class=\"container\">"
						  << "<span id=\"success\"></span><b>" << tr("SUCCESS")
						  << "</b>:<br>\r\n<form action=\"http://shx5vqsw7usdaunyzr2qmes2fq37oumybpudrd4jjj4e4vk4uusa.b32.i2p/add\""
						  << " method=\"post\" rel=\"noreferrer\" target=\"_blank\">\r\n"
						  << "<textarea readonly name=\"record\" cols=\"80\" rows=\"10\">" << out.str () << "</textarea>\r\n<br>\r\n<br>\r\n"
						  << "<b>" << tr("Register at reg.i2p") << ":</b>\r\n<br>\r\n"
						  << "<b>" << tr("Description") << ":</b>\r\n<input type=\"text\" maxlength=\"64\" name=\"desc\" placeholder=\""
						  << tr("Short description of domain") << "\">\r\n"
						  << "<input type=\"submit\" value=\"" << tr("Submit") << "\">\r\n"
						  << "</form></span></td></tr>\r\n";
						delete[] signature;
						delete[] sig;
					}
					else
						s << "<tr class=\"toast\"><td class=\"notify error center\" colspan=\"2\"><span class=\"container\"><b>"
						  << tr("ERROR") << "</b>:&nbsp;"
						  << tr("Domain can't end with .b32.i2p") << "</span></td></tr>\r\n";
				}
				else
					s << "<tr class=\"toast\"><td class=\"notify error center\" colspan=\"2\"><span class=\"container\">"
					  << tr("ERROR") << "</b>:&nbsp;"
					  << tr("Domain must end with .i2p") << "</span></td></tr>\r\n";
			}
			else
				s << "<tr class=\"toast\"><td class=\"notify error center\" colspan=\"2\"><span class=\"container\">"
				  << tr("ERROR") << "</b>:&nbsp;"
				  << tr("No such destination found") << "</span></td></tr>\r\n";

//			s << "<a href=\"" << webroot << "?page=local_destination&b32=" << b32 << "\">" << tr("Return to destination page") << "</a>\r\n";
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
			std::string styleFile = i2p::fs::DataDirPath ("webconsole/style.css");
			if (i2p::fs::Exists(styleFile))
				LoadExtCSS();
			else
				ShowError(s, tr("No CSS file found on disk!"));
		}
		else
		{
			res.code = 400;
			ShowError(s, tr("Unknown command") + ": " + cmd);
			return;
		}


		s << "<tr class=\"toast\"><td class=\"notify center\" colspan=\"2\"><span class=\"container\">"
		  << "<span id=\"success\"></span>";
		if (cmd == HTTP_COMMAND_SHUTDOWN_NOW)
			s << tr("Immediate router shutdown initiated");
		else if (cmd == HTTP_COMMAND_SHUTDOWN_CANCEL)
			s << tr("Router shutdown cancelled");
		else if (cmd == HTTP_COMMAND_RELOAD_CSS) {
			s << tr("Console CSS stylesheet reloaded");
		} else if (cmd == HTTP_COMMAND_LIMITTRANSIT)
			s << tr("Maximum transit tunnels configured for session");
		else if (cmd == HTTP_COMMAND_ENABLE_TRANSIT)
			s << tr("Transit tunnels enabled for session");
		else if (cmd == HTTP_COMMAND_DISABLE_TRANSIT)
			s << tr("Transit tunnels disabled for session");
		else if (cmd == HTTP_COMMAND_SETLANGUAGE)
			s << tr("Console language updated");
		else if (cmd == HTTP_COMMAND_LOGLEVEL)
			s << tr("Log level updated for session");
		else
			s << "<b>" << tr("SUCCESS") << "</b>:&nbsp;" << tr("Command accepted");
		s << "</span></td></tr>\r\n";
		res.add_header("Refresh", redirect.c_str());
	}

	void HTTPConnection::SendReply (HTTPRes& reply, std::string& content)
	{
		reply.add_header("X-Frame-Options", "SAMEORIGIN");
		reply.add_header("X-Content-Type-Options", "nosniff");
		reply.add_header("X-XSS-Protection", "1; mode=block");
		reply.add_header("Content-Type", "text/html");
		reply.add_header("Server", "i2pd " VERSION " webconsole" );
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
				LogPrint (eLogError, "HTTPServer: runtime exception: ", ex.what ());
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
		if (ecode)
		{
			if(newSocket) newSocket->close();
			LogPrint(eLogError, "HTTP Server: Error handling accept ", ecode.message());
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
} // i2p
