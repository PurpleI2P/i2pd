/*
* Copyright (c) 2013-2022, The PurpleI2P Project
*
* This file is part of Purple i2pd project and licensed under BSD3
*
* See full license text in LICENSE file at top of project tree
*/

#include <iomanip>
#define BOOST_BIND_GLOBAL_PLACEHOLDERS
#include <boost/lexical_cast.hpp>
#include <boost/property_tree/json_parser.hpp>

#include "Log.h"
#include "RouterContext.h"
#include "NetDb.hpp"
#include "Tunnel.h"
#include "Transports.h"
#include "version.h"
#include "ClientContext.h"
#include "I2PControlHandlers.h"

namespace i2p
{
namespace client
{
	I2PControlHandlers::I2PControlHandlers ()
	{
		// RouterInfo
		m_RouterInfoHandlers["i2p.router.uptime"]                    = &I2PControlHandlers::UptimeHandler;
		m_RouterInfoHandlers["i2p.router.version"]                   = &I2PControlHandlers::VersionHandler;
		m_RouterInfoHandlers["i2p.router.status"]                    = &I2PControlHandlers::StatusHandler;
		m_RouterInfoHandlers["i2p.router.netdb.knownpeers"]          = &I2PControlHandlers::NetDbKnownPeersHandler;
		m_RouterInfoHandlers["i2p.router.netdb.activepeers"]         = &I2PControlHandlers::NetDbActivePeersHandler;
		m_RouterInfoHandlers["i2p.router.net.bw.inbound.1s"]         = &I2PControlHandlers::InboundBandwidth1S;
		m_RouterInfoHandlers["i2p.router.net.bw.inbound.15s"]        = &I2PControlHandlers::InboundBandwidth15S;
		m_RouterInfoHandlers["i2p.router.net.bw.outbound.1s"]        = &I2PControlHandlers::OutboundBandwidth1S;
		m_RouterInfoHandlers["i2p.router.net.bw.outbound.15s"]       = &I2PControlHandlers::OutboundBandwidth15S;
		m_RouterInfoHandlers["i2p.router.net.status"]                = &I2PControlHandlers::NetStatusHandler;
		m_RouterInfoHandlers["i2p.router.net.tunnels.participating"] = &I2PControlHandlers::TunnelsParticipatingHandler;
		m_RouterInfoHandlers["i2p.router.net.tunnels.successrate"]   = &I2PControlHandlers::TunnelsSuccessRateHandler;
		m_RouterInfoHandlers["i2p.router.net.total.received.bytes"]  = &I2PControlHandlers::NetTotalReceivedBytes;
		m_RouterInfoHandlers["i2p.router.net.total.sent.bytes"]      = &I2PControlHandlers::NetTotalSentBytes;

		// NetworkSetting
		m_NetworkSettingHandlers["i2p.router.net.bw.in"]  = &I2PControlHandlers::InboundBandwidthLimit;
		m_NetworkSettingHandlers["i2p.router.net.bw.out"] = &I2PControlHandlers::OutboundBandwidthLimit;

		// ClientServicesInfo
		m_ClientServicesInfoHandlers["I2PTunnel"] = &I2PControlHandlers::I2PTunnelInfoHandler;
		m_ClientServicesInfoHandlers["HTTPProxy"] = &I2PControlHandlers::HTTPProxyInfoHandler;
		m_ClientServicesInfoHandlers["SOCKS"]     = &I2PControlHandlers::SOCKSInfoHandler;
		m_ClientServicesInfoHandlers["SAM"]       = &I2PControlHandlers::SAMInfoHandler;
		m_ClientServicesInfoHandlers["BOB"]       = &I2PControlHandlers::BOBInfoHandler;
		m_ClientServicesInfoHandlers["I2CP"]      = &I2PControlHandlers::I2CPInfoHandler;
	}

	void I2PControlHandlers::InsertParam (std::ostringstream& ss, const std::string& name, int value) const
	{
		ss << "\"" << name << "\":" << value;
	}

	void I2PControlHandlers::InsertParam (std::ostringstream& ss, const std::string& name, const std::string& value, bool quotes) const
	{
		ss << "\"" << name << "\":";
		if (value.length () > 0)
		{
			if (quotes)
				ss << "\"" << value << "\"";
			else
				ss << value;
		}
		else
			ss << "null";
	}

	void I2PControlHandlers::InsertParam (std::ostringstream& ss, const std::string& name, double value) const
	{
		ss << "\"" << name << "\":" << std::fixed << std::setprecision(2) << value;
	}

	void I2PControlHandlers::InsertParam (std::ostringstream& ss, const std::string& name, const boost::property_tree::ptree& value) const
	{
		std::ostringstream buf;
		boost::property_tree::write_json (buf, value, false);
		ss << "\"" << name << "\":" << buf.str();
	}

// RouterInfo

	void I2PControlHandlers::RouterInfoHandler (const boost::property_tree::ptree& params, std::ostringstream& results)
	{
		bool first = true;
		for (auto it = params.begin (); it != params.end (); it++)
		{
			LogPrint (eLogDebug, "I2PControl: RouterInfo request: ", it->first);
			auto it1 = m_RouterInfoHandlers.find (it->first);
			if (it1 != m_RouterInfoHandlers.end ())
			{
				if (!first) results << ",";
				else first = false;
				(this->*(it1->second))(results);
			}
			else
				LogPrint (eLogError, "I2PControl: RouterInfo unknown request ", it->first);
		}
	}

	void I2PControlHandlers::UptimeHandler (std::ostringstream& results)
	{
		InsertParam (results, "i2p.router.uptime", std::to_string (i2p::context.GetUptime ()*1000LL), false);
	}

	void I2PControlHandlers::VersionHandler (std::ostringstream& results)
	{
		InsertParam (results, "i2p.router.version", VERSION);
	}

	void I2PControlHandlers::StatusHandler (std::ostringstream& results)
	{
		auto dest = i2p::client::context.GetSharedLocalDestination ();
		InsertParam (results, "i2p.router.status", (dest && dest->IsReady ()) ? "1" : "0");
	}

	void I2PControlHandlers::NetDbKnownPeersHandler (std::ostringstream& results)
	{
		InsertParam (results, "i2p.router.netdb.knownpeers", i2p::data::netdb.GetNumRouters ());
	}

	void I2PControlHandlers::NetDbActivePeersHandler (std::ostringstream& results)
	{
		InsertParam (results, "i2p.router.netdb.activepeers", (int)i2p::transport::transports.GetPeers ().size ());
	}

	void I2PControlHandlers::NetStatusHandler (std::ostringstream& results)
	{
		InsertParam (results, "i2p.router.net.status", (int)i2p::context.GetStatus ());
	}

	void I2PControlHandlers::TunnelsParticipatingHandler (std::ostringstream& results)
	{
		int transit = i2p::tunnel::tunnels.GetTransitTunnels ().size ();
		InsertParam (results, "i2p.router.net.tunnels.participating", transit);
	}

	void I2PControlHandlers::TunnelsSuccessRateHandler (std::ostringstream& results)
	{
		int rate = i2p::tunnel::tunnels.GetTunnelCreationSuccessRate ();
		InsertParam (results, "i2p.router.net.tunnels.successrate", rate);
	}

	void I2PControlHandlers::InboundBandwidth1S (std::ostringstream& results)
	{
		double bw = i2p::transport::transports.GetInBandwidth ();
		InsertParam (results, "i2p.router.net.bw.inbound.1s", bw);
	}

	void I2PControlHandlers::InboundBandwidth15S (std::ostringstream& results)
	{
		double bw = i2p::transport::transports.GetInBandwidth15s ();
		InsertParam (results, "i2p.router.net.bw.inbound.15s", bw);
	}

	void I2PControlHandlers::OutboundBandwidth1S (std::ostringstream& results)
	{
		double bw = i2p::transport::transports.GetOutBandwidth ();
		InsertParam (results, "i2p.router.net.bw.outbound.1s", bw);
	}

	void I2PControlHandlers::OutboundBandwidth15S (std::ostringstream& results)
	{
		double bw = i2p::transport::transports.GetOutBandwidth15s ();
		InsertParam (results, "i2p.router.net.bw.outbound.15s", bw);
	}

	void I2PControlHandlers::NetTotalReceivedBytes (std::ostringstream& results)
	{
		InsertParam (results, "i2p.router.net.total.received.bytes", (double)i2p::transport::transports.GetTotalReceivedBytes ());
	}

	void I2PControlHandlers::NetTotalSentBytes (std::ostringstream& results)
	{
		InsertParam (results, "i2p.router.net.total.sent.bytes", (double)i2p::transport::transports.GetTotalSentBytes ());
	}

// network setting
	void I2PControlHandlers::NetworkSettingHandler (const boost::property_tree::ptree& params, std::ostringstream& results)
	{
		for (auto it = params.begin (); it != params.end (); it++)
		{
			LogPrint (eLogDebug, "I2PControl: NetworkSetting request: ", it->first);
			auto it1 = m_NetworkSettingHandlers.find (it->first);
			if (it1 != m_NetworkSettingHandlers.end ()) {
				if (it != params.begin ()) results << ",";
				(this->*(it1->second))(it->second.data (), results);
			} else
				LogPrint (eLogError, "I2PControl: NetworkSetting unknown request: ", it->first);
		}
	}

	void I2PControlHandlers::InboundBandwidthLimit (const std::string& value, std::ostringstream& results)
	{
		if (value != "null")
			i2p::context.SetBandwidth (std::atoi(value.c_str()));
		int bw = i2p::context.GetBandwidthLimit();
		InsertParam (results, "i2p.router.net.bw.in", bw);
	}

	void I2PControlHandlers::OutboundBandwidthLimit (const std::string& value, std::ostringstream& results)
	{
		if (value != "null")
			i2p::context.SetBandwidth (std::atoi(value.c_str()));
		int bw = i2p::context.GetBandwidthLimit();
		InsertParam (results, "i2p.router.net.bw.out", bw);
	}

// ClientServicesInfo

	void I2PControlHandlers::ClientServicesInfoHandler (const boost::property_tree::ptree& params, std::ostringstream& results)
	{
		for (auto it = params.begin (); it != params.end (); it++)
		{
			LogPrint (eLogDebug, "I2PControl: ClientServicesInfo request: ", it->first);
			auto it1 = m_ClientServicesInfoHandlers.find (it->first);
			if (it1 != m_ClientServicesInfoHandlers.end ())
			{
				if (it != params.begin ()) results << ",";
				(this->*(it1->second))(results);
			}
			else
				LogPrint (eLogError, "I2PControl: ClientServicesInfo unknown request ", it->first);
		}
	}

	void I2PControlHandlers::I2PTunnelInfoHandler (std::ostringstream& results)
	{
		boost::property_tree::ptree pt;
		boost::property_tree::ptree client_tunnels, server_tunnels;

		for (auto& it: i2p::client::context.GetClientTunnels ())
		{
			auto& ident = it.second->GetLocalDestination ()->GetIdentHash();
			boost::property_tree::ptree ct;
			ct.put("address", i2p::client::context.GetAddressBook ().ToAddress(ident));
			client_tunnels.add_child(it.second->GetName (), ct);
		}

		auto& serverTunnels = i2p::client::context.GetServerTunnels ();
		if (!serverTunnels.empty ()) {
			for (auto& it: serverTunnels)
			{
				auto& ident = it.second->GetLocalDestination ()->GetIdentHash();
				boost::property_tree::ptree st;
				st.put("address", i2p::client::context.GetAddressBook ().ToAddress(ident));
				st.put("port", it.second->GetLocalPort ());
				server_tunnels.add_child(it.second->GetName (), st);
			}
		}

		auto& clientForwards = i2p::client::context.GetClientForwards ();
		if (!clientForwards.empty ())
		{
			for (auto& it: clientForwards)
			{
				auto& ident = it.second->GetLocalDestination ()->GetIdentHash();
				boost::property_tree::ptree ct;
				ct.put("address", i2p::client::context.GetAddressBook ().ToAddress(ident));
				client_tunnels.add_child(it.second->GetName (), ct);
			}
		}

		auto& serverForwards = i2p::client::context.GetServerForwards ();
		if (!serverForwards.empty ())
		{
			for (auto& it: serverForwards)
			{
				auto& ident = it.second->GetLocalDestination ()->GetIdentHash();
				boost::property_tree::ptree st;
				st.put("address", i2p::client::context.GetAddressBook ().ToAddress(ident));
				server_tunnels.add_child(it.second->GetName (), st);
			}
		}

		pt.add_child("client", client_tunnels);
		pt.add_child("server", server_tunnels);

		InsertParam (results, "I2PTunnel", pt);
	}

	void I2PControlHandlers::HTTPProxyInfoHandler (std::ostringstream& results)
	{
		boost::property_tree::ptree pt;

		auto httpProxy = i2p::client::context.GetHttpProxy ();
		if (httpProxy)
		{
			auto& ident = httpProxy->GetLocalDestination ()->GetIdentHash();
			pt.put("enabled", true);
			pt.put("address", i2p::client::context.GetAddressBook ().ToAddress(ident));
		}
		else
			pt.put("enabled", false);

		InsertParam (results, "HTTPProxy", pt);
	}

	void I2PControlHandlers::SOCKSInfoHandler (std::ostringstream& results)
	{
		boost::property_tree::ptree pt;

		auto socksProxy = i2p::client::context.GetSocksProxy ();
		if (socksProxy)
		{
			auto& ident = socksProxy->GetLocalDestination ()->GetIdentHash();
			pt.put("enabled", true);
			pt.put("address", i2p::client::context.GetAddressBook ().ToAddress(ident));
		}
		else
			pt.put("enabled", false);

		InsertParam (results, "SOCKS", pt);
	}

	void I2PControlHandlers::SAMInfoHandler (std::ostringstream& results)
	{
		boost::property_tree::ptree pt;
		auto sam = i2p::client::context.GetSAMBridge ();
		if (sam)
		{
			pt.put("enabled", true);
			boost::property_tree::ptree sam_sessions;
			for (auto& it: sam->GetSessions ())
			{
				boost::property_tree::ptree sam_session, sam_session_sockets;
				auto& name = it.second->GetLocalDestination ()->GetNickname ();
				auto& ident = it.second->GetLocalDestination ()->GetIdentHash();
				sam_session.put("name", name);
				sam_session.put("address", i2p::client::context.GetAddressBook ().ToAddress(ident));

				for (const auto& socket: sam->ListSockets(it.first))
				{
					boost::property_tree::ptree stream;
					stream.put("type", socket->GetSocketType ());
					stream.put("peer", socket->GetSocket ().remote_endpoint());

					sam_session_sockets.push_back(std::make_pair("", stream));
				}
				sam_session.add_child("sockets", sam_session_sockets);
				sam_sessions.add_child(it.first, sam_session);
			}

			pt.add_child("sessions", sam_sessions);
		}
		else
			pt.put("enabled", false);

		InsertParam (results, "SAM", pt);
	}

	void I2PControlHandlers::BOBInfoHandler (std::ostringstream& results)
	{
		boost::property_tree::ptree pt;
		auto bob = i2p::client::context.GetBOBCommandChannel ();
		if (bob)
		{
			/* TODO more info */
			pt.put("enabled", true);
		}
		else
			pt.put("enabled", false);

		InsertParam (results, "BOB", pt);
	}

	void I2PControlHandlers::I2CPInfoHandler (std::ostringstream& results)
	{
		boost::property_tree::ptree pt;
		auto i2cp = i2p::client::context.GetI2CPServer ();
		if (i2cp)
		{
			/* TODO more info */
			pt.put("enabled", true);
		}
		else
			pt.put("enabled", false);

		InsertParam (results, "I2CP", pt);
	}
}
}
