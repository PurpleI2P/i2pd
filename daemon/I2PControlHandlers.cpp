/*
* Copyright (c) 2013-2022, The PurpleI2P Project
*
* This file is part of Purple i2pd project and licensed under BSD3
*
* See full license text in LICENSE file at top of project tree
*/

#include <iomanip>
#include <boost/lexical_cast.hpp>
#include <boost/property_tree/json_parser.hpp>
#include "Log.h"
#include "ClientContext.h"
#include "I2PControlHandlers.h"

namespace i2p
{
namespace client
{
	I2PControlHandlers::I2PControlHandlers ()
	{
		// ClientServicesInfo
		m_ClientServicesInfoHandlers["I2PTunnel"] = &I2PControlHandlers::I2PTunnelInfoHandler;
		m_ClientServicesInfoHandlers["HTTPProxy"] = &I2PControlHandlers::HTTPProxyInfoHandler;
		m_ClientServicesInfoHandlers["SOCKS"]     = &I2PControlHandlers::SOCKSInfoHandler;
		m_ClientServicesInfoHandlers["SAM"]       = &I2PControlHandlers::SAMInfoHandler;
		m_ClientServicesInfoHandlers["BOB"]       = &I2PControlHandlers::BOBInfoHandler;
		m_ClientServicesInfoHandlers["I2CP"]      = &I2PControlHandlers::I2CPInfoHandler;
	}	

	void I2PControlHandlers::InsertParam (std::ostringstream& ss, const std::string& name, const boost::property_tree::ptree& value) const
	{
		std::ostringstream buf;
		boost::property_tree::write_json (buf, value, false);
		ss << "\"" << name << "\":" << buf.str();
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
