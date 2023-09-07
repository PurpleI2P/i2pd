/*
* Copyright (c) 2013-2022, The PurpleI2P Project
*
* This file is part of Purple i2pd project and licensed under BSD3
*
* See full license text in LICENSE file at top of project tree
*/

#ifndef I2P_CONTROL_HANDLERS_H__
#define I2P_CONTROL_HANDLERS_H__

#include <sstream>
#include <map>
#include <string>
#include <boost/property_tree/ptree.hpp>

namespace i2p
{
namespace client
{
	class I2PControlHandlers
	{
		public:

			I2PControlHandlers ();

			// methods
			// TODO: make protected
			void RouterInfoHandler (const boost::property_tree::ptree& params, std::ostringstream& results);
			void NetworkSettingHandler (const boost::property_tree::ptree& params, std::ostringstream& results);
			void ClientServicesInfoHandler (const boost::property_tree::ptree& params, std::ostringstream& results);

		protected:

			void InsertParam (std::ostringstream& ss, const std::string& name, int value) const;
			void InsertParam (std::ostringstream& ss, const std::string& name, double value) const;
			void InsertParam (std::ostringstream& ss, const std::string& name, const std::string& value, bool quotes = true) const;
			void InsertParam (std::ostringstream& ss, const std::string& name, const boost::property_tree::ptree& value) const;

		private:

			// RouterInfo
			typedef void (I2PControlHandlers::*RouterInfoRequestHandler)(std::ostringstream& results);
			void UptimeHandler (std::ostringstream& results);
			void VersionHandler (std::ostringstream& results);
			void StatusHandler (std::ostringstream& results);
			void NetDbKnownPeersHandler (std::ostringstream& results);
			void NetDbActivePeersHandler (std::ostringstream& results);
			void NetStatusHandler (std::ostringstream& results);
			void TunnelsParticipatingHandler (std::ostringstream& results);
			void TunnelsSuccessRateHandler (std::ostringstream& results);
			void InboundBandwidth1S (std::ostringstream& results);
			void InboundBandwidth15S (std::ostringstream& results);
			void OutboundBandwidth1S (std::ostringstream& results);
			void OutboundBandwidth15S (std::ostringstream& results);
			void NetTotalReceivedBytes (std::ostringstream& results);
			void NetTotalSentBytes (std::ostringstream& results);

			// NetworkSetting
			typedef void (I2PControlHandlers::*NetworkSettingRequestHandler)(const std::string& value, std::ostringstream& results);
			void InboundBandwidthLimit  (const std::string& value, std::ostringstream& results);
			void OutboundBandwidthLimit (const std::string& value, std::ostringstream& results);

			// ClientServicesInfo
			typedef void (I2PControlHandlers::*ClientServicesInfoRequestHandler)(std::ostringstream& results);
			void I2PTunnelInfoHandler (std::ostringstream& results);
			void HTTPProxyInfoHandler (std::ostringstream& results);
			void SOCKSInfoHandler (std::ostringstream& results);
			void SAMInfoHandler (std::ostringstream& results);
			void BOBInfoHandler (std::ostringstream& results);
			void I2CPInfoHandler (std::ostringstream& results);

		private:

			std::map<std::string, RouterInfoRequestHandler> m_RouterInfoHandlers;
			std::map<std::string, NetworkSettingRequestHandler> m_NetworkSettingHandlers;
			std::map<std::string, ClientServicesInfoRequestHandler> m_ClientServicesInfoHandlers;
	};
}
}

#endif
