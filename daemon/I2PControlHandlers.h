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

			// TODO: make protected
			void ClientServicesInfoHandler (const boost::property_tree::ptree& params, std::ostringstream& results);
		
		private:

			void InsertParam (std::ostringstream& ss, const std::string& name, const boost::property_tree::ptree& value) const;
		
			// ClientServicesInfo
			typedef void (I2PControlHandlers::*ClientServicesInfoRequestHandler)(std::ostringstream& results);
			void I2PTunnelInfoHandler (std::ostringstream& results);
			void HTTPProxyInfoHandler (std::ostringstream& results);
			void SOCKSInfoHandler (std::ostringstream& results);
			void SAMInfoHandler (std::ostringstream& results);
			void BOBInfoHandler (std::ostringstream& results);
			void I2CPInfoHandler (std::ostringstream& results);
		
		private:

			std::map<std::string, ClientServicesInfoRequestHandler> m_ClientServicesInfoHandlers;
	};
}
}

#endif
