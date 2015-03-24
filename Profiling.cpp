#include <boost/property_tree/ptree.hpp>
#include <boost/property_tree/ini_parser.hpp>
#include "Profiling.h"

namespace i2p
{
namespace data
{
	RouterProfile::RouterProfile (const IdentHash& identHash):
		m_IdentHash (identHash), m_NumTunnelsAgreed (0), m_NumTunnelsDeclined (0)
	{
	}

	std::shared_ptr<RouterProfile> GetProfile (const IdentHash& identHash)
	{
		return std::make_shared<RouterProfile> (identHash);
	}		
}		
}	