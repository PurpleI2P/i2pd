#ifndef MATCHED_DESTINATION_H_
#define MATCHED_DESTINATION_H_
#include "Destination.h"
#include <string>

namespace dotnet
{
namespace client
{
	/**
		 client tunnel that uses same OBEP as IBGW of each remote lease for a remote destination
	 */
	class MatchedTunnelDestination : public ClientDestination, public dotnet::tunnel::ITunnelPeerSelector
	{
	public:
		MatchedTunnelDestination(const dotnet::data::PrivateKeys& keys, const std::string & remoteName, const std::map<std::string, std::string> * params = nullptr);
		bool Start();
		bool Stop();

		bool SelectPeers(dotnet::tunnel::Path & peers, int hops, bool inbound);
		bool OnBuildResult(const dotnet::tunnel::Path & peers, bool inbound, dotnet::tunnel::TunnelBuildResult result);

	private:
		void ResolveCurrentLeaseSet();
		void HandleFoundCurrentLeaseSet(std::shared_ptr<const dotnet::data::LeaseSet> ls);

	private:
		std::string m_RemoteName;
		dotnet::data::IdentHash m_RemoteIdent;
		std::shared_ptr<const dotnet::data::LeaseSet> m_RemoteLeaseSet;
		std::shared_ptr<boost::asio::deadline_timer> m_ResolveTimer;
	};
}
}

#endif
