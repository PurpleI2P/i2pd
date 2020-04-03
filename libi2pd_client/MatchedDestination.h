#ifndef MATCHED_DESTINATION_H_
#define MATCHED_DESTINATION_H_
#include "Destination.h"
#include <string>

namespace i2p
{
namespace client
{
	/**
		 client tunnel that uses same OBEP as IBGW of each remote lease for a remote destination
	 */
	class MatchedTunnelDestination : public RunnableClientDestination, public i2p::tunnel::ITunnelPeerSelector
	{
	public:
		MatchedTunnelDestination(const i2p::data::PrivateKeys& keys, const std::string & remoteName, const std::map<std::string, std::string> * params = nullptr);
		void Start();
		void Stop();

		bool SelectPeers(i2p::tunnel::Path & peers, int hops, bool inbound);

	private:
		void ResolveCurrentLeaseSet();
		void HandleFoundCurrentLeaseSet(std::shared_ptr<const i2p::data::LeaseSet> ls);

	private:
		std::string m_RemoteName;
		i2p::data::IdentHash m_RemoteIdent;
		std::shared_ptr<const i2p::data::LeaseSet> m_RemoteLeaseSet;
		std::shared_ptr<boost::asio::deadline_timer> m_ResolveTimer;
	};
}
}

#endif
