#ifndef DATAGRAM_H__
#define DATAGRAM_H__

#include <inttypes.h>
#include <memory>
#include <functional>
#include <map>
#include "Base.h"
#include "Identity.h"
#include "LeaseSet.h"
#include "I2NPProtocol.h"
#include "Garlic.h"

namespace i2p
{
namespace client
{
	class ClientDestination;
}
namespace datagram
{
	// milliseconds for max session idle time 
	const uint64_t DATAGRAM_SESSION_MAX_IDLE = 10 * 60 * 1000;
	// milliseconds for how long we try sticking to a dead routing path before trying to switch
	const uint64_t DATAGRAM_SESSION_PATH_TIMEOUT = 5000;
	// milliseconds interval a routing path is used before switching
	const uint64_t DATAGRAM_SESSION_PATH_SWITCH_INTERVAL = 20 * 60 * 1000;
	// milliseconds before lease expire should we try switching leases
	const uint64_t DATAGRAM_SESSION_LEASE_HANDOVER_WINDOW = 10 * 1000;
	// milliseconds fudge factor for leases handover
	const uint64_t DATAGRAM_SESSION_LEASE_HANDOVER_FUDGE = 1000;

	
	class DatagramSession
	{
	public:
		DatagramSession(i2p::client::ClientDestination * localDestination,
										const i2p::data::IdentHash & remoteIdent);

		/** send an i2np message to remote endpoint for this session */
		void SendMsg(std::shared_ptr<I2NPMessage> msg);
		/** get the last time in milliseconds for when we used this datagram session */
		uint64_t LastActivity() const { return m_LastUse; }
		/** get the last time in milliseconds when we successfully sent data */
		uint64_t LastSuccess() const { return m_LastSuccess; }
		struct Info
		{
			std::shared_ptr<const i2p::data::IdentHash> IBGW;
			std::shared_ptr<const i2p::data::IdentHash> OBEP;
			const uint64_t activity;
			const uint64_t success;
			Info() : IBGW(nullptr), OBEP(nullptr), activity(0), success(0) {}
			Info(const uint8_t * ibgw, const uint8_t * obep, const uint64_t a, const uint64_t s) :
				activity(a),
				success(s) {
				if(ibgw) IBGW = std::make_shared<i2p::data::IdentHash>(ibgw);
				else IBGW = nullptr;
				if(obep) OBEP = std::make_shared<i2p::data::IdentHash>(obep);
				else OBEP = nullptr;
			}
		};

		Info GetSessionInfo() const;

		
	private:

		/** update our routing path we are using, mark that we have changed paths */
		void UpdateRoutingPath(const std::shared_ptr<i2p::garlic::GarlicRoutingPath> & path);

		/** return true if we should switch routing paths because of path lifetime or timeout otherwise false */
		bool ShouldUpdateRoutingPath() const;

		/** return true if we should switch the lease for out routing path otherwise return false */
		bool ShouldSwitchLease() const;
		
		/** get next usable routing path, try reusing outbound tunnels	*/
		std::shared_ptr<i2p::garlic::GarlicRoutingPath> GetNextRoutingPath();
		/** 
		 *	mark current routing path as invalid and clear it
		 *	if the outbound tunnel we were using was okay don't use the IBGW in the routing path's lease next time
		 */
		void ResetRoutingPath();

		/** get next usable lease, does not fetch or update if expired or have no lease set */
		std::shared_ptr<const i2p::data::Lease> GetNextLease();
		
		void HandleSend(std::shared_ptr<I2NPMessage> msg);
		void HandleGotLeaseSet(std::shared_ptr<const i2p::data::LeaseSet> remoteIdent,
													 std::shared_ptr<I2NPMessage> msg);
		void UpdateLeaseSet(std::shared_ptr<I2NPMessage> msg=nullptr);
		
	private:
		i2p::client::ClientDestination * m_LocalDestination;
		i2p::data::IdentHash m_RemoteIdentity;
		std::shared_ptr<i2p::garlic::GarlicRoutingSession> m_RoutingSession;
		// Ident hash of IBGW that are invalid
		std::vector<i2p::data::IdentHash> m_InvalidIBGW;
		std::shared_ptr<const i2p::data::LeaseSet> m_RemoteLeaseSet;
		uint64_t m_LastUse;
		uint64_t m_LastPathChange;
		uint64_t m_LastSuccess;
	};
	
	const size_t MAX_DATAGRAM_SIZE = 32768;	 
	class DatagramDestination
	{
		typedef std::function<void (const i2p::data::IdentityEx& from, uint16_t fromPort, uint16_t toPort, const uint8_t * buf, size_t len)> Receiver;

		public:

    
			DatagramDestination (std::shared_ptr<i2p::client::ClientDestination> owner);
			~DatagramDestination ();				

			void SendDatagramTo (const uint8_t * payload, size_t len, const i2p::data::IdentHash& ident, uint16_t fromPort = 0, uint16_t toPort = 0);
			void HandleDataMessagePayload (uint16_t fromPort, uint16_t toPort, const uint8_t * buf, size_t len);

			void SetReceiver (const Receiver& receiver) { m_Receiver = receiver; };
			void ResetReceiver () { m_Receiver = nullptr; };

			void SetReceiver (const Receiver& receiver, uint16_t port) { std::lock_guard<std::mutex> lock(m_ReceiversMutex); m_ReceiversByPorts[port] = receiver; };
			void ResetReceiver (uint16_t port) { std::lock_guard<std::mutex> lock(m_ReceiversMutex); m_ReceiversByPorts.erase (port); };

			std::shared_ptr<DatagramSession::Info> GetInfoForRemote(const i2p::data::IdentHash & remote);
		
			// clean up stale sessions
			void CleanUp ();

		private:
						
			std::shared_ptr<DatagramSession> ObtainSession(const i2p::data::IdentHash & ident);
			
			std::shared_ptr<I2NPMessage> CreateDataMessage (const uint8_t * payload, size_t len, uint16_t fromPort, uint16_t toPort);

			void HandleDatagram (uint16_t fromPort, uint16_t toPort, uint8_t *const& buf, size_t len);

			/** find a receiver by port, if none by port is found try default receiever, otherwise returns nullptr */
			Receiver FindReceiver(uint16_t port);
			
		private:
			i2p::client::ClientDestination * m_Owner;
			i2p::data::IdentityEx m_Identity;
			Receiver m_Receiver; // default
			std::mutex m_SessionsMutex;
			std::map<i2p::data::IdentHash, std::shared_ptr<DatagramSession> > m_Sessions;
			std::mutex m_ReceiversMutex;
			std::map<uint16_t, Receiver> m_ReceiversByPorts;

			i2p::data::GzipInflator m_Inflator;
			i2p::data::GzipDeflator m_Deflator;
	};		
}
}

#endif

