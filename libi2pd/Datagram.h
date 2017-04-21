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
	const uint64_t DATAGRAM_SESSION_PATH_TIMEOUT = 10 * 1000;
	// milliseconds interval a routing path is used before switching
	const uint64_t DATAGRAM_SESSION_PATH_SWITCH_INTERVAL = 20 * 60 * 1000;
	// milliseconds before lease expire should we try switching leases
	const uint64_t DATAGRAM_SESSION_LEASE_HANDOVER_WINDOW = 30 * 1000;
	// milliseconds fudge factor for leases handover
	const uint64_t DATAGRAM_SESSION_LEASE_HANDOVER_FUDGE = 1000;
	// milliseconds minimum time between path switches
	const uint64_t DATAGRAM_SESSION_PATH_MIN_LIFETIME = 5 * 1000;
  // max 64 messages buffered in send queue for each datagram session
  const size_t DATAGRAM_SEND_QUEUE_MAX_SIZE = 64;

	class DatagramSession : public std::enable_shared_from_this<DatagramSession>
	{
	public:
		DatagramSession(i2p::client::ClientDestination * localDestination, const i2p::data::IdentHash & remoteIdent);

		void Start ();
		void Stop ();


    /** @brief ack the garlic routing path */
    void Ack();

		/** send an i2np message to remote endpoint for this session */
		void SendMsg(std::shared_ptr<I2NPMessage> msg);
		/** get the last time in milliseconds for when we used this datagram session */
		uint64_t LastActivity() const { return m_LastUse; }

		struct Info
		{
			std::shared_ptr<const i2p::data::IdentHash> IBGW;
			std::shared_ptr<const i2p::data::IdentHash> OBEP;
			const uint64_t activity;

			Info() : IBGW(nullptr), OBEP(nullptr), activity(0) {}
			Info(const uint8_t * ibgw, const uint8_t * obep, const uint64_t a) :
				activity(a) {
				if(ibgw) IBGW = std::make_shared<i2p::data::IdentHash>(ibgw);
				else IBGW = nullptr;
				if(obep) OBEP = std::make_shared<i2p::data::IdentHash>(obep);
				else OBEP = nullptr;
			}
		};

		Info GetSessionInfo() const;

	private:

    void FlushSendQueue();
    void ScheduleFlushSendQueue();

    void HandleSend(std::shared_ptr<I2NPMessage> msg);

    std::shared_ptr<i2p::garlic::GarlicRoutingPath> GetSharedRoutingPath();

    void HandleLeaseSetUpdated(std::shared_ptr<i2p::data::LeaseSet> ls);

	private:
		i2p::client::ClientDestination * m_LocalDestination;
    i2p::data::IdentHash m_RemoteIdent;
    std::shared_ptr<const i2p::data::LeaseSet> m_RemoteLeaseSet;
    std::shared_ptr<i2p::garlic::GarlicRoutingSession> m_RoutingSession;
    std::shared_ptr<const i2p::data::Lease> m_CurrentRemoteLease;
    std::shared_ptr<i2p::tunnel::OutboundTunnel> m_CurrentOutboundTunnel;
    boost::asio::deadline_timer m_SendQueueTimer;
    std::vector<std::shared_ptr<I2NPMessage> > m_SendQueue;
    uint64_t m_LastUse;
    bool m_RequestingLS;
	};

	typedef std::shared_ptr<DatagramSession> DatagramSession_ptr;

	const size_t MAX_DATAGRAM_SIZE = 32768;
	class DatagramDestination
	{
		typedef std::function<void (const i2p::data::IdentityEx& from, uint16_t fromPort, uint16_t toPort, const uint8_t * buf, size_t len)> Receiver;

		public:


    DatagramDestination (std::shared_ptr<i2p::client::ClientDestination> owner);
			~DatagramDestination ();

    	void SendDatagramTo (const uint8_t * payload, size_t len, const i2p::data::IdentHash & ident, uint16_t fromPort = 0, uint16_t toPort = 0);
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
			std::map<i2p::data::IdentHash, DatagramSession_ptr > m_Sessions;
			std::mutex m_ReceiversMutex;
			std::map<uint16_t, Receiver> m_ReceiversByPorts;

			i2p::data::GzipInflator m_Inflator;
			i2p::data::GzipDeflator m_Deflator;
	};
}
}

#endif
