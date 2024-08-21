/*
* Copyright (c) 2013-2024, The PurpleI2P Project
*
* This file is part of Purple i2pd project and licensed under BSD3
*
* See full license text in LICENSE file at top of project tree
*/

#ifndef DATAGRAM_H__
#define DATAGRAM_H__

#include <inttypes.h>
#include <memory>
#include <functional>
#include <map>
#include <vector>
#include "Base.h"
#include "Gzip.h"
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
	const uint64_t DATAGRAM_MAX_FLUSH_INTERVAL = 5; // in milliseconds

	class DatagramSession : public std::enable_shared_from_this<DatagramSession>
	{

		public:

			DatagramSession(std::shared_ptr<i2p::client::ClientDestination> localDestination, const i2p::data::IdentHash & remoteIdent);

			void Start ();
			void Stop ();


			/** @brief ack the garlic routing path */
			void Ack();

			/** send an i2np message to remote endpoint for this session */
			void SendMsg(std::shared_ptr<I2NPMessage> msg);
			void FlushSendQueue();
			/** get the last time in milliseconds for when we used this datagram session */
			uint64_t LastActivity() const { return m_LastUse; }

		bool IsRatchets () const { return m_RoutingSession && m_RoutingSession->IsRatchets (); }

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

			std::shared_ptr<i2p::garlic::GarlicRoutingPath> GetSharedRoutingPath();

			void HandleLeaseSetUpdated(std::shared_ptr<i2p::data::LeaseSet> ls);

		private:

			std::shared_ptr<i2p::client::ClientDestination> m_LocalDestination;
			i2p::data::IdentHash m_RemoteIdent;
			std::shared_ptr<const i2p::data::LeaseSet> m_RemoteLeaseSet;
			std::shared_ptr<i2p::garlic::GarlicRoutingSession> m_RoutingSession;
			std::vector<std::shared_ptr<i2p::garlic::GarlicRoutingSession> > m_PendingRoutingSessions;
			std::vector<std::shared_ptr<I2NPMessage> > m_SendQueue;
			uint64_t m_LastUse, m_LastFlush; // milliseconds
			bool m_RequestingLS;
	};

	typedef std::shared_ptr<DatagramSession> DatagramSession_ptr;

	const size_t MAX_DATAGRAM_SIZE = 32768;
	class DatagramDestination
	{
		typedef std::function<void (const i2p::data::IdentityEx& from, uint16_t fromPort, uint16_t toPort, const uint8_t * buf, size_t len)> Receiver;
		typedef std::function<void (uint16_t fromPort, uint16_t toPort, const uint8_t * buf, size_t len)> RawReceiver;

		public:

			DatagramDestination (std::shared_ptr<i2p::client::ClientDestination> owner, bool gzip);
			~DatagramDestination ();

			void SendDatagramTo (const uint8_t * payload, size_t len, const i2p::data::IdentHash & ident, uint16_t fromPort = 0, uint16_t toPort = 0);
			void SendRawDatagramTo (const uint8_t * payload, size_t len, const i2p::data::IdentHash & ident, uint16_t fromPort = 0, uint16_t toPort = 0);
			// TODO: implement calls from other thread from SAM

			std::shared_ptr<DatagramSession> GetSession(const i2p::data::IdentHash & ident);
			void SendDatagram (std::shared_ptr<DatagramSession> session, const uint8_t * payload, size_t len, uint16_t fromPort, uint16_t toPort);
			void SendRawDatagram (std::shared_ptr<DatagramSession> session, const uint8_t * payload, size_t len, uint16_t fromPort, uint16_t toPort);
			void FlushSendQueue (std::shared_ptr<DatagramSession> session);

			void HandleDataMessagePayload (uint16_t fromPort, uint16_t toPort, const uint8_t * buf, size_t len, bool isRaw = false);


			void SetReceiver (const Receiver& receiver, uint16_t port);
			void ResetReceiver (uint16_t port);

			void SetRawReceiver (const RawReceiver& receiver, uint16_t port);
			void ResetRawReceiver (uint16_t port);

			std::shared_ptr<DatagramSession::Info> GetInfoForRemote(const i2p::data::IdentHash & remote);

			// clean up stale sessions
			void CleanUp ();

		private:

			std::shared_ptr<DatagramSession> ObtainSession(const i2p::data::IdentHash & ident);

			std::shared_ptr<I2NPMessage> CreateDataMessage (const std::vector<std::pair<const uint8_t *, size_t> >& payloads,
				uint16_t fromPort, uint16_t toPort, bool isRaw = false, bool checksum = true);

			void HandleDatagram (uint16_t fromPort, uint16_t toPort, uint8_t *const& buf, size_t len);
			void HandleRawDatagram (uint16_t fromPort, uint16_t toPort, const uint8_t * buf, size_t len);

			Receiver FindReceiver(uint16_t port);
			RawReceiver FindRawReceiver(uint16_t port);

		private:

			std::shared_ptr<i2p::client::ClientDestination> m_Owner;

			std::mutex m_SessionsMutex;
			std::map<i2p::data::IdentHash, DatagramSession_ptr > m_Sessions;

			Receiver m_DefaultReceiver;
			RawReceiver m_DefaultRawReceiver;
			uint16_t m_DefaultReceiverPort;
			uint16_t m_DefaultRawReceiverPort;
			std::mutex m_ReceiversMutex;
			std::mutex m_RawReceiversMutex;
			std::unordered_map<uint16_t, Receiver> m_ReceiversByPorts;
			std::unordered_map<uint16_t, RawReceiver> m_RawReceiversByPorts;

			bool m_Gzip; // gzip compression of data messages
			i2p::data::GzipInflator m_Inflator;
			std::unique_ptr<i2p::data::GzipDeflator> m_Deflator;
			std::vector<uint8_t> m_From, m_Signature;
			i2p::util::MemoryPool<I2NPMessageBuffer<I2NP_MAX_MESSAGE_SIZE> > m_I2NPMsgsPool;
	};
}
}

#endif
