/*
* Copyright (c) 2013-2024, The PurpleI2P Project
*
* This file is part of Purple i2pd project and licensed under BSD3
*
* See full license text in LICENSE file at top of project tree
*/

#ifndef UDPTUNNEL_H__
#define UDPTUNNEL_H__

#include <inttypes.h>
#include <string>
#include <memory>
#include <thread>
#include <vector>
#include <unordered_map>
#include <boost/asio.hpp>
#include "Identity.h"
#include "Destination.h"
#include "Datagram.h"
#include "AddressBook.h"

namespace i2p
{
namespace client
{
	/** 2 minute timeout for udp sessions */
	const uint64_t I2P_UDP_SESSION_TIMEOUT = 1000 * 60 * 2;
	const uint64_t I2P_UDP_REPLIABLE_DATAGRAM_INTERVAL = 100; // in milliseconds

	/** max size for i2p udp */
	const size_t I2P_UDP_MAX_MTU = 64*1024;

	struct UDPSession
	{
		i2p::datagram::DatagramDestination * m_Destination;
		boost::asio::ip::udp::socket IPSocket;
		i2p::data::IdentHash Identity;
		boost::asio::ip::udp::endpoint FromEndpoint;
		boost::asio::ip::udp::endpoint SendEndpoint;
		uint64_t LastActivity;

		uint16_t LocalPort;
		uint16_t RemotePort;

		uint8_t m_Buffer[I2P_UDP_MAX_MTU];

		UDPSession(boost::asio::ip::udp::endpoint localEndpoint,
			const std::shared_ptr<i2p::client::ClientDestination> & localDestination,
			const boost::asio::ip::udp::endpoint& remote, const i2p::data::IdentHash& ident,
			uint16_t ourPort, uint16_t theirPort);
		void HandleReceived(const boost::system::error_code & ecode, std::size_t len);
		void Receive();
	};


	/** read only info about a datagram session */
	struct DatagramSessionInfo
	{
		/** the name of this forward */
		std::string Name;
		/** ident hash of local destination */
		std::shared_ptr<const i2p::data::IdentHash> LocalIdent;
		/** ident hash of remote destination */
		std::shared_ptr<const i2p::data::IdentHash> RemoteIdent;
		/** ident hash of IBGW in use currently in this session or nullptr if none is set */
		std::shared_ptr<const i2p::data::IdentHash> CurrentIBGW;
		/** ident hash of OBEP in use for this session or nullptr if none is set */
		std::shared_ptr<const i2p::data::IdentHash> CurrentOBEP;
		/** i2p router's udp endpoint */
		boost::asio::ip::udp::endpoint LocalEndpoint;
		/** client's udp endpoint */
		boost::asio::ip::udp::endpoint RemoteEndpoint;
		/** how long has this conversation been idle in ms */
		uint64_t idle;
	};

	typedef std::shared_ptr<UDPSession> UDPSessionPtr;

	/** server side udp tunnel, many i2p inbound to 1 ip outbound */
	class I2PUDPServerTunnel
	{
		public:

			I2PUDPServerTunnel (const std::string & name,
				std::shared_ptr<i2p::client::ClientDestination> localDestination,
				const boost::asio::ip::address& localAddress,
				const boost::asio::ip::udp::endpoint& forwardTo, uint16_t port, bool gzip);
			~I2PUDPServerTunnel ();

			/** expire stale udp conversations */
			void ExpireStale (const uint64_t delta=I2P_UDP_SESSION_TIMEOUT);
			void Start ();
			void Stop ();
			const char * GetName () const { return m_Name.c_str(); }
			std::vector<std::shared_ptr<DatagramSessionInfo> > GetSessions ();
			std::shared_ptr<ClientDestination> GetLocalDestination () const { return m_LocalDest; }

			void SetUniqueLocal (bool isUniqueLocal = true) { m_IsUniqueLocal = isUniqueLocal; }

		private:

			void HandleRecvFromI2P (const i2p::data::IdentityEx& from, uint16_t fromPort, uint16_t toPort, const uint8_t * buf, size_t len);
			void HandleRecvFromI2PRaw (uint16_t fromPort, uint16_t toPort, const uint8_t * buf, size_t len);
			UDPSessionPtr ObtainUDPSession (const i2p::data::IdentityEx& from, uint16_t localPort, uint16_t remotePort);
			uint32_t GetSessionIndex (uint16_t fromPort, uint16_t toPort) const { return ((uint32_t)fromPort << 16) + toPort; }

		private:

			bool m_IsUniqueLocal;
			const std::string m_Name;
			boost::asio::ip::address m_LocalAddress;
			boost::asio::ip::udp::endpoint m_RemoteEndpoint;
			std::mutex m_SessionsMutex;
			std::unordered_map<uint32_t, UDPSessionPtr> m_Sessions; // (from port, to port)->session
			std::shared_ptr<i2p::client::ClientDestination> m_LocalDest;
			UDPSessionPtr m_LastSession;
			uint16_t m_inPort;
			bool m_Gzip;

		public:

			bool isUpdated; // transient, used during reload only
	};

	class I2PUDPClientTunnel
	{
		public:

			I2PUDPClientTunnel (const std::string & name, const std::string &remoteDest,
				const boost::asio::ip::udp::endpoint& localEndpoint, std::shared_ptr<i2p::client::ClientDestination> localDestination,
				uint16_t remotePort, bool gzip);
			~I2PUDPClientTunnel ();

			void Start ();
			void Stop ();
			const char * GetName () const { return m_Name.c_str(); }
			std::vector<std::shared_ptr<DatagramSessionInfo> > GetSessions ();

			bool IsLocalDestination (const i2p::data::IdentHash & destination) const { return destination == m_LocalDest->GetIdentHash(); }

			std::shared_ptr<ClientDestination> GetLocalDestination () const { return m_LocalDest; }
			inline void SetLocalDestination (std::shared_ptr<ClientDestination> dest)
			{
				if (m_LocalDest) m_LocalDest->Release ();
				if (dest) dest->Acquire ();
				m_LocalDest = dest;
			}

			void ExpireStale (const uint64_t delta=I2P_UDP_SESSION_TIMEOUT);

		private:

			typedef std::pair<boost::asio::ip::udp::endpoint, uint64_t> UDPConvo;
			void RecvFromLocal ();
			void HandleRecvFromLocal (const boost::system::error_code & e, std::size_t transferred);
			void HandleRecvFromI2P (const i2p::data::IdentityEx& from, uint16_t fromPort, uint16_t toPort, const uint8_t * buf, size_t len);
			void HandleRecvFromI2PRaw (uint16_t fromPort, uint16_t toPort, const uint8_t * buf, size_t len);
			void TryResolving ();

		private:

			const std::string m_Name;
			std::mutex m_SessionsMutex;
			std::unordered_map<uint16_t, std::shared_ptr<UDPConvo> > m_Sessions; // maps i2p port -> local udp convo
			const std::string m_RemoteDest;
			std::shared_ptr<i2p::client::ClientDestination> m_LocalDest;
			const boost::asio::ip::udp::endpoint m_LocalEndpoint;
			std::shared_ptr<const Address> m_RemoteAddr;
			std::thread * m_ResolveThread;
			std::unique_ptr<boost::asio::ip::udp::socket> m_LocalSocket;
			boost::asio::ip::udp::endpoint m_RecvEndpoint;
			uint8_t m_RecvBuff[I2P_UDP_MAX_MTU];
			uint16_t RemotePort, m_LastPort;
			bool m_cancel_resolve;
			bool m_Gzip;
			std::shared_ptr<UDPConvo> m_LastSession;

		public:

			bool isUpdated; // transient, used during reload only
	};


}
}

#endif
