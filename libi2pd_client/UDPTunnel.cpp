/*
* Copyright (c) 2013-2024, The PurpleI2P Project
*
* This file is part of Purple i2pd project and licensed under BSD3
*
* See full license text in LICENSE file at top of project tree
*/

#include "Log.h"
#include "util.h"
#include "ClientContext.h"
#include "I2PTunnel.h" // for GetLoopbackAddressFor
#include "UDPTunnel.h"

namespace i2p
{
namespace client
{
	void I2PUDPServerTunnel::HandleRecvFromI2P(const i2p::data::IdentityEx& from, uint16_t fromPort, uint16_t toPort, const uint8_t * buf, size_t len)
	{
		if (!m_LastSession || m_LastSession->Identity.GetLL()[0] != from.GetIdentHash ().GetLL()[0] || fromPort != m_LastSession->RemotePort)
			m_LastSession = ObtainUDPSession(from, toPort, fromPort);
		m_LastSession->IPSocket.send_to(boost::asio::buffer(buf, len), m_RemoteEndpoint);
		m_LastSession->LastActivity = i2p::util::GetMillisecondsSinceEpoch();
	}

	void I2PUDPServerTunnel::HandleRecvFromI2PRaw (uint16_t fromPort, uint16_t toPort, const uint8_t * buf, size_t len)
	{
		if (m_LastSession && (fromPort != m_LastSession->RemotePort || toPort != m_LastSession->LocalPort))
		{
			std::lock_guard<std::mutex> lock(m_SessionsMutex);
			auto it = m_Sessions.find (GetSessionIndex (fromPort, toPort));
			if (it != m_Sessions.end ())
				m_LastSession = it->second;
			else
				m_LastSession = nullptr;
		}
		if (m_LastSession)
		{
			m_LastSession->IPSocket.send_to(boost::asio::buffer(buf, len), m_RemoteEndpoint);
			m_LastSession->LastActivity = i2p::util::GetMillisecondsSinceEpoch();
		}
	}

	void I2PUDPServerTunnel::ExpireStale(const uint64_t delta)
	{
		std::lock_guard<std::mutex> lock(m_SessionsMutex);
		uint64_t now = i2p::util::GetMillisecondsSinceEpoch();
		auto itr = m_Sessions.begin();
		while(itr != m_Sessions.end())
		{
			if(now - itr->second->LastActivity >= delta )
				itr = m_Sessions.erase(itr);
			else
				itr++;
		}
	}

	void I2PUDPClientTunnel::ExpireStale(const uint64_t delta)
	{
		std::lock_guard<std::mutex> lock(m_SessionsMutex);
		uint64_t now = i2p::util::GetMillisecondsSinceEpoch();
		std::vector<uint16_t> removePorts;
		for (const auto & s : m_Sessions) {
			if (now - s.second->second >= delta)
				removePorts.push_back(s.first);
		}
		for(auto port : removePorts) {
			m_Sessions.erase(port);
		}
	}

	UDPSessionPtr I2PUDPServerTunnel::ObtainUDPSession(const i2p::data::IdentityEx& from, uint16_t localPort, uint16_t remotePort)
	{
		auto ih = from.GetIdentHash();
		auto idx = GetSessionIndex (remotePort, localPort);
		{
			std::lock_guard<std::mutex> lock(m_SessionsMutex);
			auto it = m_Sessions.find (idx);
			if (it != m_Sessions.end ())
			{
				if (it->second->Identity.GetLL()[0] == ih.GetLL()[0])
				{
					LogPrint(eLogDebug, "UDPServer: Found session ", it->second->IPSocket.local_endpoint(), " ", ih.ToBase32());
					return it->second;
				}
				else
				{
					LogPrint(eLogWarning, "UDPServer: Session with from ", remotePort, " and to ", localPort, " ports already exists. But from differend address. Removed");
					m_Sessions.erase (it);
				}
			}
		}

		boost::asio::ip::address addr;
		/** create new udp session */
		if(m_IsUniqueLocal && m_LocalAddress.is_loopback())
		{
			auto ident = from.GetIdentHash();
			addr = GetLoopbackAddressFor(ident);
		}
		else
			addr = m_LocalAddress;

		auto s = std::make_shared<UDPSession>(boost::asio::ip::udp::endpoint(addr, 0),
			m_LocalDest, m_RemoteEndpoint, ih, localPort, remotePort);
		std::lock_guard<std::mutex> lock(m_SessionsMutex);
		m_Sessions.emplace (idx, s);
		return s;
	}

	UDPSession::UDPSession(boost::asio::ip::udp::endpoint localEndpoint,
		const std::shared_ptr<i2p::client::ClientDestination> & localDestination,
		const boost::asio::ip::udp::endpoint& endpoint, const i2p::data::IdentHash& to,
		uint16_t ourPort, uint16_t theirPort) :
		m_Destination(localDestination->GetDatagramDestination()),
		IPSocket(localDestination->GetService(), localEndpoint),
		Identity (to), SendEndpoint(endpoint),
		LastActivity(i2p::util::GetMillisecondsSinceEpoch()),
		LocalPort(ourPort),
		RemotePort(theirPort)
	{
		IPSocket.set_option (boost::asio::socket_base::receive_buffer_size (I2P_UDP_MAX_MTU ));
		Receive();
	}

	void UDPSession::Receive()
	{
		LogPrint(eLogDebug, "UDPSession: Receive");
		IPSocket.async_receive_from(boost::asio::buffer(m_Buffer, I2P_UDP_MAX_MTU),
			FromEndpoint, std::bind(&UDPSession::HandleReceived, this, std::placeholders::_1, std::placeholders::_2));
	}

	void UDPSession::HandleReceived(const boost::system::error_code & ecode, std::size_t len)
	{
		if(!ecode)
		{
			LogPrint(eLogDebug, "UDPSession: Forward ", len, "B from ", FromEndpoint);
			auto ts = i2p::util::GetMillisecondsSinceEpoch();
			auto session = m_Destination->GetSession (Identity);
			if (ts > LastActivity + I2P_UDP_REPLIABLE_DATAGRAM_INTERVAL)
				m_Destination->SendDatagram(session, m_Buffer, len, LocalPort, RemotePort);
			else
				m_Destination->SendRawDatagram(session, m_Buffer, len, LocalPort, RemotePort);
			size_t numPackets = 0;
			while (numPackets < i2p::datagram::DATAGRAM_SEND_QUEUE_MAX_SIZE)
			{
				boost::system::error_code ec;
				size_t moreBytes = IPSocket.available(ec);
				if (ec || !moreBytes) break;
				len = IPSocket.receive_from (boost::asio::buffer (m_Buffer, I2P_UDP_MAX_MTU), FromEndpoint, 0, ec);
				m_Destination->SendRawDatagram (session, m_Buffer, len, LocalPort, RemotePort);
				numPackets++;
			}
			if (numPackets > 0)
				LogPrint(eLogDebug, "UDPSession: Forward more ", numPackets, "packets B from ", FromEndpoint);
			m_Destination->FlushSendQueue (session);
			LastActivity = ts;
			Receive();
		}
		else
			LogPrint(eLogError, "UDPSession: ", ecode.message());
	}

	I2PUDPServerTunnel::I2PUDPServerTunnel (const std::string & name, std::shared_ptr<i2p::client::ClientDestination> localDestination,
		const boost::asio::ip::address& localAddress, const boost::asio::ip::udp::endpoint& forwardTo, uint16_t inPort, bool gzip) :
		m_IsUniqueLocal (true), m_Name (name), m_LocalAddress (localAddress),
		m_RemoteEndpoint (forwardTo), m_LocalDest (localDestination), m_inPort(inPort), m_Gzip (gzip)
	{
	}

	I2PUDPServerTunnel::~I2PUDPServerTunnel ()
	{
		Stop ();
	}

	void I2PUDPServerTunnel::Start ()
	{
		m_LocalDest->Start ();

		auto dgram = m_LocalDest->CreateDatagramDestination (m_Gzip);
		dgram->SetReceiver (
			std::bind (&I2PUDPServerTunnel::HandleRecvFromI2P, this, std::placeholders::_1, std::placeholders::_2, std::placeholders::_3, std::placeholders::_4, std::placeholders::_5),
			m_inPort
		);
		dgram->SetRawReceiver (
			std::bind (&I2PUDPServerTunnel::HandleRecvFromI2PRaw, this, std::placeholders::_1, std::placeholders::_2, std::placeholders::_3, std::placeholders::_4),
			m_inPort
		);
	}

	void I2PUDPServerTunnel::Stop ()
	{
		auto dgram = m_LocalDest->GetDatagramDestination ();
		if (dgram) {
			dgram->ResetReceiver (m_inPort);
			dgram->ResetRawReceiver (m_inPort);
		}
	}

	std::vector<std::shared_ptr<DatagramSessionInfo> > I2PUDPServerTunnel::GetSessions ()
	{
		std::vector<std::shared_ptr<DatagramSessionInfo> > sessions;
		std::lock_guard<std::mutex> lock (m_SessionsMutex);

		for (auto it: m_Sessions)
		{
			auto s = it.second;
			if (!s->m_Destination) continue;
			auto info = s->m_Destination->GetInfoForRemote (s->Identity);
			if (!info) continue;

			auto sinfo = std::make_shared<DatagramSessionInfo> ();
			sinfo->Name = m_Name;
			sinfo->LocalIdent = std::make_shared<i2p::data::IdentHash> (m_LocalDest->GetIdentHash ().data ());
			sinfo->RemoteIdent = std::make_shared<i2p::data::IdentHash> (s->Identity.data ());
			sinfo->CurrentIBGW = info->IBGW;
			sinfo->CurrentOBEP = info->OBEP;
			sessions.push_back (sinfo);
		}
		return sessions;
	}

	I2PUDPClientTunnel::I2PUDPClientTunnel (const std::string & name, const std::string &remoteDest,
		const boost::asio::ip::udp::endpoint& localEndpoint,
		std::shared_ptr<i2p::client::ClientDestination> localDestination,
		uint16_t remotePort, bool gzip) :
		m_Name (name), m_RemoteDest (remoteDest), m_LocalDest (localDestination), m_LocalEndpoint (localEndpoint),
		m_ResolveThread (nullptr), m_LocalSocket (nullptr), RemotePort (remotePort),
		m_LastPort (0), m_cancel_resolve (false), m_Gzip (gzip)
	{
	}

	I2PUDPClientTunnel::~I2PUDPClientTunnel ()
	{
		Stop ();
	}

	void I2PUDPClientTunnel::Start ()
	{
		// Reset flag in case of tunnel reload
		if (m_cancel_resolve) m_cancel_resolve = false;

		m_LocalSocket.reset (new boost::asio::ip::udp::socket (m_LocalDest->GetService (), m_LocalEndpoint));
		m_LocalSocket->set_option (boost::asio::socket_base::receive_buffer_size (I2P_UDP_MAX_MTU));
		m_LocalSocket->set_option (boost::asio::socket_base::reuse_address (true));

		auto dgram = m_LocalDest->CreateDatagramDestination (m_Gzip);
		dgram->SetReceiver (std::bind (&I2PUDPClientTunnel::HandleRecvFromI2P, this,
			std::placeholders::_1, std::placeholders::_2,
			std::placeholders::_3, std::placeholders::_4,
			std::placeholders::_5),
			RemotePort
		);
		dgram->SetRawReceiver (std::bind (&I2PUDPClientTunnel::HandleRecvFromI2PRaw, this,
			std::placeholders::_1, std::placeholders::_2, std::placeholders::_3, std::placeholders::_4),
			RemotePort
		);

		m_LocalDest->Start ();
		if (m_ResolveThread == nullptr)
			m_ResolveThread = new std::thread (std::bind (&I2PUDPClientTunnel::TryResolving, this));
		RecvFromLocal ();
	}

	void I2PUDPClientTunnel::Stop ()
	{
		auto dgram = m_LocalDest->GetDatagramDestination ();
		if (dgram) {
			dgram->ResetReceiver (RemotePort);
			dgram->ResetRawReceiver (RemotePort);
		}
		m_cancel_resolve = true;

		m_Sessions.clear();

		if(m_LocalSocket && m_LocalSocket->is_open ())
			m_LocalSocket->close ();

		if(m_ResolveThread)
		{
			m_ResolveThread->join ();
			delete m_ResolveThread;
			m_ResolveThread = nullptr;
		}
		m_RemoteAddr = nullptr;
	}

	void I2PUDPClientTunnel::RecvFromLocal ()
	{
		m_LocalSocket->async_receive_from (boost::asio::buffer (m_RecvBuff, I2P_UDP_MAX_MTU),
			m_RecvEndpoint, std::bind (&I2PUDPClientTunnel::HandleRecvFromLocal, this, std::placeholders::_1, std::placeholders::_2));
	}

	void I2PUDPClientTunnel::HandleRecvFromLocal (const boost::system::error_code & ec, std::size_t transferred)
	{
		if (m_cancel_resolve) {
			LogPrint (eLogDebug, "UDP Client: Ignoring incoming data: stopping");
			return;
		}
		if (ec) {
			LogPrint (eLogError, "UDP Client: Reading from socket error: ", ec.message (), ". Restarting listener...");
			RecvFromLocal (); // Restart listener and continue work
			return;
		}
		if (!m_RemoteAddr || !m_RemoteAddr->IsIdentHash ())  // TODO: handle B33
		{
			LogPrint (eLogWarning, "UDP Client: Remote endpoint not resolved yet");
			RecvFromLocal ();
			return; // drop, remote not resolved
		}
		auto remotePort = m_RecvEndpoint.port ();
		if (!m_LastPort || m_LastPort != remotePort)
		{
			auto itr = m_Sessions.find (remotePort);
			if (itr != m_Sessions.end ())
				m_LastSession = itr->second;
			else
			{
				m_LastSession = std::make_shared<UDPConvo> (boost::asio::ip::udp::endpoint (m_RecvEndpoint), 0);
				m_Sessions.emplace (remotePort, m_LastSession);
			}
			m_LastPort = remotePort;
		}
		// send off to remote i2p destination
		auto ts = i2p::util::GetMillisecondsSinceEpoch ();
		LogPrint (eLogDebug, "UDP Client: Send ", transferred, " to ", m_RemoteAddr->identHash.ToBase32 (), ":", RemotePort);
		auto session = m_LocalDest->GetDatagramDestination ()->GetSession (m_RemoteAddr->identHash);
		if (ts > m_LastSession->second + I2P_UDP_REPLIABLE_DATAGRAM_INTERVAL)
			m_LocalDest->GetDatagramDestination ()->SendDatagram (session, m_RecvBuff, transferred, remotePort, RemotePort);
		else
			m_LocalDest->GetDatagramDestination ()->SendRawDatagram (session, m_RecvBuff, transferred, remotePort, RemotePort);
		size_t numPackets = 0;
		while (numPackets < i2p::datagram::DATAGRAM_SEND_QUEUE_MAX_SIZE)
		{
			boost::system::error_code ec;
			size_t moreBytes = m_LocalSocket->available (ec);
			if (ec || !moreBytes) break;
			transferred = m_LocalSocket->receive_from (boost::asio::buffer (m_RecvBuff, I2P_UDP_MAX_MTU), m_RecvEndpoint, 0, ec);
			remotePort = m_RecvEndpoint.port ();
			// TODO: check remotePort
			m_LocalDest->GetDatagramDestination ()->SendRawDatagram (session, m_RecvBuff, transferred, remotePort, RemotePort);
			numPackets++;
		}
		if (numPackets)
			LogPrint (eLogDebug, "UDP Client: Sent ", numPackets, " more packets to ", m_RemoteAddr->identHash.ToBase32 ());
		m_LocalDest->GetDatagramDestination ()->FlushSendQueue (session);

		// mark convo as active
		if (m_LastSession)
			m_LastSession->second = ts;
		RecvFromLocal ();
	}

	std::vector<std::shared_ptr<DatagramSessionInfo> > I2PUDPClientTunnel::GetSessions ()
	{
		// TODO: implement
		std::vector<std::shared_ptr<DatagramSessionInfo> > infos;
		return infos;
	}

	void I2PUDPClientTunnel::TryResolving ()
	{
		i2p::util::SetThreadName ("UDP Resolver");
		LogPrint (eLogInfo, "UDP Tunnel: Trying to resolve ", m_RemoteDest);

		while (!(m_RemoteAddr = context.GetAddressBook().GetAddress(m_RemoteDest)) && !m_cancel_resolve)
		{
			LogPrint (eLogWarning, "UDP Tunnel: Failed to lookup ", m_RemoteDest);
			std::this_thread::sleep_for (std::chrono::seconds (1));
		}
		if (m_cancel_resolve)
		{
			LogPrint(eLogError, "UDP Tunnel: Lookup of ", m_RemoteDest, " was cancelled");
			return;
		}
		if (!m_RemoteAddr)
		{
			LogPrint (eLogError, "UDP Tunnel: ", m_RemoteDest, " not found");
			return;
		}
		LogPrint(eLogInfo, "UDP Tunnel: Resolved ", m_RemoteDest, " to ", m_RemoteAddr->identHash.ToBase32 ());
	}

	void I2PUDPClientTunnel::HandleRecvFromI2P (const i2p::data::IdentityEx& from, uint16_t fromPort, uint16_t toPort, const uint8_t * buf, size_t len)
	{
		if (m_RemoteAddr && from.GetIdentHash() == m_RemoteAddr->identHash)
			HandleRecvFromI2PRaw (fromPort, toPort, buf, len);
		else
			LogPrint(eLogWarning, "UDP Client: Unwarranted traffic from ", from.GetIdentHash().ToBase32 ());
	}

	void I2PUDPClientTunnel::HandleRecvFromI2PRaw (uint16_t fromPort, uint16_t toPort, const uint8_t * buf, size_t len)
	{
		auto itr = m_Sessions.find (toPort);
		// found convo ?
		if (itr != m_Sessions.end ())
		{
			// found convo
			if (len > 0)
			{
				LogPrint (eLogDebug, "UDP Client: Got ", len, "B from ", m_RemoteAddr ? m_RemoteAddr->identHash.ToBase32 () : "");
				m_LocalSocket->send_to (boost::asio::buffer (buf, len), itr->second->first);
				// mark convo as active
				itr->second->second = i2p::util::GetMillisecondsSinceEpoch ();
			}
		}
		else
			LogPrint (eLogWarning, "UDP Client: Not tracking udp session using port ", (int) toPort);
	}

}
}
