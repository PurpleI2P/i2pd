#ifndef DOTNETTUNNEL_H__
#define DOTNETTUNNEL_H__

#include <inttypes.h>
#include <string>
#include <set>
#include <tuple>
#include <memory>
#include <sstream>
#include <boost/asio.hpp>
#include "Identity.h"
#include "Destination.h"
#include "Datagram.h"
#include "Streaming.h"
#include "DotNetService.h"
#include "AddressBook.h"

namespace dotnet
{
namespace client
{
	const size_t DOTNET_TUNNEL_CONNECTION_BUFFER_SIZE = 65536;
	const int DOTNET_TUNNEL_CONNECTION_MAX_IDLE = 3600; // in seconds
	const int DOTNET_TUNNEL_DESTINATION_REQUEST_TIMEOUT = 10; // in seconds
	// for HTTP tunnels
	const char X_DOTNET_DEST_HASH[] = "X-DOTNET-DestHash"; // hash  in base64
	const char X_DOTNET_DEST_B64[] = "X-DOTNET-DestB64"; // full address in base64
	const char X_DOTNET_DEST_B32[] = "X-DOTNET-DestB32"; // .dot.net address

	class DotNetTunnelConnection: public DotNetServiceHandler, public std::enable_shared_from_this<DotNetTunnelConnection>
	{
		public:
			DotNetTunnelConnection (DotNetService * owner, std::shared_ptr<boost::asio::ip::tcp::socket> socket,
				std::shared_ptr<const dotnet::data::LeaseSet> leaseSet, int port = 0); // to DOTNET
			DotNetTunnelConnection (DotNetService * owner, std::shared_ptr<boost::asio::ip::tcp::socket> socket,
				std::shared_ptr<dotnet::stream::Stream> stream); // to DOTNET using simplified API
			DotNetTunnelConnection (DotNetService * owner, std::shared_ptr<dotnet::stream::Stream> stream,  std::shared_ptr<boost::asio::ip::tcp::socket> socket,
				const boost::asio::ip::tcp::endpoint& target, bool quiet = true); // from DOTNET
			~DotNetTunnelConnection ();
			void DOTNETConnect (const uint8_t * msg = nullptr, size_t len = 0);
			void Connect (bool isUniqueLocal = true);

		protected:
			void Terminate ();

			void Receive ();
			void HandleReceived (const boost::system::error_code& ecode, std::size_t bytes_transferred);
			virtual void Write (const uint8_t * buf, size_t len); // can be overloaded
			void HandleWrite (const boost::system::error_code& ecode);

			void StreamReceive ();
			void HandleStreamReceive (const boost::system::error_code& ecode, std::size_t bytes_transferred);
			void HandleConnect (const boost::system::error_code& ecode);

			std::shared_ptr<const boost::asio::ip::tcp::socket> GetSocket () const { return m_Socket; };

		private:
			uint8_t m_Buffer[DOTNET_TUNNEL_CONNECTION_BUFFER_SIZE], m_StreamBuffer[DOTNET_TUNNEL_CONNECTION_BUFFER_SIZE];
			std::shared_ptr<boost::asio::ip::tcp::socket> m_Socket;
			std::shared_ptr<dotnet::stream::Stream> m_Stream;
			boost::asio::ip::tcp::endpoint m_RemoteEndpoint;
			bool m_IsQuiet; // don't send destination
	};

	class DOTNETClientTunnelConnectionHTTP: public DotNetTunnelConnection
	{
		public:
			DOTNETClientTunnelConnectionHTTP (DotNetService * owner, std::shared_ptr<boost::asio::ip::tcp::socket> socket,
				std::shared_ptr<dotnet::stream::Stream> stream):
				DotNetTunnelConnection (owner, socket, stream), m_HeaderSent (false),
				m_ConnectionSent (false), m_ProxyConnectionSent (false) {};

		protected:
			void Write (const uint8_t * buf, size_t len);

		private:
			std::stringstream m_InHeader, m_OutHeader;
			bool m_HeaderSent, m_ConnectionSent, m_ProxyConnectionSent;
	};

	class DOTNETServerTunnelConnectionHTTP: public DotNetTunnelConnection
	{
		public:
			DOTNETServerTunnelConnectionHTTP (DotNetService * owner, std::shared_ptr<dotnet::stream::Stream> stream,
				std::shared_ptr<boost::asio::ip::tcp::socket> socket,
				const boost::asio::ip::tcp::endpoint& target, const std::string& host);

		protected:
			void Write (const uint8_t * buf, size_t len);

		private:
			std::string m_Host;
			std::stringstream m_InHeader, m_OutHeader;
			bool m_HeaderSent;
			std::shared_ptr<const dotnet::data::IdentityEx> m_From;
	};

	class DotNetTunnelConnectionIRC: public DotNetTunnelConnection
	{
		public:
			DotNetTunnelConnectionIRC (DotNetService * owner, std::shared_ptr<dotnet::stream::Stream> stream,
				std::shared_ptr<boost::asio::ip::tcp::socket> socket,
				const boost::asio::ip::tcp::endpoint& target, const std::string& m_WebircPass);

		protected:
			void Write (const uint8_t * buf, size_t len);

		private:
			std::shared_ptr<const dotnet::data::IdentityEx> m_From;
			std::stringstream m_OutPacket, m_InPacket;
			bool m_NeedsWebIrc;
			std::string m_WebircPass;
	};


	class DOTNETClientTunnel: public TCPIPAcceptor
	{
		protected:
			// Implements TCPIPAcceptor
			std::shared_ptr<DotNetServiceHandler> CreateHandler(std::shared_ptr<boost::asio::ip::tcp::socket> socket);

		public:
			DOTNETClientTunnel (const std::string& name, const std::string& destination,
				const std::string& address, int port, std::shared_ptr<ClientDestination> localDestination, int destinationPort = 0);
			~DOTNETClientTunnel () {}

			void Start ();
			void Stop ();

			const char* GetName() { return m_Name.c_str (); }

		private:
			std::shared_ptr<const Address> GetAddress ();

		private:
			std::string m_Name, m_Destination;
			std::shared_ptr<const Address> m_Address;
			int m_DestinationPort;
	};


	/** 2 minute timeout for udp sessions */
	const uint64_t DOTNET_UDP_SESSION_TIMEOUT = 1000 * 60 * 2;

	/** max size for dotnet udp */
	const size_t DOTNET_UDP_MAX_MTU = dotnet::datagram::MAX_DATAGRAM_SIZE;

	struct UDPSession
	{
		dotnet::datagram::DatagramDestination * m_Destination;
		boost::asio::ip::udp::socket IPSocket;
		dotnet::data::IdentHash Identity;
		boost::asio::ip::udp::endpoint FromEndpoint;
		boost::asio::ip::udp::endpoint SendEndpoint;
		uint64_t LastActivity;

		uint16_t LocalPort;
		uint16_t RemotePort;

		uint8_t m_Buffer[DOTNET_UDP_MAX_MTU];

		UDPSession(boost::asio::ip::udp::endpoint localEndpoint,
							 const std::shared_ptr<dotnet::client::ClientDestination> & localDestination,
							 boost::asio::ip::udp::endpoint remote, const dotnet::data::IdentHash * ident,
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
		std::shared_ptr<const dotnet::data::IdentHash> LocalIdent;
		/** ident hash of remote destination */
		std::shared_ptr<const dotnet::data::IdentHash> RemoteIdent;
		/** ident hash of IBGW in use currently in this session or nullptr if none is set */
		std::shared_ptr<const dotnet::data::IdentHash> CurrentIBGW;
		/** ident hash of OBEP in use for this session or nullptr if none is set */
		std::shared_ptr<const dotnet::data::IdentHash> CurrentOBEP;
		/** dotnet router's udp endpoint */
		boost::asio::ip::udp::endpoint LocalEndpoint;
		/** client's udp endpoint */
		boost::asio::ip::udp::endpoint RemoteEndpoint;
		/** how long has this converstation been idle in ms */
		uint64_t idle;
	};

	typedef std::shared_ptr<UDPSession> UDPSessionPtr;

	/** server side udp tunnel, many dotnet inbound to 1 ip outbound */
	class DOTNETUDPServerTunnel
	{
		public:
			DOTNETUDPServerTunnel(const std::string & name,
				std::shared_ptr<dotnet::client::ClientDestination> localDestination,
				boost::asio::ip::address localAddress,
				boost::asio::ip::udp::endpoint forwardTo, uint16_t port);
			~DOTNETUDPServerTunnel();
			/** expire stale udp conversations */
			void ExpireStale(const uint64_t delta=DOTNET_UDP_SESSION_TIMEOUT);
			void Start();
			const char * GetName() const { return m_Name.c_str(); }
			std::vector<std::shared_ptr<DatagramSessionInfo> > GetSessions();
			std::shared_ptr<ClientDestination> GetLocalDestination () const { return m_LocalDest; }

			void SetUniqueLocal(bool isUniqueLocal = true) { m_IsUniqueLocal = isUniqueLocal; }

		private:
			void HandleRecvFromDOTNET(const dotnet::data::IdentityEx& from, uint16_t fromPort, uint16_t toPort, const uint8_t * buf, size_t len);
			UDPSessionPtr ObtainUDPSession(const dotnet::data::IdentityEx& from, uint16_t localPort, uint16_t remotePort);

		private:
			bool m_IsUniqueLocal;
			const std::string m_Name;
			boost::asio::ip::address m_LocalAddress;
			boost::asio::ip::udp::endpoint m_RemoteEndpoint;
			std::mutex m_SessionsMutex;
			std::vector<UDPSessionPtr> m_Sessions;
			std::shared_ptr<dotnet::client::ClientDestination> m_LocalDest;
	};

	class DOTNETUDPClientTunnel
	{
		public:
			DOTNETUDPClientTunnel(const std::string & name, const std::string &remoteDest,
				boost::asio::ip::udp::endpoint localEndpoint, std::shared_ptr<dotnet::client::ClientDestination> localDestination,
				uint16_t remotePort);
			~DOTNETUDPClientTunnel();
			void Start();
			const char * GetName() const { return m_Name.c_str(); }
			std::vector<std::shared_ptr<DatagramSessionInfo> > GetSessions();

			bool IsLocalDestination(const dotnet::data::IdentHash & destination) const { return destination == m_LocalDest->GetIdentHash(); }

			std::shared_ptr<ClientDestination> GetLocalDestination () const { return m_LocalDest; }
			void ExpireStale(const uint64_t delta=DOTNET_UDP_SESSION_TIMEOUT);

		private:
			typedef std::pair<boost::asio::ip::udp::endpoint, uint64_t> UDPConvo;
			void RecvFromLocal();
			void HandleRecvFromLocal(const boost::system::error_code & e, std::size_t transferred);
			void HandleRecvFromDOTNET(const dotnet::data::IdentityEx& from, uint16_t fromPort, uint16_t toPort, const uint8_t * buf, size_t len);
			void TryResolving();
			const std::string m_Name;
			std::mutex m_SessionsMutex;
			std::map<uint16_t, UDPConvo > m_Sessions; // maps dotnet port -> local udp convo
			const std::string m_RemoteDest;
			std::shared_ptr<dotnet::client::ClientDestination> m_LocalDest;
			const boost::asio::ip::udp::endpoint m_LocalEndpoint;
			dotnet::data::IdentHash * m_RemoteIdent;
			std::thread * m_ResolveThread;
			boost::asio::ip::udp::socket m_LocalSocket;
			boost::asio::ip::udp::endpoint m_RecvEndpoint;
			uint8_t m_RecvBuff[DOTNET_UDP_MAX_MTU];
			uint16_t RemotePort;
			bool m_cancel_resolve;
	};

	class DOTNETServerTunnel: public DotNetService
	{
		public:
			DOTNETServerTunnel (const std::string& name, const std::string& address, int port,
				std::shared_ptr<ClientDestination> localDestination, int inport = 0, bool gzip = true);

			void Start ();
			void Stop ();

			void SetAccessList (const std::set<dotnet::data::IdentHash>& accessList);

			void SetUniqueLocal (bool isUniqueLocal) { m_IsUniqueLocal = isUniqueLocal; }
			bool IsUniqueLocal () const { return m_IsUniqueLocal; }

			const std::string& GetAddress() const { return m_Address; }
			int GetPort () const { return m_Port; };
			uint16_t GetLocalPort () const { return m_PortDestination->GetLocalPort (); };
			const boost::asio::ip::tcp::endpoint& GetEndpoint () const { return m_Endpoint; }

			const char* GetName() { return m_Name.c_str (); }

		private:
			void HandleResolve (const boost::system::error_code& ecode, boost::asio::ip::tcp::resolver::iterator it,
				std::shared_ptr<boost::asio::ip::tcp::resolver> resolver);

			void Accept ();
			void HandleAccept (std::shared_ptr<dotnet::stream::Stream> stream);
			virtual std::shared_ptr<DotNetTunnelConnection> CreateDOTNETConnection (std::shared_ptr<dotnet::stream::Stream> stream);

		private:
			bool m_IsUniqueLocal;
			std::string m_Name, m_Address;
			int m_Port;
			boost::asio::ip::tcp::endpoint m_Endpoint;
			std::shared_ptr<dotnet::stream::StreamingDestination> m_PortDestination;
			std::set<dotnet::data::IdentHash> m_AccessList;
			bool m_IsAccessList;
	};

	class DOTNETServerTunnelHTTP: public DOTNETServerTunnel
	{
		public:
			DOTNETServerTunnelHTTP (const std::string& name, const std::string& address, int port,
				std::shared_ptr<ClientDestination> localDestination, const std::string& host,
				int inport = 0, bool gzip = true);

		private:
			std::shared_ptr<DotNetTunnelConnection> CreateDOTNETConnection (std::shared_ptr<dotnet::stream::Stream> stream);

		private:
			std::string m_Host;
	};

	class DOTNETServerTunnelIRC: public DOTNETServerTunnel
	{
		public:
			DOTNETServerTunnelIRC (const std::string& name, const std::string& address, int port,
				std::shared_ptr<ClientDestination> localDestination, const std::string& webircpass,
				int inport = 0, bool gzip = true);

		private:
			std::shared_ptr<DotNetTunnelConnection> CreateDOTNETConnection (std::shared_ptr<dotnet::stream::Stream> stream);

		private:
			std::string m_WebircPass;
	};
}
}

#endif
