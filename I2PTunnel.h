#ifndef I2PTUNNEL_H__
#define I2PTUNNEL_H__

#include <inttypes.h>
#include <string>
#include <set>
#include <memory>
#include <sstream>
#include <boost/asio.hpp>
#include "Identity.h"
#include "Destination.h"
#include "Streaming.h"
#include "I2PService.h"

namespace i2p
{
namespace client
{
	const size_t I2P_TUNNEL_CONNECTION_BUFFER_SIZE = 8192;
	const int I2P_TUNNEL_CONNECTION_MAX_IDLE = 3600; // in seconds	
	const int I2P_TUNNEL_DESTINATION_REQUEST_TIMEOUT = 10; // in seconds
	// for HTTP tunnels		
	const char X_I2P_DEST_HASH[] = "X-I2P-DestHash"; // hash  in base64
	const char X_I2P_DEST_B64[] = "X-I2P-DestB64"; // full address in base64
	const char X_I2P_DEST_B32[] = "X-I2P-DestB32"; // .b32.i2p address

	class I2PTunnelConnection: public I2PServiceHandler, public std::enable_shared_from_this<I2PTunnelConnection>
	{
		public:

			I2PTunnelConnection (I2PService * owner, std::shared_ptr<boost::asio::ip::tcp::socket> socket,
				std::shared_ptr<const i2p::data::LeaseSet> leaseSet, int port = 0); // to I2P
			I2PTunnelConnection (I2PService * owner, std::shared_ptr<boost::asio::ip::tcp::socket> socket,
				std::shared_ptr<i2p::stream::Stream> stream); // to I2P using simplified API 
			I2PTunnelConnection (I2PService * owner, std::shared_ptr<i2p::stream::Stream> stream,  std::shared_ptr<boost::asio::ip::tcp::socket> socket, 
				const boost::asio::ip::tcp::endpoint& target, bool quiet = true); // from I2P
			~I2PTunnelConnection ();
			void I2PConnect (const uint8_t * msg = nullptr, size_t len = 0);
			void Connect ();
			
		protected:

			void Terminate ();	

			void Receive ();
			void HandleReceived (const boost::system::error_code& ecode, std::size_t bytes_transferred);	
			virtual void Write (const uint8_t * buf, size_t len); // can be overloaded
			void HandleWrite (const boost::system::error_code& ecode);	

			void StreamReceive ();
			void HandleStreamReceive (const boost::system::error_code& ecode, std::size_t bytes_transferred);
			void HandleConnect (const boost::system::error_code& ecode);

		private:

			uint8_t m_Buffer[I2P_TUNNEL_CONNECTION_BUFFER_SIZE], m_StreamBuffer[I2P_TUNNEL_CONNECTION_BUFFER_SIZE];
			std::shared_ptr<boost::asio::ip::tcp::socket> m_Socket;
			std::shared_ptr<i2p::stream::Stream> m_Stream;
			boost::asio::ip::tcp::endpoint m_RemoteEndpoint;
			bool m_IsQuiet; // don't send destination
	};

	class I2PTunnelConnectionHTTP: public I2PTunnelConnection
	{
		public:
			
			I2PTunnelConnectionHTTP (I2PService * owner, std::shared_ptr<i2p::stream::Stream> stream,
				std::shared_ptr<boost::asio::ip::tcp::socket> socket, 
				const boost::asio::ip::tcp::endpoint& target, const std::string& host); 

		protected:

			void Write (const uint8_t * buf, size_t len);

		private:
		
			std::string m_Host;
			std::stringstream m_InHeader, m_OutHeader;
			bool m_HeaderSent;
			std::shared_ptr<const i2p::data::IdentityEx> m_From;
	};

	class I2PTunnelConnectionIRC: public I2PTunnelConnection
    {
        public:
                
            I2PTunnelConnectionIRC (I2PService * owner, std::shared_ptr<i2p::stream::Stream> stream,
                std::shared_ptr<boost::asio::ip::tcp::socket> socket, 
                const boost::asio::ip::tcp::endpoint& target, const std::string& host); 

        protected:

            void Write (const uint8_t * buf, size_t len);

        private:
                
            std::string m_Host;
            std::shared_ptr<const i2p::data::IdentityEx> m_From;
            std::stringstream m_OutPacket, m_InPacket;
    };


	class I2PClientTunnel: public TCPIPAcceptor
	{
		protected:

			// Implements TCPIPAcceptor
			std::shared_ptr<I2PServiceHandler> CreateHandler(std::shared_ptr<boost::asio::ip::tcp::socket> socket);

		public:

			I2PClientTunnel (const std::string& name, const std::string& destination, 
				const std::string& address, int port, std::shared_ptr<ClientDestination> localDestination, int destinationPort = 0);
			~I2PClientTunnel () {}
	
			void Start ();
			void Stop ();

			const char* GetName() { return m_Name.c_str (); }	
			
		private:

			const i2p::data::IdentHash * GetIdentHash ();

		private:
			
			std::string m_Name, m_Destination;
			const i2p::data::IdentHash * m_DestinationIdentHash;
			int m_DestinationPort;	
	};	

	class I2PServerTunnel: public I2PService
	{
		public:

			I2PServerTunnel (const std::string& name, const std::string& address, int port, 
				std::shared_ptr<ClientDestination> localDestination, int inport = 0);	

			void Start ();
			void Stop ();

			void SetAccessList (const std::set<i2p::data::IdentHash>& accessList); 

			const std::string& GetAddress() const { return m_Address; }
			int GetPort () const { return m_Port; };
			uint16_t GetLocalPort () const { return m_PortDestination->GetLocalPort (); };
			const boost::asio::ip::tcp::endpoint& GetEndpoint () const { return m_Endpoint; }

			const char* GetName() { return m_Name.c_str (); }	
			
		private:

			void HandleResolve (const boost::system::error_code& ecode, boost::asio::ip::tcp::resolver::iterator it, 
				std::shared_ptr<boost::asio::ip::tcp::resolver> resolver);

			void Accept ();
			void HandleAccept (std::shared_ptr<i2p::stream::Stream> stream);
			virtual void CreateI2PConnection (std::shared_ptr<i2p::stream::Stream> stream);

		private:

			std::string m_Name, m_Address;
			int m_Port;
			boost::asio::ip::tcp::endpoint m_Endpoint;	
			std::shared_ptr<i2p::stream::StreamingDestination> m_PortDestination;
			std::set<i2p::data::IdentHash> m_AccessList;
			bool m_IsAccessList;			
	};

	class I2PServerTunnelHTTP: public I2PServerTunnel
	{
		public:

			I2PServerTunnelHTTP (const std::string& name, const std::string& address, int port, 
				std::shared_ptr<ClientDestination> localDestination, const std::string& host,
			    int inport = 0);	

		private:

			void CreateI2PConnection (std::shared_ptr<i2p::stream::Stream> stream);

		private:

			std::string m_Host;
	};
	
    class I2PServerTunnelIRC: public I2PServerTunnel
    {
        public:

            I2PServerTunnelIRC (const std::string& name, const std::string& address, int port, 
                std::shared_ptr<ClientDestination> localDestination, int inport = 0);   

        private:

            void CreateI2PConnection (std::shared_ptr<i2p::stream::Stream> stream); 
    };

}
}	

#endif
