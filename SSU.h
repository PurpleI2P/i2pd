#ifndef SSU_H__
#define SSU_H__

#include <inttypes.h>
#include <string.h>
#include <map>
#include <list>
#include <set>
#include <thread>
#include <boost/asio.hpp>
#include "aes.h"
#include "I2PEndian.h"
#include "Identity.h"
#include "RouterInfo.h"
#include "I2NPProtocol.h"
#include "SSUSession.h"

namespace i2p
{
namespace transport
{
	const int SSU_KEEP_ALIVE_INTERVAL = 30; // 30 seconds	
	const int SSU_TO_INTRODUCER_SESSION_DURATION = 3600; // 1 hour
	const size_t SSU_MAX_NUM_INTRODUCERS = 3;
	
	class SSUServer
	{
		public:

			SSUServer (int port);
			~SSUServer ();
			void Start ();
			void Stop ();
			SSUSession * GetSession (std::shared_ptr<const i2p::data::RouterInfo> router, bool peerTest = false);
			SSUSession * FindSession (const i2p::data::RouterInfo * router) const;
			SSUSession * FindSession (const boost::asio::ip::udp::endpoint& e) const;
			SSUSession * GetRandomEstablishedSession (const SSUSession * excluded);
			void DeleteSession (SSUSession * session);
			void DeleteAllSessions ();			

			boost::asio::io_service& GetService () { return m_Socket.get_io_service(); };
			const boost::asio::ip::udp::endpoint& GetEndpoint () const { return m_Endpoint; };			
			void Send (const uint8_t * buf, size_t len, const boost::asio::ip::udp::endpoint& to);
			void AddRelay (uint32_t tag, const boost::asio::ip::udp::endpoint& relay);
			SSUSession * FindRelaySession (uint32_t tag);

		private:

			void Run ();
			void Receive ();
			void ReceiveV6 ();
			void HandleReceivedFrom (const boost::system::error_code& ecode, std::size_t bytes_transferred);
			void HandleReceivedFromV6 (const boost::system::error_code& ecode, std::size_t bytes_transferred);
			void HandleReceivedBuffer (boost::asio::ip::udp::endpoint& from, uint8_t * buf, std::size_t bytes_transferred);

			template<typename Filter>
			SSUSession * GetRandomSession (Filter filter);
			
			std::set<SSUSession *> FindIntroducers (int maxNumIntroducers);	
			void ScheduleIntroducersUpdateTimer ();
			void HandleIntroducersUpdateTimer (const boost::system::error_code& ecode);
			
		private:

			bool m_IsRunning;
			std::thread * m_Thread;	
			boost::asio::io_service m_Service;
			boost::asio::io_service::work m_Work;
			boost::asio::ip::udp::endpoint m_Endpoint, m_EndpointV6;
			boost::asio::ip::udp::socket m_Socket, m_SocketV6;
			boost::asio::ip::udp::endpoint m_SenderEndpoint, m_SenderEndpointV6;
			boost::asio::deadline_timer m_IntroducersUpdateTimer;
			std::list<boost::asio::ip::udp::endpoint> m_Introducers; // introducers we are connected to
			i2p::crypto::AESAlignedBuffer<2*SSU_MTU_V4> m_ReceiveBuffer;
			i2p::crypto::AESAlignedBuffer<2*SSU_MTU_V6> m_ReceiveBufferV6; 
			std::map<boost::asio::ip::udp::endpoint, SSUSession *> m_Sessions;
			std::map<uint32_t, boost::asio::ip::udp::endpoint> m_Relays; // we are introducer

		public:
			// for HTTP only
			const decltype(m_Sessions)& GetSessions () const { return m_Sessions; };
	};
}
}

#endif

