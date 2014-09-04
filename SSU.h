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
#include "SSUData.h"

namespace i2p
{
namespace ssu
{
#pragma pack(1)
	struct SSUHeader
	{
		uint8_t mac[16];
		uint8_t iv[16];
		uint8_t flag;
		uint32_t time;	

		uint8_t GetPayloadType () const { return flag >> 4; };
	};
#pragma pack()

	const int SSU_CONNECT_TIMEOUT = 5; // 5 seconds
	const int SSU_TERMINATION_TIMEOUT = 330; // 5.5 minutes

	// payload types (4 bits)
	const uint8_t PAYLOAD_TYPE_SESSION_REQUEST = 0;
	const uint8_t PAYLOAD_TYPE_SESSION_CREATED = 1;
	const uint8_t PAYLOAD_TYPE_SESSION_CONFIRMED = 2;
	const uint8_t PAYLOAD_TYPE_RELAY_REQUEST = 3;
	const uint8_t PAYLOAD_TYPE_RELAY_RESPONSE = 4;
	const uint8_t PAYLOAD_TYPE_RELAY_INTRO = 5;
	const uint8_t PAYLOAD_TYPE_DATA = 6;
	const uint8_t PAYLOAD_TYPE_PEER_TEST = 7;
	const uint8_t PAYLOAD_TYPE_SESSION_DESTROYED = 8;

	enum SessionState
	{
		eSessionStateUnknown,	
		eSessionStateIntroduced,
		eSessionStateEstablished,
		eSessionStateFailed
	};	

	class SSUServer;
	class SSUSession
	{
		public:

			SSUSession (SSUServer& server, boost::asio::ip::udp::endpoint& remoteEndpoint,
				const i2p::data::RouterInfo * router = nullptr, bool peerTest = false);
			void ProcessNextMessage (uint8_t * buf, size_t len, const boost::asio::ip::udp::endpoint& senderEndpoint);		
			~SSUSession ();
			
			void Connect ();
			void Introduce (uint32_t iTag, const uint8_t * iKey);
			void WaitForIntroduction ();
			void Close ();
			boost::asio::ip::udp::endpoint& GetRemoteEndpoint () { return m_RemoteEndpoint; };
			const i2p::data::RouterInfo * GetRemoteRouter () const  { return m_RemoteRouter; };
			void SendI2NPMessage (I2NPMessage * msg);
			void SendPeerTest (); // Alice			

			SessionState GetState () const  { return m_State; };
			size_t GetNumSentBytes () const { return m_NumSentBytes; };
			size_t GetNumReceivedBytes () const { return m_NumReceivedBytes; };
			
			
		private:

			void CreateAESandMacKey (const uint8_t * pubKey); 

			void PostI2NPMessage (I2NPMessage * msg);
			void ProcessMessage (uint8_t * buf, size_t len, const boost::asio::ip::udp::endpoint& senderEndpoint); // call for established session
			void ProcessSessionRequest (uint8_t * buf, size_t len, const boost::asio::ip::udp::endpoint& senderEndpoint);
			void SendSessionRequest ();
			void SendRelayRequest (uint32_t iTag, const uint8_t * iKey);
			void ProcessSessionCreated (uint8_t * buf, size_t len);
			void SendSessionCreated (const uint8_t * x);
			void ProcessSessionConfirmed (uint8_t * buf, size_t len);
			void SendSessionConfirmed (const uint8_t * y, const uint8_t * ourAddress);
			void ProcessRelayRequest (uint8_t * buf, size_t len);
			void SendRelayResponse (uint32_t nonce, const boost::asio::ip::udp::endpoint& from, const uint8_t * introKey, const boost::asio::ip::udp::endpoint& to);
			void SendRelayIntro (SSUSession * session, const boost::asio::ip::udp::endpoint& from);
			void ProcessRelayResponse (uint8_t * buf, size_t len);
			void ProcessRelayIntro (uint8_t * buf, size_t len);
			void Established ();
			void Failed ();
			void ScheduleConnectTimer ();
			void HandleConnectTimer (const boost::system::error_code& ecode);
			void ProcessPeerTest (uint8_t * buf, size_t len, const boost::asio::ip::udp::endpoint& senderEndpoint);
			void SendPeerTest (uint32_t nonce, uint32_t address, uint16_t port, uint8_t * introKey, bool toAddress = true); 
			void ProcessData (uint8_t * buf, size_t len);		
			void SendSesionDestroyed ();
			void Send (uint8_t type, const uint8_t * payload, size_t len); // with session key
			void Send (const uint8_t * buf, size_t size); 
			
			void FillHeaderAndEncrypt (uint8_t payloadType, uint8_t * buf, size_t len, const uint8_t * aesKey, const uint8_t * iv, const uint8_t * macKey);
			void FillHeaderAndEncrypt (uint8_t payloadType, uint8_t * buf, size_t len); // with session key 
			void Decrypt (uint8_t * buf, size_t len, const uint8_t * aesKey);
			void DecryptSessionKey (uint8_t * buf, size_t len);
			bool Validate (uint8_t * buf, size_t len, const uint8_t * macKey);			
			const uint8_t * GetIntroKey () const; 

			void ScheduleTermination ();
			void HandleTerminationTimer (const boost::system::error_code& ecode);
			
		private:
	
			friend class SSUData; // TODO: change in later
			SSUServer& m_Server;
			boost::asio::ip::udp::endpoint m_RemoteEndpoint;
			const i2p::data::RouterInfo * m_RemoteRouter;
			boost::asio::deadline_timer m_Timer;
			i2p::data::DHKeysPair * m_DHKeysPair; // X - for client and Y - for server
			bool m_PeerTest;
			SessionState m_State;
			bool m_IsSessionKey;
			uint32_t m_RelayTag;	
			std::set<uint32_t> m_PeerTestNonces;
			i2p::crypto::CBCEncryption m_SessionKeyEncryption;
			i2p::crypto::CBCDecryption m_SessionKeyDecryption;
			uint8_t m_SessionKey[32], m_MacKey[32];
			std::list<i2p::I2NPMessage *> m_DelayedMessages;
			SSUData m_Data;
			size_t m_NumSentBytes, m_NumReceivedBytes;
	};

	class SSUServer
	{
		public:

			SSUServer (int port);
			~SSUServer ();
			void Start ();
			void Stop ();
			SSUSession * GetSession (const i2p::data::RouterInfo * router, bool peerTest = false);
			SSUSession * FindSession (const i2p::data::RouterInfo * router);
			SSUSession * FindSession (const boost::asio::ip::udp::endpoint& e);
			SSUSession * GetRandomEstablishedSession ();
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
			void HandleReceivedFrom (const boost::system::error_code& ecode, std::size_t bytes_transferred);

			template<typename Filter>
			SSUSession * GetRandomSession (Filter filter);

		private:

			bool m_IsRunning;
			std::thread * m_Thread;	
			boost::asio::io_service m_Service;
			boost::asio::io_service::work m_Work;
			boost::asio::ip::udp::endpoint m_Endpoint;
			boost::asio::ip::udp::socket m_Socket;
			boost::asio::ip::udp::endpoint m_SenderEndpoint;
			uint8_t m_ReceiveBuffer[2*SSU_MTU];
			std::map<boost::asio::ip::udp::endpoint, SSUSession *> m_Sessions;
			std::map<uint32_t, boost::asio::ip::udp::endpoint> m_Relays; // we are introducer

		public:
			// for HTTP only
			const decltype(m_Sessions)& GetSessions () const { return m_Sessions; };
	};
}
}

#endif

