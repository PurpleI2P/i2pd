#ifndef SSU_SESSION_H__
#define SSU_SESSION_H__

#include <inttypes.h>
#include <set>
#include <memory>
#include "aes.h"
#include "hmac.h"
#include "I2NPProtocol.h"
#include "TransportSession.h"
#include "SSUData.h"

namespace i2p
{
namespace transport
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
		eSessionStateClosed,
		eSessionStateFailed
	};	

	enum PeerTestParticipant
	{
		ePeerTestParticipantUnknown = 0,
		ePeerTestParticipantAlice1,
		ePeerTestParticipantAlice2,
		ePeerTestParticipantBob,
		ePeerTestParticipantCharlie
	};
	
	class SSUServer;
	class SSUSession: public TransportSession, public std::enable_shared_from_this<SSUSession>
	{
		public:

			SSUSession (SSUServer& server, boost::asio::ip::udp::endpoint& remoteEndpoint,
				std::shared_ptr<const i2p::data::RouterInfo> router = nullptr, bool peerTest = false);
			void ProcessNextMessage (uint8_t * buf, size_t len, const boost::asio::ip::udp::endpoint& senderEndpoint);		
			~SSUSession ();
			
			void Connect ();
			void WaitForConnect ();
			void Introduce (uint32_t iTag, const uint8_t * iKey);
			void WaitForIntroduction ();
			void Close ();
			void Done ();
			boost::asio::ip::udp::endpoint& GetRemoteEndpoint () { return m_RemoteEndpoint; };
			bool IsV6 () const { return m_RemoteEndpoint.address ().is_v6 (); };
			void SendI2NPMessage (I2NPMessage * msg);
			void SendI2NPMessages (const std::vector<I2NPMessage *>& msgs);
			void SendPeerTest (); // Alice			

			SessionState GetState () const  { return m_State; };
			size_t GetNumSentBytes () const { return m_NumSentBytes; };
			size_t GetNumReceivedBytes () const { return m_NumReceivedBytes; };
			
			void SendKeepAlive ();	
			uint32_t GetRelayTag () const { return m_RelayTag; };	
			uint32_t GetCreationTime () const { return m_CreationTime; };

			void FlushData ();
			
		private:

			boost::asio::io_service& GetService ();
			void CreateAESandMacKey (const uint8_t * pubKey); 

			void PostI2NPMessage (I2NPMessage * msg);
			void PostI2NPMessages (std::vector<I2NPMessage *> msgs);
			void ProcessMessage (uint8_t * buf, size_t len, const boost::asio::ip::udp::endpoint& senderEndpoint); // call for established session
			void ProcessSessionRequest (uint8_t * buf, size_t len, const boost::asio::ip::udp::endpoint& senderEndpoint);
			void SendSessionRequest ();
			void SendRelayRequest (uint32_t iTag, const uint8_t * iKey);
			void ProcessSessionCreated (uint8_t * buf, size_t len);
			void SendSessionCreated (const uint8_t * x);
			void ProcessSessionConfirmed (uint8_t * buf, size_t len);
			void SendSessionConfirmed (const uint8_t * y, const uint8_t * ourAddress, size_t ourAddressLen);
			void ProcessRelayRequest (uint8_t * buf, size_t len, const boost::asio::ip::udp::endpoint& from);
			void SendRelayResponse (uint32_t nonce, const boost::asio::ip::udp::endpoint& from,
				const uint8_t * introKey, const boost::asio::ip::udp::endpoint& to);
			void SendRelayIntro (SSUSession * session, const boost::asio::ip::udp::endpoint& from);
			void ProcessRelayResponse (uint8_t * buf, size_t len);
			void ProcessRelayIntro (uint8_t * buf, size_t len);
			void Established ();
			void Failed ();
			void ScheduleConnectTimer ();
			void HandleConnectTimer (const boost::system::error_code& ecode);
			void ProcessPeerTest (uint8_t * buf, size_t len, const boost::asio::ip::udp::endpoint& senderEndpoint);
			void SendPeerTest (uint32_t nonce, uint32_t address, uint16_t port, const uint8_t * introKey, bool toAddress = true, bool sendAddress = true); 
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
			boost::asio::deadline_timer m_Timer;
			bool m_PeerTest;
			SessionState m_State;
			bool m_IsSessionKey;
			uint32_t m_RelayTag;	
			i2p::crypto::CBCEncryption m_SessionKeyEncryption;
			i2p::crypto::CBCDecryption m_SessionKeyDecryption;
			i2p::crypto::AESKey m_SessionKey;
			i2p::crypto::MACKey m_MacKey;
			uint32_t m_CreationTime; // seconds since epoch
			SSUData m_Data;
			bool m_IsDataReceived;
	};


}
}

#endif

