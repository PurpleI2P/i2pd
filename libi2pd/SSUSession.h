#ifndef SSU_SESSION_H__
#define SSU_SESSION_H__

#include <inttypes.h>
#include <set>
#include <memory>
#include "Crypto.h"
#include "I2NPProtocol.h"
#include "TransportSession.h"
#include "SSUData.h"

namespace i2p
{
namespace transport
{
	const uint8_t SSU_HEADER_EXTENDED_OPTIONS_INCLUDED = 0x04;
	struct SSUHeader
	{
		uint8_t mac[16];
		uint8_t iv[16];
		uint8_t flag;
		uint8_t time[4];	

		uint8_t GetPayloadType () const { return flag >> 4; };
		bool IsExtendedOptions () const { return flag & SSU_HEADER_EXTENDED_OPTIONS_INCLUDED; };	
	};

	const int SSU_CONNECT_TIMEOUT = 5; // 5 seconds
	const int SSU_TERMINATION_TIMEOUT = 330; // 5.5 minutes
	const int SSU_CLOCK_SKEW = 60; // in seconds 

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

	// extended options
	const uint16_t EXTENDED_OPTIONS_FLAG_REQUEST_RELAY_TAG = 0x0001;

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
			void Introduce (const i2p::data::RouterInfo::Introducer& introducer, 
				std::shared_ptr<const i2p::data::RouterInfo> to); // Alice to Charlie
			void WaitForIntroduction ();
			void Close ();
			void Done ();
			void Failed ();
			boost::asio::ip::udp::endpoint& GetRemoteEndpoint () { return m_RemoteEndpoint; };
			bool IsV6 () const { return m_RemoteEndpoint.address ().is_v6 (); };
			void SendI2NPMessages (const std::vector<std::shared_ptr<I2NPMessage> >& msgs);
			void SendPeerTest (); // Alice			

			SessionState GetState () const  { return m_State; };
			size_t GetNumSentBytes () const { return m_NumSentBytes; };
			size_t GetNumReceivedBytes () const { return m_NumReceivedBytes; };
			
			void SendKeepAlive ();	
			uint32_t GetRelayTag () const { return m_RelayTag; };	
			const i2p::data::RouterInfo::IntroKey& GetIntroKey () const { return m_IntroKey; };
			uint32_t GetCreationTime () const { return m_CreationTime; };

			void FlushData ();
			
		private:

			boost::asio::io_service& GetService ();
			void CreateAESandMacKey (const uint8_t * pubKey); 
			size_t GetSSUHeaderSize (const uint8_t * buf) const;
			void PostI2NPMessages (std::vector<std::shared_ptr<I2NPMessage> > msgs);
			void ProcessMessage (uint8_t * buf, size_t len, const boost::asio::ip::udp::endpoint& senderEndpoint); // call for established session
			void ProcessSessionRequest (const uint8_t * buf, size_t len, const boost::asio::ip::udp::endpoint& senderEndpoint);
			void SendSessionRequest ();
			void SendRelayRequest (const i2p::data::RouterInfo::Introducer& introducer, uint32_t nonce);
			void ProcessSessionCreated (uint8_t * buf, size_t len);
			void SendSessionCreated (const uint8_t * x, bool sendRelayTag = true);
			void ProcessSessionConfirmed (const uint8_t * buf, size_t len);
			void SendSessionConfirmed (const uint8_t * y, const uint8_t * ourAddress, size_t ourAddressLen);
			void ProcessRelayRequest (const uint8_t * buf, size_t len, const boost::asio::ip::udp::endpoint& from);
			void SendRelayResponse (uint32_t nonce, const boost::asio::ip::udp::endpoint& from,
				const uint8_t * introKey, const boost::asio::ip::udp::endpoint& to);
			void SendRelayIntro (std::shared_ptr<SSUSession> session, const boost::asio::ip::udp::endpoint& from);
			void ProcessRelayResponse (const uint8_t * buf, size_t len);
			void ProcessRelayIntro (const uint8_t * buf, size_t len);
			void Established ();
			void ScheduleConnectTimer ();
			void HandleConnectTimer (const boost::system::error_code& ecode);
			void ProcessPeerTest (const uint8_t * buf, size_t len, const boost::asio::ip::udp::endpoint& senderEndpoint);
			void SendPeerTest (uint32_t nonce, const boost::asio::ip::address& address, uint16_t port, const uint8_t * introKey, bool toAddress = true, bool sendAddress = true); 
			void ProcessData (uint8_t * buf, size_t len);		
			void SendSessionDestroyed ();
			void Send (uint8_t type, const uint8_t * payload, size_t len); // with session key
			void Send (const uint8_t * buf, size_t size); 
			
			void FillHeaderAndEncrypt (uint8_t payloadType, uint8_t * buf, size_t len, const i2p::crypto::AESKey& aesKey, 
				const uint8_t * iv, const i2p::crypto::MACKey& macKey, uint8_t flag = 0);
			void FillHeaderAndEncrypt (uint8_t payloadType, uint8_t * buf, size_t len); // with session key 
			void Decrypt (uint8_t * buf, size_t len, const i2p::crypto::AESKey& aesKey);
			void DecryptSessionKey (uint8_t * buf, size_t len);
			bool Validate (uint8_t * buf, size_t len, const i2p::crypto::MACKey& macKey);			

			void Reset ();
			
		private:
	
			friend class SSUData; // TODO: change in later
			SSUServer& m_Server;
			boost::asio::ip::udp::endpoint m_RemoteEndpoint;
			boost::asio::deadline_timer m_ConnectTimer;
			bool m_IsPeerTest;
			SessionState m_State;
			bool m_IsSessionKey;
			uint32_t m_RelayTag; // received from peer
			uint32_t m_SentRelayTag; // sent by us
			i2p::crypto::CBCEncryption m_SessionKeyEncryption;
			i2p::crypto::CBCDecryption m_SessionKeyDecryption;
			i2p::crypto::AESKey m_SessionKey;
			i2p::crypto::MACKey m_MacKey;
			i2p::data::RouterInfo::IntroKey m_IntroKey;
			uint32_t m_CreationTime; // seconds since epoch
			SSUData m_Data;
			bool m_IsDataReceived;
			std::unique_ptr<SignedData> m_SignedData; // we need it for SessionConfirmed only
			std::map<uint32_t, std::shared_ptr<const i2p::data::RouterInfo> > m_RelayRequests; // nonce->Charlie
	};


}
}

#endif

