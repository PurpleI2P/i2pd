/*
* Copyright (c) 2022, The PurpleI2P Project
*
* This file is part of Purple i2pd project and licensed under BSD3
*
* See full license text in LICENSE file at top of project tree
*/

#ifndef SSU2_SESSION_H__
#define SSU2_SESSION_H__

#include <memory>
#include <functional>
#include <map>
#include <set>
#include <list>
#include <boost/asio.hpp>
#include "Crypto.h"
#include "RouterInfo.h"
#include "TransportSession.h"

namespace i2p
{
namespace transport
{
	const int SSU2_CONNECT_TIMEOUT = 5; // 5 seconds
	const int SSU2_TERMINATION_TIMEOUT = 330; // 5.5 minutes
	const int SSU2_TOKEN_EXPIRATION_TIMEOUT = 9; // in seconds
	const int SSU2_RELAY_NONCE_EXPIRATION_TIMEOUT = 10; // in seconds
	const int SSU2_PEER_TEST_EXPIRATION_TIMEOUT = 60; // 60 seconds
	const size_t SSU2_MTU = 1488;
	const size_t SSU2_MAX_PAYLOAD_SIZE = SSU2_MTU - 32;
	const int SSU2_RESEND_INTERVAL = 3; // in seconds
	const int SSU2_MAX_NUM_RESENDS = 5;
	const int SSU2_INCOMPLETE_MESSAGES_CLEANUP_TIMEOUT = 30; // in seconds
	const size_t SSU2_MAX_WINDOW_SIZE = 128; // in packets
	const int SSU2_MAX_NUM_ACK_RANGES = 32; // to send

	enum SSU2MessageType
	{
		eSSU2SessionRequest = 0,
		eSSU2SessionCreated = 1,
		eSSU2SessionConfirmed = 2,
		eSSU2Data = 6,
		eSSU2PeerTest = 7,
		eSSU2Retry = 9,
		eSSU2TokenRequest = 10,
		eSSU2HolePunch = 11
	};

	enum SSU2BlockType
	{
		eSSU2BlkDateTime = 0,
		eSSU2BlkOptions, // 1
		eSSU2BlkRouterInfo, // 2
		eSSU2BlkI2NPMessage, // 3
		eSSU2BlkFirstFragment, // 4
		eSSU2BlkFollowOnFragment, // 5
		eSSU2BlkTermination, // 6
		eSSU2BlkRelayRequest, // 7
		eSSU2BlkRelayResponse, // 8
		eSSU2BlkRelayIntro, // 9
		eSSU2BlkPeerTest, // 10
		eSSU2BlkNextNonce, // 11
		eSSU2BlkAck, // 12
		eSSU2BlkAddress, // 13
		eSSU2BlkIntroKey, // 14
		eSSU2BlkRelayTagRequest, // 15
		eSSU2BlkRelayTag, // 16
		eSSU2BlkNewToken, // 17
		eSSU2BlkPathChallenge, // 18
		eSSU2BlkPathResponse, // 19
		eSSU2BlkFirstPacketNumber, // 20
		eSSU2BlkPadding = 254
	};

	enum SSU2SessionState
	{
		eSSU2SessionStateUnknown,
		eSSU2SessionStateIntroduced,
		eSSU2SessionStatePeerTest,
		eSSU2SessionStateEstablished,
		eSSU2SessionStateTerminated,
		eSSU2SessionStateFailed
	};

	enum SSU2PeerTestCode
	{
		eSSU2PeerTestCodeAccept = 0,
		eSSU2PeerTestCodeBobReasonUnspecified = 1,
		eSSU2PeerTestCodeBobNoCharlieAvailable = 2,
		eSSU2PeerTestCodeBobLimitExceeded = 3,
		eSSU2PeerTestCodeBobSignatureFailure = 4,
		eSSU2PeerTestCodeCharlieReasonUnspecified = 64,
		eSSU2PeerTestCodeCharlieUnsupportedAddress = 65,
		eSSU2PeerTestCodeCharlieLimitExceeded = 66,
		eSSU2PeerTestCodeCharlieSignatureFailure = 67,
		eSSU2PeerTestCodeCharlieAliceIsAlreadyConnected = 68,
		eSSU2PeerTestCodeCharlieAliceIsBanned = 69,
		eSSU2PeerTestCodeCharlieAliceIsUnknown = 70,
		eSSU2PeerTestCodeUnspecified = 128
	};	

	struct SSU2IncompleteMessage
	{
		struct Fragment
		{
			uint8_t buf[SSU2_MTU];
			size_t len;
			bool isLast;
		};

		std::shared_ptr<I2NPMessage> msg;
		int nextFragmentNum;
		uint32_t lastFragmentInsertTime; // in seconds
		std::map<int, std::shared_ptr<Fragment> > outOfSequenceFragments;
	};

	// RouterInfo flags
	const uint8_t SSU2_ROUTER_INFO_FLAG_REQUEST_FLOOD = 0x01;
	const uint8_t SSU2_ROUTER_INFO_FLAG_GZIP = 0x02;

	class SSU2Server;
	class SSU2Session: public TransportSession, public std::enable_shared_from_this<SSU2Session>
	{
		union Header
		{
			uint64_t ll[2];
			uint8_t buf[16];
			struct
			{
				uint64_t connID;
				uint32_t packetNum;
				uint8_t type;
				uint8_t flags[3];
			} h;
		};

		struct SentPacket
		{
			uint8_t payload[SSU2_MAX_PAYLOAD_SIZE];
			size_t payloadSize = 0;
			uint32_t nextResendTime; // in seconds
			int numResends = 0;
		};

		struct SessionConfirmedFragment
		{
			Header header;
			uint8_t payload[SSU2_MAX_PAYLOAD_SIZE];
			size_t payloadSize;
		};

		typedef std::function<void ()> OnEstablished;

		public:

			SSU2Session (SSU2Server& server, std::shared_ptr<const i2p::data::RouterInfo> in_RemoteRouter = nullptr,
				std::shared_ptr<const i2p::data::RouterInfo::Address> addr = nullptr);
			~SSU2Session ();

			void SetRemoteEndpoint (const boost::asio::ip::udp::endpoint& ep) { m_RemoteEndpoint = ep; };
			const boost::asio::ip::udp::endpoint& GetRemoteEndpoint () const { return m_RemoteEndpoint; };
			i2p::data::RouterInfo::CompatibleTransports GetRemoteTransports () const { return m_RemoteTransports; };
			std::shared_ptr<const i2p::data::RouterInfo::Address> GetAddress () const { return m_Address; };
			void SetOnEstablished (OnEstablished e) { m_OnEstablished = e; };

			void Connect ();
			bool Introduce (std::shared_ptr<SSU2Session> session, uint32_t relayTag);
			void SendPeerTest (); // Alice, Data message
			void Terminate ();
			void TerminateByTimeout ();
			void CleanUp (uint64_t ts);
			void FlushData ();
			void Done () override;
			void SendI2NPMessages (const std::vector<std::shared_ptr<I2NPMessage> >& msgs) override;
			void Resend (uint64_t ts);
			bool IsEstablished () const { return m_State == eSSU2SessionStateEstablished; };
			uint64_t GetConnID () const { return m_SourceConnID; };
			SSU2SessionState GetState () const { return m_State; };
			void SetState (SSU2SessionState state) { m_State = state; };

			bool ProcessFirstIncomingMessage (uint64_t connID, uint8_t * buf, size_t len);
			bool ProcessSessionCreated (uint8_t * buf, size_t len);
			bool ProcessSessionConfirmed (uint8_t * buf, size_t len);
			bool ProcessRetry (uint8_t * buf, size_t len);
			bool ProcessHolePunch (uint8_t * buf, size_t len);
			bool ProcessPeerTest (uint8_t * buf, size_t len);
			void ProcessData (uint8_t * buf, size_t len);

		private:

			void Established ();
			void PostI2NPMessages (std::vector<std::shared_ptr<I2NPMessage> > msgs);
			bool SendQueue ();
			void SendFragmentedMessage (std::shared_ptr<I2NPMessage> msg);

			void ProcessSessionRequest (Header& header, uint8_t * buf, size_t len);
			void ProcessTokenRequest (Header& header, uint8_t * buf, size_t len);

			void SendSessionRequest (uint64_t token = 0);
			void SendSessionCreated (const uint8_t * X);
			void SendSessionConfirmed (const uint8_t * Y);
			void KDFDataPhase (uint8_t * keydata_ab, uint8_t * keydata_ba);
			void SendTokenRequest ();
			void SendRetry ();
			uint32_t SendData (const uint8_t * buf, size_t len); // returns packet num
			void SendQuickAck ();
			void SendTermination ();
			void SendHolePunch (uint32_t nonce, const boost::asio::ip::udp::endpoint& ep, const uint8_t * introKey);
			void SendPeerTest (uint8_t msg, const uint8_t * signedData, size_t signedDataLen, const uint8_t * introKey); // PeerTest message 
			
			void HandlePayload (const uint8_t * buf, size_t len);
			void HandleAck (const uint8_t * buf, size_t len);
			void HandleAckRange (uint32_t firstPacketNum, uint32_t lastPacketNum);
			bool ExtractEndpoint (const uint8_t * buf, size_t size, boost::asio::ip::udp::endpoint& ep);
			size_t CreateEndpoint (uint8_t * buf, size_t len, const boost::asio::ip::udp::endpoint& ep);
			std::shared_ptr<const i2p::data::RouterInfo::Address> FindLocalAddress () const;
			std::shared_ptr<const i2p::data::RouterInfo> ExtractRouterInfo (const uint8_t * buf, size_t size);
			void CreateNonce (uint64_t seqn, uint8_t * nonce);
			bool UpdateReceivePacketNum (uint32_t packetNum); // for Ack, returns false if duplicate
			void HandleFirstFragment (const uint8_t * buf, size_t len);
			void HandleFollowOnFragment (const uint8_t * buf, size_t len);
			bool ConcatOutOfSequenceFragments (std::shared_ptr<SSU2IncompleteMessage> m); // true if message complete
			void HandleRelayRequest (const uint8_t * buf, size_t len);
			void HandleRelayIntro (const uint8_t * buf, size_t len);
			void HandleRelayResponse (const uint8_t * buf, size_t len);
			void HandlePeerTest (const uint8_t * buf, size_t len);

			size_t CreateAddressBlock (uint8_t * buf, size_t len, const boost::asio::ip::udp::endpoint& ep);
			size_t CreateRouterInfoBlock (uint8_t * buf, size_t len, std::shared_ptr<const i2p::data::RouterInfo> r);
			size_t CreateAckBlock (uint8_t * buf, size_t len);
			size_t CreatePaddingBlock (uint8_t * buf, size_t len, size_t minSize = 0);
			size_t CreateI2NPBlock (uint8_t * buf, size_t len, std::shared_ptr<I2NPMessage>&& msg);
			size_t CreateFirstFragmentBlock (uint8_t * buf, size_t len, std::shared_ptr<I2NPMessage> msg);
			size_t CreateFollowOnFragmentBlock (uint8_t * buf, size_t len, std::shared_ptr<I2NPMessage> msg, uint8_t& fragmentNum, uint32_t msgID);
			size_t CreateRelayIntroBlock (uint8_t * buf, size_t len, const uint8_t * introData, size_t introDataLen);
			size_t CreateRelayResponseBlock (uint8_t * buf, size_t len, uint32_t nonce); // Charlie
			size_t CreatePeerTestBlock (uint8_t * buf, size_t len, uint8_t msg, SSU2PeerTestCode code, const uint8_t * routerHash, const uint8_t * signedData, size_t signedDataLen);
			size_t CreatePeerTestBlock (uint8_t * buf, size_t len, uint32_t nonce); // Alice

		private:

			SSU2Server& m_Server;
			std::shared_ptr<i2p::crypto::X25519Keys> m_EphemeralKeys;
			std::unique_ptr<i2p::crypto::NoiseSymmetricState> m_NoiseState;
			std::unique_ptr<SessionConfirmedFragment> m_SessionConfirmedFragment1; // for Bob if applicable
			std::shared_ptr<const i2p::data::RouterInfo::Address> m_Address;
			boost::asio::ip::udp::endpoint m_RemoteEndpoint;
			i2p::data::RouterInfo::CompatibleTransports m_RemoteTransports; // for peer tests
			uint64_t m_DestConnID, m_SourceConnID;
			SSU2SessionState m_State;
			uint8_t m_KeyDataSend[64], m_KeyDataReceive[64];
			uint32_t m_SendPacketNum, m_ReceivePacketNum;
			std::set<uint32_t> m_OutOfSequencePackets; // packet nums > receive packet num
			std::map<uint32_t, std::shared_ptr<SentPacket> > m_SentPackets; // packetNum -> packet
			std::map<uint32_t, std::shared_ptr<SSU2IncompleteMessage> > m_IncompleteMessages; // I2NP
			std::map<uint32_t, std::pair <std::shared_ptr<SSU2Session>, uint64_t > > m_RelaySessions; // nonce->(Alice, timestamp) for Bob or nonce->(Charlie, timestamp) for Alice
			std::map<uint32_t, std::pair <std::shared_ptr<SSU2Session>, uint64_t > > m_PeerTests; // same as for relay sessions
			std::list<std::shared_ptr<I2NPMessage> > m_SendQueue;
			i2p::I2NPMessagesHandler m_Handler;
			bool m_IsDataReceived;
			size_t m_WindowSize;
			uint32_t m_RelayTag; // between Bob and Charlie
			OnEstablished m_OnEstablished; // callback from Established
	};

	inline uint64_t CreateHeaderMask (const uint8_t * kh, const uint8_t * nonce)
	{
		uint64_t data = 0;
		i2p::crypto::ChaCha20 ((uint8_t *)&data, 8, kh, nonce, (uint8_t *)&data);
		return data;
	}
}
}

#endif
