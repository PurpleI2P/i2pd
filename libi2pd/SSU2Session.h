/*
* Copyright (c) 2022-2024, The PurpleI2P Project
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
#include "RouterContext.h"
#include "TransportSession.h"

namespace i2p
{
namespace transport
{
	const int SSU2_CONNECT_TIMEOUT = 5; // 5 seconds
	const int SSU2_TERMINATION_TIMEOUT = 165; // in seconds
	const int SSU2_CLOCK_SKEW = 60; // in seconds
	const int SSU2_CLOCK_THRESHOLD = 15; // in seconds, if more we should adjust
	const int SSU2_TOKEN_EXPIRATION_TIMEOUT = 9; // for Retry message, in seconds
	const int SSU2_NEXT_TOKEN_EXPIRATION_TIMEOUT = 52*60; // for next token block, in seconds
	const int SSU2_TOKEN_EXPIRATION_THRESHOLD = 2; // in seconds
	const int SSU2_RELAY_NONCE_EXPIRATION_TIMEOUT = 10; // in seconds
	const int SSU2_PEER_TEST_EXPIRATION_TIMEOUT = 60; // 60 seconds
	const size_t SSU2_MAX_PACKET_SIZE = 1500;
	const size_t SSU2_MIN_PACKET_SIZE = 1280;
	const int SSU2_HANDSHAKE_RESEND_INTERVAL = 1000; // in milliseconds
	const int SSU2_MAX_NUM_RESENDS = 5;
	const int SSU2_RESEND_ATTEMPT_MIN_INTERVAL = 3; // in milliseconds
	const int SSU2_INCOMPLETE_MESSAGES_CLEANUP_TIMEOUT = 30; // in seconds
	const int SSU2_MAX_NUM_RECEIVED_I2NP_MSGIDS = 5000; // how many msgID we store for duplicates check
	const int SSU2_RECEIVED_I2NP_MSGIDS_CLEANUP_TIMEOUT = 10; // in seconds
	const int SSU2_DECAY_INTERVAL = 20; // in seconds
	const size_t SSU2_MIN_WINDOW_SIZE = 16; // in packets
	const size_t SSU2_MAX_WINDOW_SIZE = 256; // in packets
	const size_t SSU2_MIN_RTO = 100; // in milliseconds
	const size_t SSU2_INITIAL_RTO = 540; // in milliseconds
	const size_t SSU2_MAX_RTO = 2500; // in milliseconds
	const double SSU2_UNKNOWN_RTT = -1;
	const double SSU2_RTT_EWMA_ALPHA = 0.125;
	const float SSU2_kAPPA = 1.8;
	const int SSU2_MAX_NUM_ACNT = 255; // acnt, acks or nacks
	const int SSU2_MAX_NUM_ACK_PACKETS = 511; // ackthrough + acnt + 1 range
	const int SSU2_MAX_NUM_ACK_RANGES = 32; // to send
	const uint8_t SSU2_MAX_NUM_FRAGMENTS = 64;
	const int SSU2_SEND_DATETIME_NUM_PACKETS = 256;

	// flags
	const uint8_t SSU2_FLAG_IMMEDIATE_ACK_REQUESTED = 0x01;

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
		eSSU2SessionStateTokenReceived,
		eSSU2SessionStateSessionRequestSent,
		eSSU2SessionStateSessionRequestReceived,
		eSSU2SessionStateSessionCreatedSent,
		eSSU2SessionStateSessionCreatedReceived,
		eSSU2SessionStateSessionConfirmedSent,
		eSSU2SessionStateEstablished,
		eSSU2SessionStateClosing,
		eSSU2SessionStateClosingConfirmed,
		eSSU2SessionStateTerminated,
		eSSU2SessionStateFailed,
		eSSU2SessionStateIntroduced,
		eSSU2SessionStatePeerTest,
		eSSU2SessionStateTokenRequestReceived
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

	enum SSU2RelayResponseCode
	{
		eSSU2RelayResponseCodeAccept = 0,
		eSSU2RelayResponseCodeBobRelayTagNotFound = 5,
		eSSU2RelayResponseCodeCharlieUnsupportedAddress = 65,
		eSSU2RelayResponseCodeCharlieSignatureFailure = 67,
		eSSU2RelayResponseCodeCharlieAliceIsUnknown = 70
	};

	enum SSU2TerminationReason
	{
		eSSU2TerminationReasonNormalClose = 0,
		eSSU2TerminationReasonTerminationReceived = 1,
		eSSU2TerminationReasonIdleTimeout = 2,
		eSSU2TerminationReasonRouterShutdown = 3,
		eSSU2TerminationReasonDataPhaseAEADFailure= 4,
		eSSU2TerminationReasonIncompatibleOptions = 5,
		eSSU2TerminationReasonTncompatibleSignatureType = 6,
		eSSU2TerminationReasonClockSkew = 7,
		eSSU2TerminationPaddingViolation = 8,
		eSSU2TerminationReasonAEADFramingError = 9,
		eSSU2TerminationReasonPayloadFormatError = 10,
		eSSU2TerminationReasonSessionRequestError = 11,
		eSSU2TerminationReasonSessionCreatedError = 12,
		eSSU2TerminationReasonSessionConfirmedError = 13,
		eSSU2TerminationReasonTimeout = 14,
		eSSU2TerminationReasonRouterInfoSignatureVerificationFail = 15,
		eSSU2TerminationReasonInvalidS = 16,
		eSSU2TerminationReasonBanned = 17,
		eSSU2TerminationReasonBadToken = 18,
		eSSU2TerminationReasonConnectionLimits = 19,
		eSSU2TerminationReasonIncompatibleVersion = 20,
		eSSU2TerminationReasonWrongNetID = 21,
		eSSU2TerminationReasonReplacedByNewSession = 22
	};

	struct SSU2IncompleteMessage
	{
		struct Fragment
		{
			uint8_t buf[SSU2_MAX_PACKET_SIZE];
			size_t len;
			int fragmentNum;
			bool isLast;
			std::shared_ptr<Fragment> next;
		};

		std::shared_ptr<I2NPMessage> msg;
		int nextFragmentNum;
		uint32_t lastFragmentInsertTime; // in seconds
		std::shared_ptr<Fragment> outOfSequenceFragments; // #1 and more

		void AttachNextFragment (const uint8_t * fragment, size_t fragmentSize);
		bool ConcatOutOfSequenceFragments (); // true if message complete
		void AddOutOfSequenceFragment (std::shared_ptr<Fragment> fragment);
	};

	struct SSU2SentPacket
	{
		uint8_t payload[SSU2_MAX_PACKET_SIZE];
		size_t payloadSize = 0;
		uint64_t sendTime; // in milliseconds
		int numResends = 0;
	};

	// RouterInfo flags
	const uint8_t SSU2_ROUTER_INFO_FLAG_REQUEST_FLOOD = 0x01;
	const uint8_t SSU2_ROUTER_INFO_FLAG_GZIP = 0x02;

	class SSU2Server;
	class SSU2Session: public TransportSession, public std::enable_shared_from_this<SSU2Session>
	{
		protected:
			
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

		private:
			
			struct HandshakePacket
			{
				Header header;
				uint8_t headerX[48]; // part1 for SessionConfirmed
				uint8_t payload[SSU2_MAX_PACKET_SIZE*2];
				size_t payloadSize = 0;
				uint64_t sendTime = 0; // in milliseconds
				bool isSecondFragment = false; // for SessionConfirmed
			};

			typedef std::function<void ()> OnEstablished;

		public:

			SSU2Session (SSU2Server& server, std::shared_ptr<const i2p::data::RouterInfo> in_RemoteRouter = nullptr,
				std::shared_ptr<const i2p::data::RouterInfo::Address> addr = nullptr, bool noise = true);
			virtual ~SSU2Session ();

			void SetRemoteEndpoint (const boost::asio::ip::udp::endpoint& ep) { m_RemoteEndpoint = ep; };
			const boost::asio::ip::udp::endpoint& GetRemoteEndpoint () const { return m_RemoteEndpoint; };
			i2p::data::RouterInfo::CompatibleTransports GetRemoteTransports () const { return m_RemoteTransports; };
			i2p::data::RouterInfo::CompatibleTransports GetRemotePeerTestTransports () const { return m_RemotePeerTestTransports; };
			std::shared_ptr<const i2p::data::RouterInfo::Address> GetAddress () const { return m_Address; };
			void SetOnEstablished (OnEstablished e) { m_OnEstablished = e; };
			OnEstablished GetOnEstablished () const { return m_OnEstablished; };

			virtual void Connect ();
			bool Introduce (std::shared_ptr<SSU2Session> session, uint32_t relayTag);
			void WaitForIntroduction ();
			void SendPeerTest (); // Alice, Data message
			void SendKeepAlive ();
			void RequestTermination (SSU2TerminationReason reason);
			void CleanUp (uint64_t ts);
			void FlushData ();
			void Done () override;
			void SendLocalRouterInfo (bool update) override;
			void SendI2NPMessages (const std::vector<std::shared_ptr<I2NPMessage> >& msgs) override;
			void MoveSendQueue (std::shared_ptr<SSU2Session> other);
			uint32_t GetRelayTag () const override { return m_RelayTag; };
			size_t Resend (uint64_t ts); // return number of resent packets
			uint64_t GetLastResendTime () const { return m_LastResendTime; };
			bool IsEstablished () const override { return m_State == eSSU2SessionStateEstablished; };
			uint64_t GetConnID () const { return m_SourceConnID; };
			SSU2SessionState GetState () const { return m_State; };
			void SetState (SSU2SessionState state) { m_State = state; };

			virtual bool ProcessFirstIncomingMessage (uint64_t connID, uint8_t * buf, size_t len);
			bool ProcessSessionCreated (uint8_t * buf, size_t len);
			bool ProcessSessionConfirmed (uint8_t * buf, size_t len);
			bool ProcessRetry (uint8_t * buf, size_t len);
			bool ProcessHolePunch (uint8_t * buf, size_t len);
			virtual bool ProcessPeerTest (uint8_t * buf, size_t len);
			void ProcessData (uint8_t * buf, size_t len, const boost::asio::ip::udp::endpoint& from);

		protected:

			SSU2Server& GetServer () { return m_Server; }
			RouterStatus GetRouterStatus () const;
			void SetRouterStatus (RouterStatus status) const;
			size_t GetMaxPayloadSize () const { return m_MaxPayloadSize; }
			void SetIsDataReceived (bool dataReceived) { m_IsDataReceived = dataReceived; };
			
			uint64_t GetSourceConnID () const { return m_SourceConnID; }
			void SetSourceConnID (uint64_t sourceConnID) { m_SourceConnID = sourceConnID; }
			uint64_t GetDestConnID () const { return m_DestConnID; }
			void SetDestConnID (uint64_t destConnID) { m_DestConnID = destConnID; }

			void SetAddress (std::shared_ptr<const i2p::data::RouterInfo::Address> addr) { m_Address = addr; }
			void HandlePayload (const uint8_t * buf, size_t len);

			size_t CreateAddressBlock (uint8_t * buf, size_t len, const boost::asio::ip::udp::endpoint& ep);
			size_t CreatePaddingBlock (uint8_t * buf, size_t len, size_t minSize = 0);
			size_t CreatePeerTestBlock (uint8_t * buf, size_t len, uint8_t msg, SSU2PeerTestCode code, const uint8_t * routerHash, const uint8_t * signedData, size_t signedDataLen);
			
		private:

			void Terminate ();
			void Established ();
			void ScheduleConnectTimer ();
			void HandleConnectTimer (const boost::system::error_code& ecode);
			void PostI2NPMessages (std::vector<std::shared_ptr<I2NPMessage> > msgs);
			bool SendQueue (); // returns true if ack block was sent
			bool SendFragmentedMessage (std::shared_ptr<I2NPMessage> msg);
			void ResendHandshakePacket ();
			void ConnectAfterIntroduction ();

			void ProcessSessionRequest (Header& header, uint8_t * buf, size_t len);
			void ProcessTokenRequest (Header& header, uint8_t * buf, size_t len);

			void SendSessionRequest (uint64_t token = 0);
			void SendSessionCreated (const uint8_t * X);
			void SendSessionConfirmed (const uint8_t * Y);
			void KDFDataPhase (uint8_t * keydata_ab, uint8_t * keydata_ba);
			void SendTokenRequest ();
			void SendRetry ();
			uint32_t SendData (const uint8_t * buf, size_t len, uint8_t flags = 0); // returns packet num
			void SendQuickAck ();
			void SendTermination ();
			void SendHolePunch (uint32_t nonce, const boost::asio::ip::udp::endpoint& ep, const uint8_t * introKey, uint64_t token);
			void SendPathResponse (const uint8_t * data, size_t len);
			void SendPathChallenge ();

			void HandleDateTime (const uint8_t * buf, size_t len);
			void HandleRouterInfo (const uint8_t * buf, size_t len);
			void HandleAck (const uint8_t * buf, size_t len);
			void HandleAckRange (uint32_t firstPacketNum, uint32_t lastPacketNum, uint64_t ts);
			void HandleAddress (const uint8_t * buf, size_t len);
			bool ExtractEndpoint (const uint8_t * buf, size_t size, boost::asio::ip::udp::endpoint& ep);
			size_t CreateEndpoint (uint8_t * buf, size_t len, const boost::asio::ip::udp::endpoint& ep);
			std::shared_ptr<const i2p::data::RouterInfo::Address> FindLocalAddress () const;
			void AdjustMaxPayloadSize ();
			bool GetTestingState () const;
			void SetTestingState(bool testing) const;
			std::shared_ptr<const i2p::data::RouterInfo> ExtractRouterInfo (const uint8_t * buf, size_t size);
			bool UpdateReceivePacketNum (uint32_t packetNum); // for Ack, returns false if duplicate
			void HandleFirstFragment (const uint8_t * buf, size_t len);
			void HandleFollowOnFragment (const uint8_t * buf, size_t len);
			void HandleRelayRequest (const uint8_t * buf, size_t len);
			void HandleRelayIntro (const uint8_t * buf, size_t len, int attempts = 0);
			void HandleRelayResponse (const uint8_t * buf, size_t len);
			virtual void HandlePeerTest (const uint8_t * buf, size_t len);
			void HandleI2NPMsg (std::shared_ptr<I2NPMessage>&& msg);

			size_t CreateRouterInfoBlock (uint8_t * buf, size_t len, std::shared_ptr<const i2p::data::RouterInfo> r);
			size_t CreateRouterInfoBlock (uint8_t * buf, size_t len, std::shared_ptr<const i2p::data::RouterInfo::Buffer> riBuffer);
			size_t CreateAckBlock (uint8_t * buf, size_t len);
			size_t CreateI2NPBlock (uint8_t * buf, size_t len, std::shared_ptr<I2NPMessage>&& msg);
			size_t CreateFirstFragmentBlock (uint8_t * buf, size_t len, std::shared_ptr<I2NPMessage> msg);
			size_t CreateFollowOnFragmentBlock (uint8_t * buf, size_t len, std::shared_ptr<I2NPMessage> msg, uint8_t& fragmentNum, uint32_t msgID);
			size_t CreateRelayIntroBlock (uint8_t * buf, size_t len, const uint8_t * introData, size_t introDataLen);
			size_t CreateRelayResponseBlock (uint8_t * buf, size_t len, SSU2RelayResponseCode code, uint32_t nonce, uint64_t token, bool v4);
			size_t CreatePeerTestBlock (uint8_t * buf, size_t len, uint32_t nonce); // Alice
			size_t CreateTerminationBlock (uint8_t * buf, size_t len);
			
		private:

			SSU2Server& m_Server;
			std::shared_ptr<i2p::crypto::X25519Keys> m_EphemeralKeys;
			std::unique_ptr<i2p::crypto::NoiseSymmetricState> m_NoiseState;
			std::unique_ptr<HandshakePacket> m_SessionConfirmedFragment; // for Bob if applicable or second fragment for Alice
			std::unique_ptr<HandshakePacket> m_SentHandshakePacket; // SessionRequest, SessionCreated or SessionConfirmed
			std::shared_ptr<const i2p::data::RouterInfo::Address> m_Address;
			boost::asio::ip::udp::endpoint m_RemoteEndpoint;
			i2p::data::RouterInfo::CompatibleTransports m_RemoteTransports, m_RemotePeerTestTransports; 
			uint64_t m_DestConnID, m_SourceConnID;
			SSU2SessionState m_State;
			uint8_t m_KeyDataSend[64], m_KeyDataReceive[64];
			uint32_t m_SendPacketNum, m_ReceivePacketNum, m_LastDatetimeSentPacketNum;
			std::set<uint32_t> m_OutOfSequencePackets; // packet nums > receive packet num
			std::map<uint32_t, std::shared_ptr<SSU2SentPacket> > m_SentPackets; // packetNum -> packet
			std::unordered_map<uint32_t, std::shared_ptr<SSU2IncompleteMessage> > m_IncompleteMessages; // msgID -> I2NP
			std::unordered_map<uint32_t, std::pair <std::shared_ptr<SSU2Session>, uint64_t > > m_RelaySessions; // nonce->(Alice, timestamp) for Bob or nonce->(Charlie, timestamp) for Alice
			std::list<std::shared_ptr<I2NPMessage> > m_SendQueue;
			i2p::I2NPMessagesHandler m_Handler;
			bool m_IsDataReceived;
			double m_RTT;
			int m_MsgLocalExpirationTimeout;
			int m_MsgLocalSemiExpirationTimeout;
			size_t m_WindowSize, m_RTO;
			uint32_t m_RelayTag; // between Bob and Charlie
			OnEstablished m_OnEstablished; // callback from Established
			boost::asio::deadline_timer m_ConnectTimer;
			SSU2TerminationReason m_TerminationReason;
			size_t m_MaxPayloadSize;
			std::unique_ptr<i2p::data::IdentHash> m_PathChallenge;
			std::unordered_map<uint32_t, uint32_t> m_ReceivedI2NPMsgIDs; // msgID -> timestamp in seconds
			uint64_t m_LastResendTime, m_LastResendAttemptTime; // in milliseconds
	};

	
	const int SSU2_PEER_TEST_RESEND_INTERVAL = 3000; // in milliseconds
	const int SSU2_PEER_TEST_RESEND_INTERVAL_VARIANCE = 2000; // in milliseconds
	const int SSU2_PEER_TEST_MAX_NUM_RESENDS = 3;
	
	class SSU2PeerTestSession: public SSU2Session // for PeerTest msgs 5,6,7
	{
		public:

			SSU2PeerTestSession (SSU2Server& server, uint64_t sourceConnID, uint64_t destConnID);

			uint8_t GetMsgNumReceived () const { return m_MsgNumReceived; }	
			bool IsConnectedRecently () const { return m_IsConnectedRecently; }
			void SetStatusChanged () { m_IsStatusChanged = true; }
			
			void SendPeerTest (uint8_t msg, const uint8_t * signedData, size_t signedDataLen, 
				std::shared_ptr<const i2p::data::RouterInfo::Address> addr);
			bool ProcessPeerTest (uint8_t * buf, size_t len) override;
			void Connect () override; // outgoing
			bool ProcessFirstIncomingMessage (uint64_t connID, uint8_t * buf, size_t len) override; // incoming
			
		private:

			void SendPeerTest (uint8_t msg, const uint8_t * signedData, size_t signedDataLen); // PeerTest message
			void SendPeerTest (uint8_t msg); // send or resend m_SignedData
			void HandlePeerTest (const uint8_t * buf, size_t len) override;

			void ScheduleResend ();
			
		private:

			uint8_t m_MsgNumReceived, m_NumResends;
			bool m_IsConnectedRecently, m_IsStatusChanged;
			std::vector<uint8_t> m_SignedData; // for resends
			boost::asio::deadline_timer m_PeerTestResendTimer;
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
