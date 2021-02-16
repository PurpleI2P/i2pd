/*
* Copyright (c) 2013-2020, The PurpleI2P Project
*
* This file is part of Purple i2pd project and licensed under BSD3
*
* See full license text in LICENSE file at top of project tree
*/

#ifndef STREAMING_H__
#define STREAMING_H__

#include <inttypes.h>
#include <string>
#include <map>
#include <set>
#include <queue>
#include <functional>
#include <memory>
#include <mutex>
#include <boost/asio.hpp>
#include "Base.h"
#include "I2PEndian.h"
#include "Identity.h"
#include "LeaseSet.h"
#include "I2NPProtocol.h"
#include "Garlic.h"
#include "Tunnel.h"
#include "util.h" // MemoryPool

namespace i2p
{
namespace client
{
	class ClientDestination;
}
namespace stream
{
	const uint16_t PACKET_FLAG_SYNCHRONIZE = 0x0001;
	const uint16_t PACKET_FLAG_CLOSE = 0x0002;
	const uint16_t PACKET_FLAG_RESET = 0x0004;
	const uint16_t PACKET_FLAG_SIGNATURE_INCLUDED = 0x0008;
	const uint16_t PACKET_FLAG_SIGNATURE_REQUESTED = 0x0010;
	const uint16_t PACKET_FLAG_FROM_INCLUDED = 0x0020;
	const uint16_t PACKET_FLAG_DELAY_REQUESTED = 0x0040;
	const uint16_t PACKET_FLAG_MAX_PACKET_SIZE_INCLUDED = 0x0080;
	const uint16_t PACKET_FLAG_PROFILE_INTERACTIVE = 0x0100;
	const uint16_t PACKET_FLAG_ECHO = 0x0200;
	const uint16_t PACKET_FLAG_NO_ACK = 0x0400;
	const uint16_t PACKET_FLAG_OFFLINE_SIGNATURE = 0x0800;

	const size_t STREAMING_MTU = 1730;
	const size_t STREAMING_MTU_RATCHETS = 1812;
	const size_t MAX_PACKET_SIZE = 4096;
	const size_t COMPRESSION_THRESHOLD_SIZE = 66;
	const int MAX_NUM_RESEND_ATTEMPTS = 6;
	const int WINDOW_SIZE = 6; // in messages
	const int MIN_WINDOW_SIZE = 1;
	const int MAX_WINDOW_SIZE = 128;
	const int INITIAL_RTT = 8000; // in milliseconds
	const int INITIAL_RTO = 9000; // in milliseconds
	const int SYN_TIMEOUT = 200; // how long we wait for SYN after follow-on, in milliseconds
	const size_t MAX_PENDING_INCOMING_BACKLOG = 128;
	const int PENDING_INCOMING_TIMEOUT = 10; // in seconds
	const int MAX_RECEIVE_TIMEOUT = 20; // in seconds

	struct Packet
	{
		size_t len, offset;
		uint8_t buf[MAX_PACKET_SIZE];
		uint64_t sendTime;

		Packet (): len (0), offset (0), sendTime (0) {};
		uint8_t * GetBuffer () { return buf + offset; };
		size_t GetLength () const { return len - offset; };

		uint32_t GetSendStreamID () const { return bufbe32toh (buf); };
		uint32_t GetReceiveStreamID () const { return bufbe32toh (buf + 4); };
		uint32_t GetSeqn () const { return bufbe32toh (buf + 8); };
		uint32_t GetAckThrough () const { return bufbe32toh (buf + 12); };
		uint8_t GetNACKCount () const { return buf[16]; };
		uint32_t GetNACK (int i) const { return bufbe32toh (buf + 17 + 4 * i); };
		const uint8_t * GetOption () const { return buf + 17 + GetNACKCount ()*4 + 3; }; // 3 = resendDelay + flags
		uint16_t GetFlags () const { return bufbe16toh (GetOption () - 2); };
		uint16_t GetOptionSize () const { return bufbe16toh (GetOption ()); };
		const uint8_t * GetOptionData () const { return GetOption () + 2; };
		const uint8_t * GetPayload () const { return GetOptionData () + GetOptionSize (); };

		bool IsSYN () const { return GetFlags () & PACKET_FLAG_SYNCHRONIZE; };
		bool IsNoAck () const { return GetFlags () & PACKET_FLAG_NO_ACK; };
		bool IsEcho () const { return GetFlags () & PACKET_FLAG_ECHO; };
	};

	struct PacketCmp
	{
		bool operator() (const Packet * p1, const Packet * p2) const
		{
			return p1->GetSeqn () < p2->GetSeqn ();
		};
	};

	typedef std::function<void (const boost::system::error_code& ecode)> SendHandler;
	struct SendBuffer
	{
		uint8_t * buf;
		size_t len, offset;
		SendHandler handler;

		SendBuffer (const uint8_t * b, size_t l, SendHandler h):
			len(l), offset (0), handler(h)
		{
			buf = new uint8_t[len];
			memcpy (buf, b, len);
		}
		SendBuffer (size_t l): // creat empty buffer
			len(l), offset (0)	
		{
			buf = new uint8_t[len];
		}	
		~SendBuffer ()
		{
			delete[] buf;
			if (handler) handler(boost::system::error_code ());
		}
		size_t GetRemainingSize () const { return len - offset; };
		const uint8_t * GetRemaningBuffer () const { return buf + offset; };
		void Cancel () { if (handler) handler (boost::asio::error::make_error_code (boost::asio::error::operation_aborted)); handler = nullptr; };
	};

	class SendBufferQueue
	{
		public:

			SendBufferQueue (): m_Size (0) {};
			~SendBufferQueue () { CleanUp (); };

			void Add (const uint8_t * buf, size_t len, SendHandler handler);
			void Add (std::shared_ptr<SendBuffer> buf);
			size_t Get (uint8_t * buf, size_t len);
			size_t GetSize () const { return m_Size; };
			bool IsEmpty () const { return m_Buffers.empty (); };
			void CleanUp ();

		private:

			std::list<std::shared_ptr<SendBuffer> > m_Buffers;
			size_t m_Size;
	};

	enum StreamStatus
	{
		eStreamStatusNew = 0,
		eStreamStatusOpen,
		eStreamStatusReset,
		eStreamStatusClosing,
		eStreamStatusClosed
	};

	class StreamingDestination;
	class Stream: public std::enable_shared_from_this<Stream>
	{
		public:

			Stream (boost::asio::io_service& service, StreamingDestination& local,
				std::shared_ptr<const i2p::data::LeaseSet> remote, int port = 0); // outgoing
			Stream (boost::asio::io_service& service, StreamingDestination& local); // incoming

			~Stream ();
			uint32_t GetSendStreamID () const { return m_SendStreamID; };
			uint32_t GetRecvStreamID () const { return m_RecvStreamID; };
			std::shared_ptr<const i2p::data::LeaseSet> GetRemoteLeaseSet () const { return m_RemoteLeaseSet; };
			std::shared_ptr<const i2p::data::IdentityEx> GetRemoteIdentity () const { return m_RemoteIdentity; };
			bool IsOpen () const { return m_Status == eStreamStatusOpen; };
			bool IsEstablished () const { return m_SendStreamID; };
			StreamStatus GetStatus () const { return m_Status; };
			StreamingDestination& GetLocalDestination () { return m_LocalDestination; };

			void HandleNextPacket (Packet * packet);
			void HandlePing (Packet * packet);
			size_t Send (const uint8_t * buf, size_t len);
			void AsyncSend (const uint8_t * buf, size_t len, SendHandler handler);

			template<typename Buffer, typename ReceiveHandler>
			void AsyncReceive (const Buffer& buffer, ReceiveHandler handler, int timeout = 0);
			size_t ReadSome (uint8_t * buf, size_t len) { return ConcatenatePackets (buf, len); };

			void AsyncClose() { m_Service.post(std::bind(&Stream::Close, shared_from_this())); };

			/** only call close from destination thread, use Stream::AsyncClose for other threads */
			void Close ();
			void Cancel () { m_ReceiveTimer.cancel (); };

			size_t GetNumSentBytes () const { return m_NumSentBytes; };
			size_t GetNumReceivedBytes () const { return m_NumReceivedBytes; };
			size_t GetSendQueueSize () const { return m_SentPackets.size (); };
			size_t GetReceiveQueueSize () const { return m_ReceiveQueue.size (); };
			size_t GetSendBufferSize () const { return m_SendBuffer.GetSize (); };
			int GetWindowSize () const { return m_WindowSize; };
			int GetRTT () const { return m_RTT; };

			void Terminate (bool deleteFromDestination = true);

		private:

			void CleanUp ();

			void SendBuffer ();
			void SendQuickAck ();
			void SendClose ();
			bool SendPacket (Packet * packet);
			void SendPackets (const std::vector<Packet *>& packets);
			void SendUpdatedLeaseSet ();

			void SavePacket (Packet * packet);
			void ProcessPacket (Packet * packet);
			bool ProcessOptions (uint16_t flags, Packet * packet);
			void ProcessAck (Packet * packet);
			size_t ConcatenatePackets (uint8_t * buf, size_t len);

			void UpdateCurrentRemoteLease (bool expired = false);

			template<typename Buffer, typename ReceiveHandler>
			void HandleReceiveTimer (const boost::system::error_code& ecode, const Buffer& buffer, ReceiveHandler handler, int remainingTimeout);

			void ScheduleResend ();
			void HandleResendTimer (const boost::system::error_code& ecode);
			void HandleAckSendTimer (const boost::system::error_code& ecode);

		private:

			boost::asio::io_service& m_Service;
			uint32_t m_SendStreamID, m_RecvStreamID, m_SequenceNumber;
			int32_t m_LastReceivedSequenceNumber;
			StreamStatus m_Status;
			bool m_IsAckSendScheduled;
			StreamingDestination& m_LocalDestination;
			std::shared_ptr<const i2p::data::IdentityEx> m_RemoteIdentity;
			std::shared_ptr<const i2p::crypto::Verifier> m_TransientVerifier; // in case of offline key
			std::shared_ptr<const i2p::data::LeaseSet> m_RemoteLeaseSet;
			std::shared_ptr<i2p::garlic::GarlicRoutingSession> m_RoutingSession;
			std::shared_ptr<const i2p::data::Lease> m_CurrentRemoteLease;
			std::shared_ptr<i2p::tunnel::OutboundTunnel> m_CurrentOutboundTunnel;
			std::queue<Packet *> m_ReceiveQueue;
			std::set<Packet *, PacketCmp> m_SavedPackets;
			std::set<Packet *, PacketCmp> m_SentPackets;
			boost::asio::deadline_timer m_ReceiveTimer, m_ResendTimer, m_AckSendTimer;
			size_t m_NumSentBytes, m_NumReceivedBytes;
			uint16_t m_Port;

			std::mutex m_SendBufferMutex;
			SendBufferQueue m_SendBuffer;
			int m_WindowSize, m_RTT, m_RTO, m_AckDelay;
			uint64_t m_LastWindowSizeIncreaseTime;
			int m_NumResendAttempts;
			size_t m_MTU;
	};

	class StreamingDestination: public std::enable_shared_from_this<StreamingDestination>
	{
		public:

			typedef std::function<void (std::shared_ptr<Stream>)> Acceptor;

			StreamingDestination (std::shared_ptr<i2p::client::ClientDestination> owner, uint16_t localPort = 0, bool gzip = true);
			~StreamingDestination ();

			void Start ();
			void Stop ();

			std::shared_ptr<Stream> CreateNewOutgoingStream (std::shared_ptr<const i2p::data::LeaseSet> remote, int port = 0);
			void DeleteStream (std::shared_ptr<Stream> stream);
			bool DeleteStream (uint32_t recvStreamID);
			void SetAcceptor (const Acceptor& acceptor);
			void ResetAcceptor ();
			bool IsAcceptorSet () const { return m_Acceptor != nullptr; };
			void AcceptOnce (const Acceptor& acceptor);
			void AcceptOnceAcceptor (std::shared_ptr<Stream> stream, Acceptor acceptor, Acceptor prev);

			std::shared_ptr<i2p::client::ClientDestination> GetOwner () const { return m_Owner; };
			void SetOwner (std::shared_ptr<i2p::client::ClientDestination> owner) { m_Owner = owner; };
			uint16_t GetLocalPort () const { return m_LocalPort; };

			void HandleDataMessagePayload (const uint8_t * buf, size_t len);
			std::shared_ptr<I2NPMessage> CreateDataMessage (const uint8_t * payload, size_t len, uint16_t toPort, bool checksum = true);

			Packet * NewPacket () { return m_PacketsPool.Acquire(); }
			void DeletePacket (Packet * p) { return m_PacketsPool.Release(p); }

		private:

			void HandleNextPacket (Packet * packet);
			std::shared_ptr<Stream> CreateNewIncomingStream (uint32_t receiveStreamID);
			void HandlePendingIncomingTimer (const boost::system::error_code& ecode);

		private:

			std::shared_ptr<i2p::client::ClientDestination> m_Owner;
			uint16_t m_LocalPort;
			bool m_Gzip; // gzip compression of data messages
			std::mutex m_StreamsMutex;
			std::map<uint32_t, std::shared_ptr<Stream> > m_Streams; // sendStreamID->stream
			std::map<uint32_t, std::shared_ptr<Stream> > m_IncomingStreams; // receiveStreamID->stream
			Acceptor m_Acceptor;
			std::list<std::shared_ptr<Stream> > m_PendingIncomingStreams;
			boost::asio::deadline_timer m_PendingIncomingTimer;
			std::map<uint32_t, std::list<Packet *> > m_SavedPackets; // receiveStreamID->packets, arrived before SYN

			i2p::util::MemoryPool<Packet> m_PacketsPool;
			i2p::util::MemoryPool<I2NPMessageBuffer<I2NP_MAX_MESSAGE_SIZE> > m_I2NPMsgsPool;

		public:

			i2p::data::GzipInflator m_Inflator;
			i2p::data::GzipDeflator m_Deflator;

			// for HTTP only
			const decltype(m_Streams)& GetStreams () const { return m_Streams; };
	};

//-------------------------------------------------

	template<typename Buffer, typename ReceiveHandler>
	void Stream::AsyncReceive (const Buffer& buffer, ReceiveHandler handler, int timeout)
	{
		auto s = shared_from_this();
		m_Service.post ([s, buffer, handler, timeout](void)
		{
			if (!s->m_ReceiveQueue.empty () || s->m_Status == eStreamStatusReset)
				s->HandleReceiveTimer (boost::asio::error::make_error_code (boost::asio::error::operation_aborted), buffer, handler, 0);
			else
			{
				int t = (timeout > MAX_RECEIVE_TIMEOUT) ? MAX_RECEIVE_TIMEOUT : timeout;
				s->m_ReceiveTimer.expires_from_now (boost::posix_time::seconds(t));
				int left = timeout - t;
				auto self = s->shared_from_this();
				self->m_ReceiveTimer.async_wait (
					[self, buffer, handler, left](const boost::system::error_code & ec)
					{
						self->HandleReceiveTimer(ec, buffer, handler, left);
					});
			}
		});
	}

	template<typename Buffer, typename ReceiveHandler>
	void Stream::HandleReceiveTimer (const boost::system::error_code& ecode, const Buffer& buffer, ReceiveHandler handler, int remainingTimeout)
	{
		size_t received = ConcatenatePackets (boost::asio::buffer_cast<uint8_t *>(buffer), boost::asio::buffer_size(buffer));
		if (received > 0)
			handler (boost::system::error_code (), received);
		else if (ecode == boost::asio::error::operation_aborted)
		{
			// timeout not expired
			if (m_Status == eStreamStatusReset)
				handler (boost::asio::error::make_error_code (boost::asio::error::connection_reset), 0);
			else
				handler (boost::asio::error::make_error_code (boost::asio::error::operation_aborted), 0);
		}
		else
		{
			// timeout expired
			if (remainingTimeout <= 0)
				handler (boost::asio::error::make_error_code (boost::asio::error::timed_out), received);
			else
			{
				// itermediate iterrupt
				SendUpdatedLeaseSet (); // send our leaseset if applicable
				AsyncReceive (buffer, handler, remainingTimeout);
			}
		}
	}
}
}

#endif
