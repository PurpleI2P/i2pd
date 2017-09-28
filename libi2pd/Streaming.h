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

	const size_t STREAMING_MTU = 1730;
	const size_t MAX_PACKET_SIZE = 4096;
	const size_t COMPRESSION_THRESHOLD_SIZE = 66;	
	const int ACK_SEND_TIMEOUT = 200; // in milliseconds
	const int MAX_NUM_RESEND_ATTEMPTS = 6;	
	const int WINDOW_SIZE = 6; // in messages
	const int MIN_WINDOW_SIZE = 1;
	const int MAX_WINDOW_SIZE = 128;		
	const int INITIAL_RTT = 8000; // in milliseconds
	const int INITIAL_RTO = 9000; // in milliseconds
	const size_t MAX_PENDING_INCOMING_BACKLOG = 128;
	const int PENDING_INCOMING_TIMEOUT = 10; // in seconds
	const int MAX_RECEIVE_TIMEOUT = 30; // in seconds 

	/** i2cp option for limiting inbound stremaing connections */
	const char I2CP_PARAM_STREAMING_MAX_CONNS_PER_MIN[] = "maxconns";
	/** default maximum connections attempts per minute per destination */
	const uint32_t DEFAULT_MAX_CONNS_PER_MIN = 600;

	/** 
	 * max banned destinations per local destination
	 * TODO: make configurable
	 */
	const uint16_t MAX_BANNED_CONNS = 9999;
	/** 
	 * length of a ban in ms
	 * TODO: make configurable 
	 */
	const uint64_t DEFAULT_BAN_INTERVAL = 60 * 60 * 1000;
	
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
			size_t Send (const uint8_t * buf, size_t len);
			void AsyncSend (const uint8_t * buf, size_t len, SendHandler handler);
			
			template<typename Buffer, typename ReceiveHandler>
			void AsyncReceive (const Buffer& buffer, ReceiveHandler handler, int timeout = 0);
			size_t ReadSome (uint8_t * buf, size_t len) { return ConcatenatePackets (buf, len); };
			
			void Close ();
			void Cancel () { m_ReceiveTimer.cancel (); };

			size_t GetNumSentBytes () const { return m_NumSentBytes; };
			size_t GetNumReceivedBytes () const { return m_NumReceivedBytes; };
			size_t GetSendQueueSize () const { return m_SentPackets.size (); };
			size_t GetReceiveQueueSize () const { return m_ReceiveQueue.size (); };
			size_t GetSendBufferSize () const { return m_SendBuffer.GetSize (); };
			int GetWindowSize () const { return m_WindowSize; };
			int GetRTT () const { return m_RTT; };

			/** don't call me */
			void Terminate ();
						
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
			int m_WindowSize, m_RTT, m_RTO;
			uint64_t m_LastWindowSizeIncreaseTime;
			int m_NumResendAttempts;
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
			void SetAcceptor (const Acceptor& acceptor);
			void ResetAcceptor ();
			bool IsAcceptorSet () const { return m_Acceptor != nullptr; };	
			void AcceptOnce (const Acceptor& acceptor);

			std::shared_ptr<i2p::client::ClientDestination> GetOwner () const { return m_Owner; };
			void SetOwner (std::shared_ptr<i2p::client::ClientDestination> owner) { m_Owner = owner; };
			uint16_t GetLocalPort () const { return m_LocalPort; };

			void HandleDataMessagePayload (const uint8_t * buf, size_t len);
			std::shared_ptr<I2NPMessage> CreateDataMessage (const uint8_t * payload, size_t len, uint16_t toPort);

			/** set max connections per minute per destination */
			void SetMaxConnsPerMinute(const uint32_t conns);

			Packet * NewPacket () { return m_PacketsPool.Acquire (); }
			void DeletePacket (Packet * p) { m_PacketsPool.Release (p); }
			
		private:		

			void AcceptOnceAcceptor (std::shared_ptr<Stream> stream, Acceptor acceptor, Acceptor prev);
			
			void HandleNextPacket (Packet * packet);
			std::shared_ptr<Stream> CreateNewIncomingStream ();
			void HandlePendingIncomingTimer (const boost::system::error_code& ecode);

			/** handle cleaning up connection tracking for ratelimits */
			void HandleConnTrack(const boost::system::error_code& ecode);

			bool DropNewStream(const i2p::data::IdentHash & ident);

			void ScheduleConnTrack();
      
		private:

			std::shared_ptr<i2p::client::ClientDestination> m_Owner;
			uint16_t m_LocalPort;
			bool m_Gzip; // gzip compression of data messages
			std::mutex m_StreamsMutex;
			std::map<uint32_t, std::shared_ptr<Stream> > m_Streams; // sendStreamID->stream
			Acceptor m_Acceptor;
			uint32_t m_LastIncomingReceiveStreamID;
			std::list<std::shared_ptr<Stream> > m_PendingIncomingStreams;
			boost::asio::deadline_timer m_PendingIncomingTimer;
			std::map<uint32_t, std::list<Packet *> > m_SavedPackets; // receiveStreamID->packets, arrived before SYN
      
			std::mutex m_ConnsMutex;
			/** how many connections per minute did each identity have */
			std::map<i2p::data::IdentHash, uint32_t> m_Conns;
			boost::asio::deadline_timer m_ConnTrackTimer;
			uint32_t m_ConnsPerMinute;
			/** banned identities */
			std::vector<i2p::data::IdentHash> m_Banned;
			uint64_t m_LastBanClear;

			i2p::util::MemoryPool<Packet> m_PacketsPool;
			
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
		m_Service.post ([=](void)
		{
			if (!m_ReceiveQueue.empty () || m_Status == eStreamStatusReset)
				s->HandleReceiveTimer (boost::asio::error::make_error_code (boost::asio::error::operation_aborted), buffer, handler, 0);
			else
			{
				int t = (timeout > MAX_RECEIVE_TIMEOUT) ?  MAX_RECEIVE_TIMEOUT : timeout;
				s->m_ReceiveTimer.expires_from_now (boost::posix_time::seconds(t));
				s->m_ReceiveTimer.async_wait ([=](const boost::system::error_code& ecode)
					{ s->HandleReceiveTimer (ecode, buffer, handler, timeout - t); });
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
