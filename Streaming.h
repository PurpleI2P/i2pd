#ifndef STREAMING_H__
#define STREAMING_H__

#include <inttypes.h>
#include <string>
#include <map>
#include <set>
#include <queue>
#include <functional>
#include <boost/asio.hpp>
#include <boost/bind.hpp>
#include "I2PEndian.h"
#include "Identity.h"
#include "LeaseSet.h"
#include "I2NPProtocol.h"
#include "Garlic.h"
#include "Tunnel.h"

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
	const int RESEND_TIMEOUT = 10; // in seconds
	const int ACK_SEND_TIMEOUT = 200; // in milliseconds
	const int MAX_NUM_RESEND_ATTEMPTS = 5;	
	
	struct Packet
	{
		uint8_t buf[MAX_PACKET_SIZE];	
		size_t len, offset;
		int numResendAttempts;
		
		Packet (): len (0), offset (0), numResendAttempts (0) {};
		uint8_t * GetBuffer () { return buf + offset; };
		size_t GetLength () const { return len - offset; };

		uint32_t GetSendStreamID () const { return be32toh (*(uint32_t *)buf); };
		uint32_t GetReceiveStreamID () const { return be32toh (*(uint32_t *)(buf + 4)); };
		uint32_t GetSeqn () const { return be32toh (*(uint32_t *)(buf + 8)); };
		uint32_t GetAckThrough () const { return be32toh (*(uint32_t *)(buf + 12)); };
		uint8_t GetNACKCount () const { return buf[16]; };
		uint32_t GetNACK (int i) const { return be32toh (((uint32_t *)(buf + 17))[i]); };
		const uint8_t * GetOption () const { return buf + 17 + GetNACKCount ()*4 + 3; }; // 3 = resendDelay + flags
		uint16_t GetFlags () const { return be16toh (*(uint16_t *)(GetOption () - 2)); };
		uint16_t GetOptionSize () const { return be16toh (*(uint16_t *)GetOption ()); };
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
	
	class StreamingDestination;
	class Stream
	{	
		public:

			Stream (boost::asio::io_service& service, StreamingDestination& local, 
				const i2p::data::LeaseSet& remote, int port = 0); // outgoing
			Stream (boost::asio::io_service& service, StreamingDestination& local); // incoming			

			~Stream ();
			uint32_t GetSendStreamID () const { return m_SendStreamID; };
			uint32_t GetRecvStreamID () const { return m_RecvStreamID; };
			const i2p::data::LeaseSet * GetRemoteLeaseSet () const { return m_RemoteLeaseSet; };
			const i2p::data::IdentityEx& GetRemoteIdentity () const { return m_RemoteIdentity; };
			bool IsOpen () const { return m_IsOpen; };
			bool IsEstablished () const { return m_SendStreamID; };
			StreamingDestination& GetLocalDestination () { return m_LocalDestination; };
			
			void HandleNextPacket (Packet * packet);
			size_t Send (const uint8_t * buf, size_t len);
			
			template<typename Buffer, typename ReceiveHandler>
			void AsyncReceive (const Buffer& buffer, ReceiveHandler handler, int timeout = 0);

			void Close ();

			size_t GetNumSentBytes () const { return m_NumSentBytes; };
			size_t GetNumReceivedBytes () const { return m_NumReceivedBytes; };
			size_t GetSendQueueSize () const { return m_SentPackets.size (); };
			size_t GetReceiveQueueSize () const { return m_ReceiveQueue.size (); };
			
		private:

			void SendQuickAck ();
			bool SendPacket (Packet * packet);
			void SendPackets (const std::vector<Packet *>& packets);

			void SavePacket (Packet * packet);
			void ProcessPacket (Packet * packet);
			void ProcessAck (Packet * packet);
			size_t ConcatenatePackets (uint8_t * buf, size_t len);

			void UpdateCurrentRemoteLease ();
			
			template<typename Buffer, typename ReceiveHandler>
			void HandleReceiveTimer (const boost::system::error_code& ecode, const Buffer& buffer, ReceiveHandler handler);

			void ScheduleResend ();
			void HandleResendTimer (const boost::system::error_code& ecode);
			void HandleAckSendTimer (const boost::system::error_code& ecode);

			I2NPMessage * CreateDataMessage (const uint8_t * payload, size_t len);
			
		private:

			boost::asio::io_service& m_Service;
			uint32_t m_SendStreamID, m_RecvStreamID, m_SequenceNumber;
			int32_t m_LastReceivedSequenceNumber;
			bool m_IsOpen, m_IsReset, m_IsAckSendScheduled;
			StreamingDestination& m_LocalDestination;
			i2p::data::IdentityEx m_RemoteIdentity;
			const i2p::data::LeaseSet * m_RemoteLeaseSet;
			i2p::garlic::GarlicRoutingSession * m_RoutingSession;
			i2p::data::Lease m_CurrentRemoteLease;
			std::queue<Packet *> m_ReceiveQueue;
			std::set<Packet *, PacketCmp> m_SavedPackets;
			std::set<Packet *, PacketCmp> m_SentPackets;
			boost::asio::deadline_timer m_ReceiveTimer, m_ResendTimer, m_AckSendTimer;
			size_t m_NumSentBytes, m_NumReceivedBytes;
			uint16_t m_Port;
	};

	class StreamingDestination
	{
		public:

			StreamingDestination (i2p::client::ClientDestination& owner): m_Owner (owner) {};
			~StreamingDestination () {};	

			void Start ();
			void Stop ();

			Stream * CreateNewOutgoingStream (const i2p::data::LeaseSet& remote, int port = 0);
			void DeleteStream (Stream * stream);			
			void SetAcceptor (const std::function<void (Stream *)>& acceptor) { m_Acceptor = acceptor; };
			void ResetAcceptor () { m_Acceptor = nullptr; };
			bool IsAcceptorSet () const { return m_Acceptor != nullptr; };	
			i2p::client::ClientDestination& GetOwner () { return m_Owner; };

			void HandleDataMessagePayload (const uint8_t * buf, size_t len);

		private:		
	
			void HandleNextPacket (Packet * packet);
			Stream * CreateNewIncomingStream ();

		private:

			i2p::client::ClientDestination& m_Owner;
			std::mutex m_StreamsMutex;
			std::map<uint32_t, Stream *> m_Streams;
			std::function<void (Stream *)> m_Acceptor;
			
		public:

			// for HTTP only
			const decltype(m_Streams)& GetStreams () const { return m_Streams; };
	};		

	void DeleteStream (Stream * stream);

//-------------------------------------------------

	template<typename Buffer, typename ReceiveHandler>
	void Stream::AsyncReceive (const Buffer& buffer, ReceiveHandler handler, int timeout)
	{
		if (!m_ReceiveQueue.empty ())
		{
			m_Service.post ([=](void) { this->HandleReceiveTimer (
				boost::asio::error::make_error_code (boost::asio::error::operation_aborted),
				buffer, handler); });
		}
		else
		{
			m_ReceiveTimer.expires_from_now (boost::posix_time::seconds(timeout));
			m_ReceiveTimer.async_wait ([=](const boost::system::error_code& ecode)
				{ this->HandleReceiveTimer (ecode, buffer, handler); });
		}
	}

	template<typename Buffer, typename ReceiveHandler>
	void Stream::HandleReceiveTimer (const boost::system::error_code& ecode, const Buffer& buffer, ReceiveHandler handler)
	{
		size_t received = ConcatenatePackets (boost::asio::buffer_cast<uint8_t *>(buffer), boost::asio::buffer_size(buffer));
		if (ecode == boost::asio::error::operation_aborted)
		{	
			// timeout not expired	
			if (m_IsOpen)
				// no error
				handler (boost::system::error_code (), received); 
			else
				// socket closed
				handler (m_IsReset ? boost::asio::error::make_error_code (boost::asio::error::connection_reset) :
					boost::asio::error::make_error_code (boost::asio::error::operation_aborted), 0);
		}	
		else
			// timeout expired
			handler (boost::asio::error::make_error_code (boost::asio::error::timed_out), received);
	}
}		
}	

#endif
