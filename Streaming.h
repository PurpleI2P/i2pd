#ifndef STREAMING_H__
#define STREAMING_H__

#include <inttypes.h>
#include <string>
#include <map>
#include <set>
#include <queue>
#include <thread>
#include <functional>
#include <boost/asio.hpp>
#include <boost/bind.hpp>
#include <cryptopp/dsa.h>
#include "I2PEndian.h"
#include "Identity.h"
#include "LeaseSet.h"
#include "I2NPProtocol.h"
#include "TunnelPool.h"

namespace i2p
{
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
	
	struct Packet
	{
		uint8_t buf[MAX_PACKET_SIZE];	
		size_t len, offset;

		Packet (): len (0), offset (0) {};
		uint8_t * GetBuffer () { return buf + offset; };
		size_t GetLength () const { return len - offset; };

		uint32_t GetSendStreamID () const { return be32toh (*(uint32_t *)buf); };
		uint32_t GetReceiveStreamID () const { return be32toh (*(uint32_t *)(buf + 4)); };
		uint32_t GetSeqn () const { return be32toh (*(uint32_t *)(buf + 8)); };
		uint32_t GetAckThrough () const { return be32toh (*(uint32_t *)(buf + 12)); };
		uint8_t GetNACKCount () const { return buf[16]; };
		const uint8_t * GetOption () const { return buf + 17 + GetNACKCount ()*4 + 3; }; // 3 = resendDelay + flags
		uint16_t GetFlags () const { return be16toh (*(uint16_t *)(GetOption () - 2)); };
		uint16_t GetOptionSize () const { return be16toh (*(uint16_t *)GetOption ()); };
		const uint8_t * GetOptionData () const { return GetOption () + 2; };
		const uint8_t * GetPayload () const { return GetOptionData () + GetOptionSize (); };

		bool IsSYN () const { return GetFlags () & PACKET_FLAG_SYNCHRONIZE; };
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

			Stream (boost::asio::io_service& service, StreamingDestination * local, const i2p::data::LeaseSet& remote); // outgoing
			Stream (boost::asio::io_service& service, StreamingDestination * local); // incoming			

			~Stream ();
			uint32_t GetSendStreamID () const { return m_SendStreamID; };
			uint32_t GetRecvStreamID () const { return m_RecvStreamID; };
			const i2p::data::LeaseSet * GetRemoteLeaseSet () const { return m_RemoteLeaseSet; };
			bool IsOpen () const { return m_IsOpen; };
			bool IsEstablished () const { return m_SendStreamID; };
			StreamingDestination * GetLocalDestination () { return m_LocalDestination; };
			
			void HandleNextPacket (Packet * packet);
			size_t Send (const uint8_t * buf, size_t len, int timeout); // timeout in seconds
			
			template<typename Buffer, typename ReceiveHandler>
			void AsyncReceive (const Buffer& buffer, ReceiveHandler handler, int timeout = 0);

			void Close ();

			void SetLeaseSetUpdated () { m_LeaseSetUpdated = true; };
	
		private:

			void SendQuickAck ();
			bool SendPacket (Packet * packet);
			bool SendPacket (const uint8_t * buf, size_t len);

			void SavePacket (Packet * packet);
			void ProcessPacket (Packet * packet);
			size_t ConcatenatePackets (uint8_t * buf, size_t len);

			void UpdateCurrentRemoteLease ();
			
			template<typename Buffer, typename ReceiveHandler>
			void HandleReceiveTimer (const boost::system::error_code& ecode, const Buffer& buffer, ReceiveHandler handler);

		private:

			boost::asio::io_service& m_Service;
			uint32_t m_SendStreamID, m_RecvStreamID, m_SequenceNumber;
			int32_t m_LastReceivedSequenceNumber;
			bool m_IsOpen, m_LeaseSetUpdated;
			StreamingDestination * m_LocalDestination;
			i2p::data::Identity m_RemoteIdentity;
			const i2p::data::LeaseSet * m_RemoteLeaseSet;
			i2p::data::Lease m_CurrentRemoteLease;
			std::queue<Packet *> m_ReceiveQueue;
			std::set<Packet *, PacketCmp> m_SavedPackets;
			boost::asio::deadline_timer m_ReceiveTimer;
	};
	
	class StreamingDestination: public i2p::data::LocalDestination 
	{
		public:

			StreamingDestination (boost::asio::io_service& service);
			StreamingDestination (boost::asio::io_service& service, const std::string& fullPath);
			~StreamingDestination ();	

			const i2p::data::PrivateKeys& GetKeys () const { return m_Keys; };
			I2NPMessage * GetLeaseSetMsg ();
			const i2p::data::LeaseSet * GetLeaseSet ();
			i2p::tunnel::TunnelPool * GetTunnelPool () const  { return m_Pool; };			

			Stream * CreateNewOutgoingStream (const i2p::data::LeaseSet& remote);
			void DeleteStream (Stream * stream);			
			void SetAcceptor (const std::function<void (Stream *)>& acceptor) { m_Acceptor = acceptor; };
			void HandleNextPacket (Packet * packet);

			// implements LocalDestination
			const i2p::data::IdentHash& GetIdentHash () const { return m_IdentHash; };
			const i2p::data::Identity& GetIdentity () const { return m_Keys.pub; };
			const uint8_t * GetEncryptionPrivateKey () const { return m_EncryptionPrivateKey; };
			const uint8_t * GetEncryptionPublicKey () const { return m_EncryptionPublicKey; };
			void Sign (const uint8_t * buf, int len, uint8_t * signature) const;

		private:		
	
			Stream * CreateNewIncomingStream ();

		private:

			boost::asio::io_service& m_Service;
			std::map<uint32_t, Stream *> m_Streams;
			i2p::data::PrivateKeys m_Keys;
			i2p::data::IdentHash m_IdentHash;
			uint8_t m_EncryptionPublicKey[256], m_EncryptionPrivateKey[256];
			
			i2p::tunnel::TunnelPool * m_Pool;
			i2p::data::LeaseSet * m_LeaseSet;
			
			CryptoPP::DSA::PrivateKey m_SigningPrivateKey;
			std::function<void (Stream *)> m_Acceptor;
	};	

	class StreamingDestinations
	{
		public:

			StreamingDestinations (): m_IsRunning (false), m_Thread (nullptr), 
				m_Work (m_Service), m_SharedLocalDestination (nullptr) {};
			~StreamingDestinations () {};

			void Start ();
			void Stop ();

			void HandleNextPacket (i2p::data::IdentHash destination, Packet * packet);

			Stream * CreateClientStream (const i2p::data::LeaseSet& remote);
			void DeleteStream (Stream * stream);
			StreamingDestination * GetSharedLocalDestination () const { return m_SharedLocalDestination; };
			
		private:	

			void Run ();
			void LoadLocalDestinations ();
			void PostNextPacket (i2p::data::IdentHash destination, Packet * packet); 
			
		private:

			bool m_IsRunning;
			std::thread * m_Thread;	
			boost::asio::io_service m_Service;
			boost::asio::io_service::work m_Work;

			std::map<i2p::data::IdentHash, StreamingDestination *> m_Destinations;
			StreamingDestination * m_SharedLocalDestination;	
	};	
	
	Stream * CreateStream (const i2p::data::LeaseSet& remote);
	void DeleteStream (Stream * stream);
	void StartStreaming ();
	void StopStreaming ();
	StreamingDestination * GetSharedLocalDestination ();
	
	// assuming data is I2CP message
	void HandleDataMessage (i2p::data::IdentHash destination, const uint8_t * buf, size_t len);
	I2NPMessage * CreateDataMessage (Stream * s, const uint8_t * payload, size_t len);

//-------------------------------------------------

	template<typename Buffer, typename ReceiveHandler>
	void Stream::AsyncReceive (const Buffer& buffer, ReceiveHandler handler, int timeout)
	{
		if (!m_ReceiveQueue.empty ())
		{
			size_t received = ConcatenatePackets (boost::asio::buffer_cast<uint8_t *>(buffer), 					boost::asio::buffer_size(buffer));
			if (received)
			{
				// TODO: post to stream's thread
				handler (boost::system::error_code (), received);
				return;
			}	
		}
		if (!m_IsOpen)
		{
			handler (boost::asio::error::make_error_code (boost::asio::error::connection_reset), 0);
			return;
		}
		m_ReceiveTimer.expires_from_now (boost::posix_time::seconds(timeout));
		m_ReceiveTimer.async_wait ([=](const boost::system::error_code& ecode)
			{ this->HandleReceiveTimer (ecode, buffer, handler); });
	}

	template<typename Buffer, typename ReceiveHandler>
	void Stream::HandleReceiveTimer (const boost::system::error_code& ecode, const Buffer& buffer, ReceiveHandler handler)
	{
		size_t received = ConcatenatePackets (boost::asio::buffer_cast<uint8_t *>(buffer), boost::asio::buffer_size(buffer));
		if (ecode == boost::asio::error::operation_aborted)
			// timeout not expired	
			handler (boost::system::error_code (), received);
		else
			// timeout expired
			handler (boost::asio::error::make_error_code (boost::asio::error::timed_out), received);
	}
}		
}	

#endif
