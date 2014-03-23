#ifndef STREAMING_H__
#define STREAMING_H__

#include <inttypes.h>
#include <string>
#include <map>
#include <set>
#include <cryptopp/dsa.h>
#include "I2PEndian.h"
#include "Queue.h"
#include "Identity.h"
#include "LeaseSet.h"
#include "I2NPProtocol.h"
#include "Tunnel.h"
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
	const size_t MAX_PACKET_SIZE = 1754;

	struct Packet
	{
		uint8_t buf[1754];	
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

			Stream (StreamingDestination * local, const i2p::data::LeaseSet& remote);
			~Stream ();
			uint32_t GetSendStreamID () const { return m_SendStreamID; };
			uint32_t GetRecvStreamID () const { return m_RecvStreamID; };
			const i2p::data::LeaseSet& GetRemoteLeaseSet () const { return m_RemoteLeaseSet; };
			bool IsOpen () const { return m_IsOpen; };
			bool IsEstablished () const { return m_SendStreamID; };
			
			void HandleNextPacket (Packet * packet);
			size_t Send (uint8_t * buf, size_t len, int timeout); // timeout in seconds
			size_t Receive (uint8_t * buf, size_t len, int timeout = 0); // returns 0 if timeout expired
			void Close ();

			void SetLeaseSetUpdated () { m_LeaseSetUpdated = true; };
			
		private:

			void ConnectAndSend (uint8_t * buf, size_t len);
			void SendQuickAck ();
			bool SendPacket (uint8_t * packet, size_t size);

			void SavePacket (Packet * packet);
			void ProcessPacket (Packet * packet);

			void UpdateCurrentRemoteLease ();
			
		private:

			uint32_t m_SendStreamID, m_RecvStreamID, m_SequenceNumber, m_LastReceivedSequenceNumber;
			bool m_IsOpen, m_LeaseSetUpdated;
			StreamingDestination * m_LocalDestination;
			const i2p::data::LeaseSet& m_RemoteLeaseSet;
			i2p::data::Lease m_CurrentRemoteLease;
			i2p::util::Queue<Packet> m_ReceiveQueue;
			std::set<Packet *, PacketCmp> m_SavedPackets;
			i2p::tunnel::OutboundTunnel * m_OutboundTunnel;
	};
	
	class StreamingDestination: public i2p::data::LocalDestination 
	{
		public:

			StreamingDestination ();
			StreamingDestination (const std::string& fullPath);
			~StreamingDestination ();	

			const i2p::data::PrivateKeys& GetKeys () const { return m_Keys; };
			const i2p::data::Identity& GetIdentity () const { return m_Keys.pub; }; 
			const I2NPMessage * GetLeaseSet ();
			i2p::tunnel::TunnelPool * GetTunnelPool () const  { return m_Pool; };
			void Sign (uint8_t * buf, int len, uint8_t * signature) const;			

			Stream * CreateNewStream (const i2p::data::LeaseSet& remote);
			void DeleteStream (Stream * stream);
			void HandleNextPacket (Packet * packet);

			// implements LocalDestination
			void UpdateLeaseSet ();
			
		private:

			I2NPMessage * CreateLeaseSet () const;
			
		private:

			std::map<uint32_t, Stream *> m_Streams;
			i2p::data::PrivateKeys m_Keys;
			i2p::data::IdentHash m_IdentHash;

			i2p::tunnel::TunnelPool * m_Pool;
			I2NPMessage * m_LeaseSet;
			
			CryptoPP::DSA::PrivateKey m_SigningPrivateKey;
	};	

	Stream * CreateStream (const i2p::data::LeaseSet& remote);
	void DeleteStream (Stream * stream);
	void StartStreaming ();
	void StopStreaming ();
	
	// assuming data is I2CP message
	void HandleDataMessage (i2p::data::IdentHash * destination, const uint8_t * buf, size_t len);
	I2NPMessage * CreateDataMessage (Stream * s, uint8_t * payload, size_t len);
}		
}	

#endif
