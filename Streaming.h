#ifndef STREAMING_H__
#define STREAMING_H__

#include <inttypes.h>
#include <map>
#include <cryptopp/dsa.h>
#include "Identity.h"
#include "LeaseSet.h"
#include "I2NPProtocol.h"

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
		
	class StreamingDestination;
	class Stream
	{	
		public:

			Stream (StreamingDestination * local, const i2p::data::LeaseSet * remote);
			uint32_t GetSendStreamID () const { return m_SendStreamID; };
			uint32_t GetRecvStreamID () const { return m_RecvStreamID; };
			const i2p::data::LeaseSet * GetRemoteLeaseSet () const { return m_RemoteLeaseSet; };
			bool IsEstablished () const { return !m_SendStreamID; };
			
			void HandleNextPacket (const uint8_t * buf, size_t len);
			size_t Send (uint8_t * buf, size_t len, int timeout); // timeout in seconds
			
		private:

			uint32_t m_SendStreamID, m_RecvStreamID, m_SequenceNumber;
			StreamingDestination * m_LocalDestination;
			const i2p::data::LeaseSet * m_RemoteLeaseSet;
	};
	
	class StreamingDestination
	{
		public:

			StreamingDestination ();

			const i2p::data::Keys& GetKeys () const { return m_Keys; };
			const i2p::data::Identity& GetIdentity () const { return m_Identity; }; 
			I2NPMessage * CreateLeaseSet () const;
			void Sign (uint8_t * buf, int len, uint8_t * signature) const;
			
			Stream * CreateNewStream (const i2p::data::LeaseSet * remote);
			void DeleteStream (Stream * stream);
			void HandleNextPacket (const uint8_t * buf, size_t len);
			
		private:

			std::map<uint32_t, Stream *> m_Streams;
			i2p::data::Keys m_Keys;
			i2p::data::Identity m_Identity;
			i2p::data::IdentHash m_IdentHash;

			CryptoPP::DSA::PrivateKey m_SigningPrivateKey;
	};	

	Stream * CreateStream (const i2p::data::LeaseSet * remote);
	void CloseStream (Stream * stream);
	
	// assuming data is I2CP message
	void HandleDataMessage (i2p::data::IdentHash * destination, const uint8_t * buf, size_t len);
	I2NPMessage * CreateDataMessage (Stream * s, uint8_t * payload, size_t len);
}		
}	

#endif
