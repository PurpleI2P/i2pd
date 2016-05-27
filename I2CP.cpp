#include <string.h>
#include "I2PEndian.h"
#include "Log.h"
#include "Timestamp.h"
#include "I2CP.h"

namespace i2p
{
namespace client
{

	I2CPDestination::I2CPDestination (I2CPSession& owner, std::shared_ptr<const i2p::data::IdentityEx> identity, bool isPublic): 
		LeaseSetDestination (isPublic), m_Owner (owner), m_Identity (identity) 
	{
	}

	I2CPSession::I2CPSession (I2CPServer& owner, std::shared_ptr<boost::asio::ip::tcp::socket> socket):
		m_Owner (owner), m_Socket (socket), 
		m_NextMessage (nullptr), m_NextMessageLen (0), m_NextMessageOffset (0)
	{
		ReadProtocolByte ();
	}

	I2CPSession::~I2CPSession ()
	{
		delete[] m_NextMessage;
	}

	void I2CPSession::ReadProtocolByte ()
	{
		if (m_Socket)
		{
			auto s = shared_from_this ();	
			m_Socket->async_read_some (boost::asio::buffer (m_Buffer, 1), 
				[s](const boost::system::error_code& ecode, std::size_t bytes_transferred)
				    {
						if (!ecode && bytes_transferred > 0 && s->m_Buffer[0] == I2CP_PRTOCOL_BYTE)
							s->Receive ();
						else
							s->Terminate ();
					});
		}
	}

	void I2CPSession::Receive ()
	{
		m_Socket->async_read_some (boost::asio::buffer (m_Buffer, I2CP_SESSION_BUFFER_SIZE),
			std::bind (&I2CPSession::HandleReceived, shared_from_this (), std::placeholders::_1, std::placeholders::_2));
	}

	void I2CPSession::HandleReceived (const boost::system::error_code& ecode, std::size_t bytes_transferred)
	{
		if (ecode)
			Terminate ();
		else
		{
			size_t offset = 0;
			if (m_NextMessage)
			{
				if (m_NextMessageOffset + bytes_transferred <= m_NextMessageLen)
				{
					memcpy (m_NextMessage + m_NextMessageOffset, m_Buffer, bytes_transferred);
					m_NextMessageOffset += bytes_transferred;
				}	
				else
				{
					offset = m_NextMessageLen - m_NextMessageOffset;
					memcpy (m_NextMessage + m_NextMessageOffset, m_Buffer, offset);
					HandleNextMessage (m_NextMessage);
					delete[] m_NextMessage;
				}
			}	
			while (offset < bytes_transferred)
			{
				auto msgLen = bufbe32toh (m_Buffer + offset + I2CP_HEADER_LENGTH_OFFSET) + I2CP_HEADER_SIZE;
				if (msgLen <= bytes_transferred - offset)
				{
					HandleNextMessage (m_Buffer + offset);
					offset += msgLen;	
				}
				else
				{
					m_NextMessageLen = msgLen;
					m_NextMessageOffset = bytes_transferred - offset;
					m_NextMessage = new uint8_t[m_NextMessageLen];
					memcpy (m_NextMessage, m_Buffer + offset, m_NextMessageOffset);
					offset = bytes_transferred;
				}	
			}	
			Receive ();
		}
	}

	void I2CPSession::HandleNextMessage (const uint8_t * buf)
	{
		auto handler = m_Owner.GetMessagesHandlers ()[buf[I2CP_HEADER_TYPE_OFFSET]];
		if (handler)
			(this->*handler)(buf + I2CP_HEADER_SIZE, bufbe32toh (buf + I2CP_HEADER_LENGTH_OFFSET));
		else
			LogPrint (eLogError, "I2CP: Unknown I2CP messsage ", (int)buf[I2CP_HEADER_TYPE_OFFSET]);
	}

	void I2CPSession::Terminate ()
	{
	}

	void I2CPSession::SendI2CPMessage (uint8_t type, const uint8_t * payload, size_t len)
	{
		auto l = len + I2CP_HEADER_SIZE;
		uint8_t * buf = new uint8_t[l];
		htobe32buf (buf + I2CP_HEADER_LENGTH_OFFSET, len);
		buf[I2CP_HEADER_TYPE_OFFSET] = type;
		memcpy (buf + I2CP_HEADER_SIZE, payload, len);
		boost::asio::async_write (*m_Socket, boost::asio::buffer (buf, l), boost::asio::transfer_all (),
        	std::bind(&I2CPSession::HandleI2CPMessageSent, shared_from_this (), 
						std::placeholders::_1, std::placeholders::_2, buf));			
	}

	void I2CPSession::HandleI2CPMessageSent (const boost::system::error_code& ecode, std::size_t bytes_transferred, const uint8_t * buf)
	{
		delete[] buf;
		if (ecode && ecode != boost::asio::error::operation_aborted)
			Terminate ();
	}

	std::string I2CPSession::ExtractString (const uint8_t * buf, size_t len)
	{
		uint8_t l = buf[0];
		if (l > len) l = len;
		return std::string ((const char *)buf, l);
	}

	size_t I2CPSession::PutString (uint8_t * buf, size_t len, const std::string& str)
	{
		auto l = str.length ();
		if (l + 1 >= len) l = len - 1;
		if (l > 255) l = 255; // 1 byte max
		buf[0] = l;
		memcpy (buf + 1, str.c_str (), l);	
		return l + 1;
	}

	void I2CPSession::GetDateMessageHandler (const uint8_t * buf, size_t len)
	{
		// get version
		auto version = ExtractString (buf, len);
		auto l = version.length () + 1 + 8;
		uint8_t * payload = new uint8_t[l];
		// set date
		auto ts = i2p::util::GetMillisecondsSinceEpoch ();
		htobe64buf (payload, ts);
		// echo vesrion back
		PutString (payload + 8, l - 8, version);
		SendI2CPMessage (I2CP_SET_DATE_MESSAGE, payload, l); 
	}

	void I2CPSession::CreateSessionMessageHandler (const uint8_t * buf, size_t len)
	{
		// TODO
		m_Destination = std::make_shared<I2CPDestination>(*this, nullptr, false);
	}

	I2CPServer::I2CPServer (const std::string& interface, int port)
	{
		memset (m_MessagesHandlers, 0, sizeof (m_MessagesHandlers));
		m_MessagesHandlers[I2CP_GET_DATE_MESSAGE] = &I2CPSession::GetDateMessageHandler;
		m_MessagesHandlers[I2CP_CREATE_SESSION_MESSAGE ] = &I2CPSession::CreateSessionMessageHandler;	
	}
}
}

