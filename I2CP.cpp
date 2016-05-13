#include <string.h>
#include "I2PEndian.h"
#include "Log.h"
#include "I2CP.h"


namespace i2p
{
namespace client
{
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

	void I2CPSession::GetDateMessageHandler (const uint8_t * buf, size_t len)
	{
	}

	I2CPServer::I2CPServer (const std::string& interface, int port)
	{
		memset (m_MessagesHandlers, 0, sizeof (m_MessagesHandlers));
		m_MessagesHandlers[I2CP_GET_DATE_MESSAGE] = &I2CPSession::GetDateMessageHandler;	
	}
}
}

