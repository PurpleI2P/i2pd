#include <string.h>
#include <boost/bind.hpp>
#include "Log.h"
#include "RouterContext.h"
#include "hmac.h"
#include "SSU.h"

namespace i2p
{
namespace ssu
{

	SSUSession::SSUSession (SSUServer * server, const boost::asio::ip::udp::endpoint& remoteEndpoint,
		i2p::data::RouterInfo * router): m_Server (server), m_RemoteEndpoint (remoteEndpoint), 
		m_State (eSessionStateUnknown)
	{
	}

	void SSUSession::ProcessNextMessage (uint8_t * buf, size_t len)
	{
		switch (m_State)
		{
			case eSessionStateUnknown:
				// we assume session request
				ProcessSessionRequest (buf, len);
			break;
			default:
				LogPrint ("SSU state not implemented yet");
		}
	}

	void SSUSession::ProcessSessionRequest (uint8_t * buf, size_t len)
	{
		auto address = i2p::context.GetRouterInfo ().GetSSUAddress ();
		if (address)
		{
			// use intro key for verification and decryption
			if (Validate (buf, len, address->key))
			{
				m_State = eSessionStateRequestReceived;
				LogPrint ("Session request received");
				Decrypt (buf, len, address->key);
				// TODO:
			}
			else
				LogPrint ("MAC verifcation failed");	
		}
		else
			LogPrint ("SSU is not supported");
	}

	void SSUSession::Encrypt (uint8_t * buf, size_t len, uint8_t * aesKey, uint8_t * iv, uint8_t * macKey)
	{	
		if (len < sizeof (SSUHeader))
		{
			LogPrint ("Unexpected SSU packet length ", len);
			return;
		}
		SSUHeader * header = (SSUHeader *)buf;
		memcpy (header->iv, iv, 16);
		uint8_t * encrypted = &header->flag;
		uint16_t encryptedLen = len - (encrypted - buf);
		m_Encryption.SetKeyWithIV (aesKey, 32, iv);
		m_Encryption.ProcessData (encrypted, encrypted, encryptedLen);
		// assume actual buffer size is 18 (16 + 2) bytes more
		memcpy (buf + len, iv, 16);
		*(uint16_t *)(buf + len + 16) = htobe16 (encryptedLen);
		i2p::crypto::HMACMD5Digest (encrypted, encryptedLen + 18, macKey, header->mac);
	}

	void SSUSession::Decrypt (uint8_t * buf, size_t len, uint8_t * aesKey)
	{
		if (len < sizeof (SSUHeader))
		{
			LogPrint ("Unexpected SSU packet length ", len);
			return;
		}
		SSUHeader * header = (SSUHeader *)buf;
		uint8_t * encrypted = &header->flag;
		uint16_t encryptedLen = len - (encrypted - buf);	
		m_Decryption.SetKeyWithIV (aesKey, 32, header->iv);
		m_Decryption.ProcessData (encrypted, encrypted, encryptedLen);
	}

	bool SSUSession::Validate (uint8_t * buf, size_t len, uint8_t * macKey)
	{
		if (len < sizeof (SSUHeader))
		{
			LogPrint ("Unexpected SSU packet length ", len);
			return false;
		}
		SSUHeader * header = (SSUHeader *)buf;
		uint8_t * encrypted = &header->flag;
		uint16_t encryptedLen = len - (encrypted - buf);
		// assume actual buffer size is 18 (16 + 2) bytes more
		memcpy (buf + len, header->iv, 16);
		*(uint16_t *)(buf + len + 16) = htobe16 (encryptedLen);
		uint8_t digest[16];
		i2p::crypto::HMACMD5Digest (encrypted, encryptedLen + 18, macKey, digest);
		return !memcmp (header->mac, digest, 16);
	}

	SSUServer::SSUServer (boost::asio::io_service& service, int port):
		m_Socket (service, boost::asio::ip::udp::v4 (), port)
	{
	}
	
	SSUServer::~SSUServer ()
	{
		for (auto it: m_Sessions)
			delete it.second;
	}

	void SSUServer::Start ()
	{
		Receive ();
	}

	void SSUServer::Stop ()
	{
		m_Socket.close ();
	}

	void SSUServer::Send (uint8_t * buf, size_t len, const boost::asio::ip::udp::endpoint& to)
	{
		m_Socket.send_to (boost::asio::buffer (buf, len), to);
	}	

	void SSUServer::Receive ()
	{
		m_Socket.async_receive_from (boost::asio::buffer (m_ReceiveBuffer, SSU_MTU), m_SenderEndpoint,
			boost::bind (&SSUServer::HandleReceivedFrom, this, boost::asio::placeholders::error, boost::asio::placeholders::bytes_transferred)); 
	}

	void SSUServer::HandleReceivedFrom (const boost::system::error_code& ecode, std::size_t bytes_transferred)
	{
		if (!ecode)
		{
			LogPrint ("SSU received ", bytes_transferred, " bytes");
			SSUSession * session = nullptr;
			auto it = m_Sessions.find (m_SenderEndpoint);
			if (it != m_Sessions.end ())
				session = it->second;
			if (!session)
			{
				session = new SSUSession (this, m_SenderEndpoint);
				m_Sessions[m_SenderEndpoint] = session;
				LogPrint ("New SSU session from ", m_SenderEndpoint.address ().to_string (), ":", m_SenderEndpoint.port (), " created");
			}
			session->ProcessNextMessage (m_ReceiveBuffer, bytes_transferred);
			Receive ();
		}
		else
			LogPrint ("SSU receive error: ", ecode.message ());
	}

	SSUSession * SSUServer::GetSession (i2p::data::RouterInfo * router)
	{
		SSUSession * session = nullptr;
		if (router)
		{
			auto address = router->GetSSUAddress ();
			if (address)
			{
				boost::asio::ip::udp::endpoint remoteEndpoint (address->host, address->port);
				auto it = m_Sessions.find (remoteEndpoint);
				if (it != m_Sessions.end ())
					session = it->second;
				else
				{
					// otherwise create new session
					session = new SSUSession (this, remoteEndpoint, router);
					m_Sessions[remoteEndpoint] = session;
					LogPrint ("New SSU session to [", router->GetIdentHashAbbreviation (), "] ",
						remoteEndpoint.address ().to_string (), ":", remoteEndpoint.port (), " created");
				}
			}
			else
				LogPrint ("Router ", router->GetIdentHashAbbreviation (), " doesn't have SSU address");
		}
		return session;
	}
}
}

