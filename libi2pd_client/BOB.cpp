/*
* Copyright (c) 2013-2020, The PurpleI2P Project
*
* This file is part of Purple i2pd project and licensed under BSD3
*
* See full license text in LICENSE file at top of project tree
*/

#include <string.h>
#include "Log.h"
#include "ClientContext.h"
#include "util.h"
#include "BOB.h"

namespace i2p
{
namespace client
{
	BOBI2PInboundTunnel::BOBI2PInboundTunnel (const boost::asio::ip::tcp::endpoint& ep, std::shared_ptr<ClientDestination> localDestination):
		BOBI2PTunnel (localDestination), m_Acceptor (localDestination->GetService (), ep)
	{
	}

	BOBI2PInboundTunnel::~BOBI2PInboundTunnel ()
	{
		Stop ();
	}

	void BOBI2PInboundTunnel::Start ()
	{
		m_Acceptor.listen ();
		Accept ();
	}

	void BOBI2PInboundTunnel::Stop ()
	{
		m_Acceptor.close();
		ClearHandlers ();
	}

	void BOBI2PInboundTunnel::Accept ()
	{
		auto receiver = std::make_shared<AddressReceiver> ();
		receiver->socket = std::make_shared<boost::asio::ip::tcp::socket> (GetService ());
		m_Acceptor.async_accept (*receiver->socket, std::bind (&BOBI2PInboundTunnel::HandleAccept, this,
			std::placeholders::_1, receiver));
	}

	void BOBI2PInboundTunnel::HandleAccept (const boost::system::error_code& ecode, std::shared_ptr<AddressReceiver> receiver)
	{
		if (!ecode)
		{
			Accept ();
			ReceiveAddress (receiver);
		}
	}

	void BOBI2PInboundTunnel::ReceiveAddress (std::shared_ptr<AddressReceiver> receiver)
	{
		receiver->socket->async_read_some (boost::asio::buffer(
			receiver->buffer + receiver->bufferOffset,
			BOB_COMMAND_BUFFER_SIZE - receiver->bufferOffset),
			std::bind(&BOBI2PInboundTunnel::HandleReceivedAddress, this,
			std::placeholders::_1, std::placeholders::_2, receiver));
	}

	void BOBI2PInboundTunnel::HandleReceivedAddress (const boost::system::error_code& ecode, std::size_t bytes_transferred,
		std::shared_ptr<AddressReceiver> receiver)
	{
		if (ecode)
			LogPrint (eLogError, "BOB: inbound tunnel read error: ", ecode.message ());
		else
		{
			receiver->bufferOffset += bytes_transferred;
			receiver->buffer[receiver->bufferOffset] = 0;
			char * eol = strchr (receiver->buffer, '\n');
			if (eol)
			{
				*eol = 0;
				if (eol != receiver->buffer && eol[-1] == '\r') eol[-1] = 0; // workaround for Transmission, it sends '\r\n' terminated address
				receiver->data = (uint8_t *)eol + 1;
				receiver->dataLen = receiver->bufferOffset - (eol - receiver->buffer + 1);
				auto addr = context.GetAddressBook ().GetAddress (receiver->buffer);
				if (!addr)
				{
					LogPrint (eLogError, "BOB: address ", receiver->buffer, " not found");
					return;
				}
				if (addr->IsIdentHash ())
				{
					auto leaseSet = GetLocalDestination ()->FindLeaseSet (addr->identHash);
					if (leaseSet)
						CreateConnection (receiver, leaseSet);
					else
						GetLocalDestination ()->RequestDestination (addr->identHash,
							std::bind (&BOBI2PInboundTunnel::HandleDestinationRequestComplete,
							this, std::placeholders::_1, receiver));
				}
				else
					GetLocalDestination ()->RequestDestinationWithEncryptedLeaseSet (addr->blindedPublicKey,
							std::bind (&BOBI2PInboundTunnel::HandleDestinationRequestComplete,
							this, std::placeholders::_1, receiver));
			}
			else
			{
				if (receiver->bufferOffset < BOB_COMMAND_BUFFER_SIZE)
					ReceiveAddress (receiver);
				else
					LogPrint (eLogError, "BOB: missing inbound address");
			}
		}
	}

	void BOBI2PInboundTunnel::HandleDestinationRequestComplete (std::shared_ptr<i2p::data::LeaseSet> leaseSet, std::shared_ptr<AddressReceiver> receiver)
	{
		if (leaseSet)
			CreateConnection (receiver, leaseSet);
		else
			LogPrint (eLogError, "BOB: LeaseSet for inbound destination not found");
	}

	void BOBI2PInboundTunnel::CreateConnection (std::shared_ptr<AddressReceiver> receiver, std::shared_ptr<const i2p::data::LeaseSet> leaseSet)
	{
		LogPrint (eLogDebug, "BOB: New inbound connection");
		auto connection = std::make_shared<I2PTunnelConnection>(this, receiver->socket, leaseSet);
		AddHandler (connection);
		connection->I2PConnect (receiver->data, receiver->dataLen);
	}

	BOBI2POutboundTunnel::BOBI2POutboundTunnel (const std::string& outhost, int port,
		std::shared_ptr<ClientDestination> localDestination, bool quiet): BOBI2PTunnel (localDestination),
		m_Endpoint (boost::asio::ip::address::from_string (outhost), port), m_IsQuiet (quiet)
	{
	}

	void BOBI2POutboundTunnel::Start ()
	{
		Accept ();
	}

	void BOBI2POutboundTunnel::Stop ()
	{
		ClearHandlers ();
	}

	void BOBI2POutboundTunnel::Accept ()
	{
		auto localDestination = GetLocalDestination ();
		if (localDestination)
			localDestination->AcceptStreams (std::bind (&BOBI2POutboundTunnel::HandleAccept, this, std::placeholders::_1));
		else
			LogPrint (eLogError, "BOB: Local destination not set for server tunnel");
	}

	void BOBI2POutboundTunnel::HandleAccept (std::shared_ptr<i2p::stream::Stream> stream)
	{
		if (stream)
		{
			auto conn = std::make_shared<I2PTunnelConnection> (this, stream, std::make_shared<boost::asio::ip::tcp::socket> (GetService ()), m_Endpoint, m_IsQuiet);
			AddHandler (conn);
			conn->Connect ();
		}
	}

	BOBDestination::BOBDestination (std::shared_ptr<ClientDestination> localDestination,
			const std::string &nickname, const std::string &inhost, const std::string &outhost,
			const int inport, const int outport, const bool quiet):
		m_LocalDestination (localDestination),
		m_OutboundTunnel (nullptr), m_InboundTunnel (nullptr),
		m_Nickname(nickname), m_InHost(inhost), m_OutHost(outhost),
		m_InPort(inport), m_OutPort(outport), m_Quiet(quiet)
	{
	}

	BOBDestination::~BOBDestination ()
	{
		delete m_OutboundTunnel;
		delete m_InboundTunnel;
		i2p::client::context.DeleteLocalDestination (m_LocalDestination);
	}

	void BOBDestination::Start ()
	{
		if (m_OutboundTunnel) m_OutboundTunnel->Start ();
		if (m_InboundTunnel) m_InboundTunnel->Start ();
	}

	void BOBDestination::Stop ()
	{
		StopTunnels ();
		m_LocalDestination->Stop ();
	}

	void BOBDestination::StopTunnels ()
	{
		if (m_OutboundTunnel)
		{
			m_OutboundTunnel->Stop ();
			delete m_OutboundTunnel;
			m_OutboundTunnel = nullptr;
		}
		if (m_InboundTunnel)
		{
			m_InboundTunnel->Stop ();
			delete m_InboundTunnel;
			m_InboundTunnel = nullptr;
		}
	}

	void BOBDestination::CreateInboundTunnel (int port, const std::string& inhost)
	{
		if (!m_InboundTunnel)
		{
			// update inport and inhost (user can stop tunnel and change)
			m_InPort = port;
			m_InHost = inhost;
			boost::asio::ip::tcp::endpoint ep(boost::asio::ip::tcp::v4(), port);
			if (!inhost.empty ())
			{
				boost::system::error_code ec;
				auto addr = boost::asio::ip::address::from_string (inhost, ec);
				if (!ec)
					ep.address (addr);
				else
					LogPrint (eLogError, "BOB: ", ec.message ());
			}
			m_InboundTunnel = new BOBI2PInboundTunnel (ep, m_LocalDestination);
		}
	}

	void BOBDestination::CreateOutboundTunnel (const std::string& outhost, int port, bool quiet)
	{
		if (!m_OutboundTunnel)
		{
			// update outport and outhost (user can stop tunnel and change)
			m_OutPort = port;
			m_OutHost = outhost;
			m_OutboundTunnel = new BOBI2POutboundTunnel (outhost, port, m_LocalDestination, quiet);
		}
	}

	BOBCommandSession::BOBCommandSession (BOBCommandChannel& owner):
		m_Owner (owner), m_Socket (m_Owner.GetService ()),
		m_ReceiveBuffer(BOB_COMMAND_BUFFER_SIZE + 1), m_SendBuffer(BOB_COMMAND_BUFFER_SIZE + 1),
		m_IsOpen (true), m_IsQuiet (false), m_IsActive (false),
		m_InPort (0), m_OutPort (0), m_CurrentDestination (nullptr)
	{
	}

	BOBCommandSession::~BOBCommandSession ()
	{
	}

	void BOBCommandSession::Terminate ()
	{
		m_Socket.close ();
		m_IsOpen = false;
	}

	void BOBCommandSession::Receive ()
	{
		boost::asio::async_read_until(m_Socket, m_ReceiveBuffer, '\n',
			std::bind(&BOBCommandSession::HandleReceivedLine, shared_from_this(),
				std::placeholders::_1, std::placeholders::_2));
	}

	void BOBCommandSession::HandleReceivedLine(const boost::system::error_code& ecode, std::size_t bytes_transferred)
	{
		if(ecode)
		{
			LogPrint (eLogError, "BOB: command channel read error: ", ecode.message());
			if (ecode != boost::asio::error::operation_aborted)
				Terminate ();
		}
		else
		{
			std::string line;

			std::istream is(&m_ReceiveBuffer);
			std::getline(is, line);

			std::string command, operand;
			std::istringstream iss(line);
			iss >> command >> operand;

			// process command
			auto& handlers = m_Owner.GetCommandHandlers();
			auto it = handlers.find(command);
			if(it != handlers.end())
			{
				(this->*(it->second))(operand.c_str(), operand.length());
			}
			else
			{
				LogPrint (eLogError, "BOB: unknown command ", command.c_str());
				SendReplyError ("unknown command");
			}
		}
	}

	void BOBCommandSession::Send ()
	{
		boost::asio::async_write (m_Socket, m_SendBuffer,
			boost::asio::transfer_all (),
			std::bind(&BOBCommandSession::HandleSent, shared_from_this (),
				std::placeholders::_1, std::placeholders::_2));
	}

	void BOBCommandSession::HandleSent (const boost::system::error_code& ecode, std::size_t bytes_transferred)
	{
		if (ecode)
		{
			LogPrint (eLogError, "BOB: command channel send error: ", ecode.message ());
			if (ecode != boost::asio::error::operation_aborted)
				Terminate ();
		}
		else
		{
			if (m_IsOpen)
				Receive ();
			else
				Terminate ();
		}
	}

	void BOBCommandSession::SendReplyOK (const char * msg)
	{
		std::ostream os(&m_SendBuffer);
		os << "OK";
		if(msg)
		{
			os << " " << msg;
		}
		os << std::endl;
		Send ();
	}

	void BOBCommandSession::SendReplyError (const char * msg)
	{
		std::ostream os(&m_SendBuffer);
		os << "ERROR " << msg << std::endl;
		Send ();
	}

	void BOBCommandSession::SendVersion ()
	{
		std::ostream os(&m_SendBuffer);
		os << "BOB 00.00.10" << std::endl;
		SendReplyOK();
	}

	void BOBCommandSession::SendRaw (const char * data)
	{
		std::ostream os(&m_SendBuffer);
		os << data << std::endl;
	}

	void BOBCommandSession::BuildStatusLine(bool currentTunnel, BOBDestination *dest, std::string &out)
	{
		// helper lambdas
		const auto issetStr = [](const std::string &str) { return str.empty() ? "not_set" : str; }; // for inhost, outhost
		const auto issetNum = [&issetStr](const int p) { return issetStr(p == 0 ? "" : std::to_string(p)); }; // for inport, outport
		const auto destExists = [](const BOBDestination * const dest) { return dest != nullptr; };
		const auto destReady = [](const BOBDestination * const dest) { return dest->GetLocalDestination()->IsReady(); };
		const auto bool_str = [](const bool v) { return v ? "true" : "false"; }; // bool -> str

		// tunnel info
		const std::string nickname = currentTunnel ? m_Nickname : dest->GetNickname();
		const bool quiet = currentTunnel ? m_IsQuiet : dest->GetQuiet();
		const std::string inhost = issetStr(currentTunnel ? m_InHost : dest->GetInHost());
		const std::string outhost = issetStr(currentTunnel ? m_OutHost : dest->GetOutHost());
		const std::string inport = issetNum(currentTunnel ? m_InPort : dest->GetInPort());
		const std::string outport = issetNum(currentTunnel ? m_OutPort : dest->GetOutPort());
		const bool keys = destExists(dest); // key must exist when destination is created
		const bool starting = destExists(dest) && !destReady(dest);
		const bool running = destExists(dest) && destReady(dest);
		const bool stopping = false;

		// build line
		std::stringstream ss;
		ss	<< "DATA "
			<< "NICKNAME: " << nickname          << " " << "STARTING: " << bool_str(starting) << " "
			<< "RUNNING: "  << bool_str(running) << " " << "STOPPING: " << bool_str(stopping) << " "
			<< "KEYS: "     << bool_str(keys)    << " " << "QUIET: "    << bool_str(quiet) << " "
			<< "INPORT: "   << inport            << " " << "INHOST: "   << inhost << " "
			<< "OUTPORT: "  << outport           << " " << "OUTHOST: "  << outhost;
		out = ss.str();
	}

	void BOBCommandSession::ZapCommandHandler (const char * operand, size_t len)
	{
		LogPrint (eLogDebug, "BOB: zap");
		Terminate ();
	}

	void BOBCommandSession::QuitCommandHandler (const char * operand, size_t len)
	{
		LogPrint (eLogDebug, "BOB: quit");
		m_IsOpen = false;
		SendReplyOK ("Bye!");
	}

	void BOBCommandSession::StartCommandHandler (const char * operand, size_t len)
	{
		LogPrint (eLogDebug, "BOB: start ", m_Nickname);
		if (m_IsActive)
		{
			SendReplyError ("tunnel is active");
			return;
		}
		if (!m_Keys.GetPublic ()) // keys are set ?
		{
			SendReplyError("Keys must be set.");
			return;
		}
		if (m_InPort == 0
			&& m_OutHost.empty() && m_OutPort == 0)
		{
			SendReplyError("(inhost):inport or outhost:outport must be set.");
			return;
		}
		if(!m_InHost.empty())
		{
			// TODO: FIXME: temporary validation, until hostname support is added
			boost::system::error_code ec;
			boost::asio::ip::address::from_string(m_InHost, ec);
			if (ec)
			{
				SendReplyError("inhost must be a valid IPv4 address.");
				return;
			}
		}
		if(!m_OutHost.empty())
		{
			// TODO: FIXME: temporary validation, until hostname support is added
			boost::system::error_code ec;
			boost::asio::ip::address::from_string(m_OutHost, ec);
			if (ec)
			{
				SendReplyError("outhost must be a IPv4 address.");
				return;
			}
		}

		if (!m_CurrentDestination)
		{
			m_CurrentDestination = new BOBDestination (i2p::client::context.CreateNewLocalDestination (m_Keys, true, &m_Options), // deleted in clear command
				m_Nickname, m_InHost, m_OutHost, m_InPort, m_OutPort, m_IsQuiet);
			m_Owner.AddDestination (m_Nickname, m_CurrentDestination);
		}
		if (m_InPort)
			m_CurrentDestination->CreateInboundTunnel (m_InPort, m_InHost);
		if (m_OutPort && !m_OutHost.empty ())
			m_CurrentDestination->CreateOutboundTunnel (m_OutHost, m_OutPort, m_IsQuiet);
		m_CurrentDestination->Start ();
		SendReplyOK ("Tunnel starting");
		m_IsActive = true;
	}

	void BOBCommandSession::StopCommandHandler (const char * operand, size_t len)
	{
		LogPrint (eLogDebug, "BOB: stop ", m_Nickname);
		if (!m_IsActive)
		{
			SendReplyError ("tunnel is inactive");
			return;
		}
		auto dest = m_Owner.FindDestination (m_Nickname);
		if (dest)
		{
			dest->StopTunnels ();
			SendReplyOK ("Tunnel stopping");
		}
		else
			SendReplyError ("tunnel not found");
		m_IsActive = false;
	}

	void BOBCommandSession::SetNickCommandHandler (const char * operand, size_t len)
	{
		LogPrint (eLogDebug, "BOB: setnick ", operand);
		m_Nickname = operand;
		std::string msg ("Nickname set to ");
		msg += m_Nickname;
		SendReplyOK (msg.c_str ());
	}

	void BOBCommandSession::GetNickCommandHandler (const char * operand, size_t len)
	{
		LogPrint (eLogDebug, "BOB: getnick ", operand);
		m_CurrentDestination = m_Owner.FindDestination (operand);
		if (m_CurrentDestination)
		{
			m_Keys = m_CurrentDestination->GetKeys ();
			m_Nickname = operand;
		}
		if (m_Nickname == operand)
		{
			std::string msg ("Nickname set to ");
			msg += m_Nickname;
			SendReplyOK (msg.c_str ());
		}
		else
			SendReplyError ("no nickname has been set");
	}

	void BOBCommandSession::NewkeysCommandHandler (const char * operand, size_t len)
	{
		LogPrint (eLogDebug, "BOB: newkeys");
		i2p::data::SigningKeyType signatureType = i2p::data::SIGNING_KEY_TYPE_DSA_SHA1;
		i2p::data::CryptoKeyType cryptoType = i2p::data::CRYPTO_KEY_TYPE_ELGAMAL;
		if (*operand)
		{
			try
			{
				char * operand1 = (char *)strchr (operand, ' ');
				if (operand1)
				{
					*operand1 = 0; operand1++;
					cryptoType = std::stoi(operand1);
				}
				signatureType = std::stoi(operand);
			}
			catch (std::invalid_argument& ex)
			{
				LogPrint (eLogWarning, "BOB: newkeys ", ex.what ());
			}
		}


		m_Keys = i2p::data::PrivateKeys::CreateRandomKeys (signatureType, cryptoType);
		SendReplyOK (m_Keys.GetPublic ()->ToBase64 ().c_str ());
	}

	void BOBCommandSession::SetkeysCommandHandler (const char * operand, size_t len)
	{
		LogPrint (eLogDebug, "BOB: setkeys ", operand);
		if (m_Keys.FromBase64 (operand))
			SendReplyOK (m_Keys.GetPublic ()->ToBase64 ().c_str ());
		else
			SendReplyError ("invalid keys");
	}

	void BOBCommandSession::GetkeysCommandHandler (const char * operand, size_t len)
	{
		LogPrint (eLogDebug, "BOB: getkeys");
		if (m_Keys.GetPublic ()) // keys are set ?
			SendReplyOK (m_Keys.ToBase64 ().c_str ());
		else
			SendReplyError ("keys are not set");
	}

	void BOBCommandSession::GetdestCommandHandler (const char * operand, size_t len)
	{
		LogPrint (eLogDebug, "BOB: getdest");
		if (m_Keys.GetPublic ()) // keys are set ?
			SendReplyOK (m_Keys.GetPublic ()->ToBase64 ().c_str ());
		else
			SendReplyError ("keys are not set");
	}

	void BOBCommandSession::OuthostCommandHandler (const char * operand, size_t len)
	{
		LogPrint (eLogDebug, "BOB: outhost ", operand);
		m_OutHost = operand;
		SendReplyOK ("outhost set");
	}

	void BOBCommandSession::OutportCommandHandler (const char * operand, size_t len)
	{
		LogPrint (eLogDebug, "BOB: outport ", operand);
		m_OutPort = std::stoi(operand);
		if (m_OutPort >= 0)
			SendReplyOK ("outbound port set");
		else
			SendReplyError ("port out of range");
	}

	void BOBCommandSession::InhostCommandHandler (const char * operand, size_t len)
	{
		LogPrint (eLogDebug, "BOB: inhost ", operand);
		m_InHost = operand;
		SendReplyOK ("inhost set");
	}

	void BOBCommandSession::InportCommandHandler (const char * operand, size_t len)
	{
		LogPrint (eLogDebug, "BOB: inport ", operand);
		m_InPort = std::stoi(operand);
		if (m_InPort >= 0)
			SendReplyOK ("inbound port set");
		else
			SendReplyError ("port out of range");
	}

	void BOBCommandSession::QuietCommandHandler (const char * operand, size_t len)
	{
		LogPrint (eLogDebug, "BOB: quiet");
		if (m_Nickname.length () > 0)
		{
			if (!m_IsActive)
			{
				m_IsQuiet = true;
				SendReplyOK ("Quiet set");
			}
			else
				SendReplyError ("tunnel is active");
		}
		else
			SendReplyError ("no nickname has been set");
	}

	void BOBCommandSession::LookupCommandHandler (const char * operand, size_t len)
	{
		LogPrint (eLogDebug, "BOB: lookup ", operand);
		auto addr = context.GetAddressBook ().GetAddress (operand);
		if (!addr)
		{
			SendReplyError ("Address Not found");
			return;
		}
		auto localDestination = m_CurrentDestination ? m_CurrentDestination->GetLocalDestination () : i2p::client::context.GetSharedLocalDestination ();
		if (addr->IsIdentHash ())
		{
			// we might have leaseset already
			auto leaseSet = localDestination->FindLeaseSet (addr->identHash);
			if (leaseSet)
			{
				SendReplyOK (leaseSet->GetIdentity ()->ToBase64 ().c_str ());
				return;
			}
		}
		// trying to request
		auto s = shared_from_this ();
		auto requstCallback = [s](std::shared_ptr<i2p::data::LeaseSet> ls)
			{
				if (ls)
					s->SendReplyOK (ls->GetIdentity ()->ToBase64 ().c_str ());
				else
					s->SendReplyError ("LeaseSet Not found");
			};
		if (addr->IsIdentHash ())
			localDestination->RequestDestination (addr->identHash, requstCallback);
		else
			localDestination->RequestDestinationWithEncryptedLeaseSet (addr->blindedPublicKey, requstCallback);
	}

	void BOBCommandSession::LookupLocalCommandHandler (const char * operand, size_t len)
	{
		LogPrint (eLogDebug, "BOB: lookup local ", operand);
		auto addr = context.GetAddressBook ().GetAddress (operand);
		if (!addr)
		{
			SendReplyError ("Address Not found");
			return;
		}
		auto ls = i2p::data::netdb.FindLeaseSet (addr->identHash);
		if (ls)
			SendReplyOK (ls->GetIdentity ()->ToBase64 ().c_str ());
		else
			SendReplyError ("Local LeaseSet Not found");
	}
		
	void BOBCommandSession::ClearCommandHandler (const char * operand, size_t len)
	{
		LogPrint (eLogDebug, "BOB: clear");
		m_Owner.DeleteDestination (m_Nickname);
		m_Nickname = "";
		SendReplyOK ("cleared");
	}

	void BOBCommandSession::ListCommandHandler (const char * operand, size_t len)
	{
		LogPrint (eLogDebug, "BOB: list");
		std::string statusLine;
		bool sentCurrent = false;
		const auto& destinations = m_Owner.GetDestinations ();
		for (const auto& it: destinations)
		{
			BuildStatusLine(false, it.second, statusLine);
			SendRaw(statusLine.c_str());
			if(m_Nickname.compare(it.second->GetNickname()) == 0)
				sentCurrent = true;
		}
		if(!sentCurrent && !m_Nickname.empty())
		{
			// add the current tunnel to the list.
			// this is for the incomplete tunnel which has not been started yet.
			BuildStatusLine(true, m_CurrentDestination, statusLine);
			SendRaw(statusLine.c_str());
		}
		SendReplyOK ("Listing done");
	}

	void BOBCommandSession::OptionCommandHandler (const char * operand, size_t len)
	{
		LogPrint (eLogDebug, "BOB: option ", operand);
		const char * value = strchr (operand, '=');
		if (value)
		{
			std::string msg ("option ");
			*(const_cast<char *>(value)) = 0;
			m_Options[operand] = value + 1;
			msg += operand;
			*(const_cast<char *>(value)) = '=';
			msg += " set to ";
			msg += value;
			SendReplyOK (msg.c_str ());
		}
		else
			SendReplyError ("malformed");
	}

	void BOBCommandSession::StatusCommandHandler (const char * operand, size_t len)
	{
		LogPrint (eLogDebug, "BOB: status ", operand);
		const std::string name = operand;
		std::string statusLine;

		// always prefer destination
		auto ptr = m_Owner.FindDestination(name);
		if(ptr != nullptr)
		{
			// tunnel destination exists
			BuildStatusLine(false, ptr, statusLine);
			SendReplyOK(statusLine.c_str());
		}
		else
		{
			if(m_Nickname == name && !name.empty())
			{
				// tunnel is incomplete / has not been started yet
				BuildStatusLine(true, nullptr, statusLine);
				SendReplyOK(statusLine.c_str());
			}
			else
			{
				SendReplyError("no nickname has been set");
			}
		}
	}
	void BOBCommandSession::HelpCommandHandler (const char * operand, size_t len)
	{
		auto helpStrings = m_Owner.GetHelpStrings();
		if(len == 0)
		{
			std::stringstream ss;
			ss << "COMMANDS:";
			for (auto const& x : helpStrings)
			{
				ss << " " << x.first;
			}
			const std::string &str = ss.str();
			SendReplyOK(str.c_str());
		}
		else
		{
			auto it = helpStrings.find(operand);
			if (it != helpStrings.end ())
			{
				SendReplyOK(it->second.c_str());
				return;
			}
			SendReplyError("No such command");
		}
	}

	BOBCommandChannel::BOBCommandChannel (const std::string& address, int port):
		RunnableService ("BOB"),
		m_Acceptor (GetIOService (), boost::asio::ip::tcp::endpoint(boost::asio::ip::address::from_string(address), port))
	{
		// command -> handler
		m_CommandHandlers[BOB_COMMAND_ZAP] = &BOBCommandSession::ZapCommandHandler;
		m_CommandHandlers[BOB_COMMAND_QUIT] = &BOBCommandSession::QuitCommandHandler;
		m_CommandHandlers[BOB_COMMAND_START] = &BOBCommandSession::StartCommandHandler;
		m_CommandHandlers[BOB_COMMAND_STOP] = &BOBCommandSession::StopCommandHandler;
		m_CommandHandlers[BOB_COMMAND_SETNICK] = &BOBCommandSession::SetNickCommandHandler;
		m_CommandHandlers[BOB_COMMAND_GETNICK] = &BOBCommandSession::GetNickCommandHandler;
		m_CommandHandlers[BOB_COMMAND_NEWKEYS] = &BOBCommandSession::NewkeysCommandHandler;
		m_CommandHandlers[BOB_COMMAND_GETKEYS] = &BOBCommandSession::GetkeysCommandHandler;
		m_CommandHandlers[BOB_COMMAND_SETKEYS] = &BOBCommandSession::SetkeysCommandHandler;
		m_CommandHandlers[BOB_COMMAND_GETDEST] = &BOBCommandSession::GetdestCommandHandler;
		m_CommandHandlers[BOB_COMMAND_OUTHOST] = &BOBCommandSession::OuthostCommandHandler;
		m_CommandHandlers[BOB_COMMAND_OUTPORT] = &BOBCommandSession::OutportCommandHandler;
		m_CommandHandlers[BOB_COMMAND_INHOST] = &BOBCommandSession::InhostCommandHandler;
		m_CommandHandlers[BOB_COMMAND_INPORT] = &BOBCommandSession::InportCommandHandler;
		m_CommandHandlers[BOB_COMMAND_QUIET] = &BOBCommandSession::QuietCommandHandler;
		m_CommandHandlers[BOB_COMMAND_LOOKUP] = &BOBCommandSession::LookupCommandHandler;
		m_CommandHandlers[BOB_COMMAND_LOOKUP_LOCAL] = &BOBCommandSession::LookupLocalCommandHandler;	
		m_CommandHandlers[BOB_COMMAND_CLEAR] = &BOBCommandSession::ClearCommandHandler;
		m_CommandHandlers[BOB_COMMAND_LIST] = &BOBCommandSession::ListCommandHandler;
		m_CommandHandlers[BOB_COMMAND_OPTION] = &BOBCommandSession::OptionCommandHandler;
		m_CommandHandlers[BOB_COMMAND_STATUS] = &BOBCommandSession::StatusCommandHandler;
		m_CommandHandlers[BOB_COMMAND_HELP] = &BOBCommandSession::HelpCommandHandler;
		// command -> help string
		m_HelpStrings[BOB_COMMAND_ZAP] = BOB_HELP_ZAP;
		m_HelpStrings[BOB_COMMAND_QUIT] = BOB_HELP_QUIT;
		m_HelpStrings[BOB_COMMAND_START] = BOB_HELP_START;
		m_HelpStrings[BOB_COMMAND_STOP] = BOB_HELP_STOP;
		m_HelpStrings[BOB_COMMAND_SETNICK] = BOB_HELP_SETNICK;
		m_HelpStrings[BOB_COMMAND_GETNICK] = BOB_HELP_GETNICK;
		m_HelpStrings[BOB_COMMAND_NEWKEYS] = BOB_HELP_NEWKEYS;
		m_HelpStrings[BOB_COMMAND_GETKEYS] = BOB_HELP_GETKEYS;
		m_HelpStrings[BOB_COMMAND_SETKEYS] = BOB_HELP_SETKEYS;
		m_HelpStrings[BOB_COMMAND_GETDEST] = BOB_HELP_GETDEST;
		m_HelpStrings[BOB_COMMAND_OUTHOST] = BOB_HELP_OUTHOST;
		m_HelpStrings[BOB_COMMAND_OUTPORT] = BOB_HELP_OUTPORT;
		m_HelpStrings[BOB_COMMAND_INHOST] = BOB_HELP_INHOST;
		m_HelpStrings[BOB_COMMAND_INPORT] = BOB_HELP_INPORT;
		m_HelpStrings[BOB_COMMAND_QUIET] = BOB_HELP_QUIET;
		m_HelpStrings[BOB_COMMAND_LOOKUP] = BOB_HELP_LOOKUP;
		m_HelpStrings[BOB_COMMAND_CLEAR] = BOB_HELP_CLEAR;
		m_HelpStrings[BOB_COMMAND_LIST] = BOB_HELP_LIST;
		m_HelpStrings[BOB_COMMAND_OPTION] = BOB_HELP_OPTION;
		m_HelpStrings[BOB_COMMAND_STATUS] = BOB_HELP_STATUS;
		m_HelpStrings[BOB_COMMAND_HELP] = BOB_HELP_HELP;
	}

	BOBCommandChannel::~BOBCommandChannel ()
	{
		if (IsRunning ())
			Stop ();
		for (const auto& it: m_Destinations)
			delete it.second;
	}

	void BOBCommandChannel::Start ()
	{
		Accept ();
		StartIOService ();
	}

	void BOBCommandChannel::Stop ()
	{
		for (auto& it: m_Destinations)
			it.second->Stop ();
		m_Acceptor.cancel ();
		StopIOService ();
	}

	void BOBCommandChannel::AddDestination (const std::string& name, BOBDestination * dest)
	{
		m_Destinations[name] = dest;
	}

	void BOBCommandChannel::DeleteDestination (const std::string& name)
	{
		auto it = m_Destinations.find (name);
		if (it != m_Destinations.end ())
		{
			it->second->Stop ();
			delete it->second;
			m_Destinations.erase (it);
		}
	}

	BOBDestination * BOBCommandChannel::FindDestination (const std::string& name)
	{
		auto it = m_Destinations.find (name);
		if (it != m_Destinations.end ())
			return it->second;
		return nullptr;
	}

	void BOBCommandChannel::Accept ()
	{
		auto newSession = std::make_shared<BOBCommandSession> (*this);
		m_Acceptor.async_accept (newSession->GetSocket (), std::bind (&BOBCommandChannel::HandleAccept, this,
			std::placeholders::_1, newSession));
	}

	void BOBCommandChannel::HandleAccept(const boost::system::error_code& ecode, std::shared_ptr<BOBCommandSession> session)
	{
		if (ecode != boost::asio::error::operation_aborted)
			Accept ();

		if (!ecode)
		{
			LogPrint (eLogInfo, "BOB: New command connection from ", session->GetSocket ().remote_endpoint ());
			session->SendVersion ();
		}
		else
			LogPrint (eLogError, "BOB: accept error: ", ecode.message ());
	}
}
}
