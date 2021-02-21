/*
* Copyright (c) 2013-2020, The PurpleI2P Project
*
* This file is part of Purple i2pd project and licensed under BSD3
*
* See full license text in LICENSE file at top of project tree
*/

#ifndef BOB_H__
#define BOB_H__

#include <inttypes.h>
#include <thread>
#include <memory>
#include <map>
#include <string>
#include <boost/asio.hpp>
#include "util.h"
#include "I2PTunnel.h"
#include "I2PService.h"
#include "Identity.h"
#include "LeaseSet.h"

namespace i2p
{
namespace client
{
	const size_t BOB_COMMAND_BUFFER_SIZE = 1024;
	const char BOB_COMMAND_ZAP[] = "zap";
	const char BOB_COMMAND_QUIT[] = "quit";
	const char BOB_COMMAND_START[] = "start";
	const char BOB_COMMAND_STOP[] = "stop";
	const char BOB_COMMAND_SETNICK[] = "setnick";
	const char BOB_COMMAND_GETNICK[] = "getnick";
	const char BOB_COMMAND_NEWKEYS[] = "newkeys";
	const char BOB_COMMAND_GETKEYS[] = "getkeys";
	const char BOB_COMMAND_SETKEYS[] = "setkeys";
	const char BOB_COMMAND_GETDEST[] = "getdest";
	const char BOB_COMMAND_OUTHOST[] = "outhost";
	const char BOB_COMMAND_OUTPORT[] = "outport";
	const char BOB_COMMAND_INHOST[] = "inhost";
	const char BOB_COMMAND_INPORT[] = "inport";
	const char BOB_COMMAND_QUIET[] = "quiet";
	const char BOB_COMMAND_LOOKUP[] = "lookup";
	const char BOB_COMMAND_LOOKUP_LOCAL[] = "lookuplocal";
	const char BOB_COMMAND_CLEAR[] = "clear";
	const char BOB_COMMAND_LIST[] = "list";
	const char BOB_COMMAND_OPTION[] = "option";
	const char BOB_COMMAND_STATUS[] = "status";
	const char BOB_COMMAND_HELP[] = "help";

	const char BOB_HELP_ZAP[] = "zap - Shuts down BOB.";
	const char BOB_HELP_QUIT[] = "quit - Quits this session with BOB.";
	const char BOB_HELP_START[] = "start - Starts the current nicknamed tunnel.";
	const char BOB_HELP_STOP[] = "stop - Stops the current nicknamed tunnel.";
	const char BOB_HELP_SETNICK[] = "setnick <NICKNAME> - Creates a new nickname.";
	const char BOB_HELP_GETNICK[] = "getnick <TUNNELNAME> - Sets the nickname from the database.";
	const char BOB_HELP_NEWKEYS[] = "newkeys - Generate a new keypair for the current nickname.";
	const char BOB_HELP_GETKEYS[] = "getkeys - Return the keypair for the current nickname.";
	const char BOB_HELP_SETKEYS[] = "setkeys <BASE64_KEYPAIR> - Sets the keypair for the current nickname.";
	const char BOB_HELP_GETDEST[] = "getdest - Return the destination for the current nickname.";
	const char BOB_HELP_OUTHOST[] = "outhost <HOSTNAME|IP> - Set the outhound hostname or IP.";
	const char BOB_HELP_OUTPORT[] = "outport <PORT_NUMBER> - Set the outbound port that nickname contacts.";
	const char BOB_HELP_INHOST[] = "inhost <HOSTNAME|IP> - Set the inbound hostname or IP.";
	const char BOB_HELP_INPORT[] = "inport <PORT_NUMBER> - Set the inbound port number nickname listens on.";
	const char BOB_HELP_QUIET[] = "quiet <True|False> - Wether to send the incoming destination.";
	const char BOB_HELP_LOOKUP[] = "lookup <I2P_HOSTNAME> - Look up an I2P hostname.";
	const char BOB_HELP_CLEAR[] = "clear - Clear the current nickname out of the list.";
	const char BOB_HELP_LIST[] = "list - List all tunnels.";
	const char BOB_HELP_OPTION[] = "option <KEY>=<VALUE> - Set an option. NOTE: Don't use any spaces.";
	const char BOB_HELP_STATUS[] = "status <NICKNAME> - Display status of a nicknamed tunnel.";
	const char BOB_HELP_HELP [] = "help <COMMAND> - Get help on a command.";

	class BOBI2PTunnel: public I2PService
	{
		public:

			BOBI2PTunnel (std::shared_ptr<ClientDestination> localDestination):
				I2PService (localDestination) {};

			virtual void Start () {};
			virtual void Stop () {};
	};

	class BOBI2PInboundTunnel: public BOBI2PTunnel
	{
		struct AddressReceiver
		{
			std::shared_ptr<boost::asio::ip::tcp::socket> socket;
			char buffer[BOB_COMMAND_BUFFER_SIZE + 1]; // for destination base64 address
			uint8_t * data; // pointer to buffer
			size_t dataLen, bufferOffset;

			AddressReceiver (): data (nullptr), dataLen (0), bufferOffset (0) {};
		};

		public:

			BOBI2PInboundTunnel (const boost::asio::ip::tcp::endpoint& ep, std::shared_ptr<ClientDestination> localDestination);
			~BOBI2PInboundTunnel ();

			void Start ();
			void Stop ();

		private:

			void Accept ();
			void HandleAccept (const boost::system::error_code& ecode, std::shared_ptr<AddressReceiver> receiver);

			void ReceiveAddress (std::shared_ptr<AddressReceiver> receiver);
			void HandleReceivedAddress (const boost::system::error_code& ecode, std::size_t bytes_transferred,
				std::shared_ptr<AddressReceiver> receiver);

			void HandleDestinationRequestComplete (std::shared_ptr<i2p::data::LeaseSet> leaseSet, std::shared_ptr<AddressReceiver> receiver);

			void CreateConnection (std::shared_ptr<AddressReceiver> receiver, std::shared_ptr<const i2p::data::LeaseSet> leaseSet);

		private:

			boost::asio::ip::tcp::acceptor m_Acceptor;
	};

	class BOBI2POutboundTunnel: public BOBI2PTunnel
	{
		public:

			BOBI2POutboundTunnel (const std::string& outhost, int port, std::shared_ptr<ClientDestination> localDestination, bool quiet);

			void Start ();
			void Stop ();

			void SetQuiet () { m_IsQuiet = true; };

		private:

			void Accept ();
			void HandleAccept (std::shared_ptr<i2p::stream::Stream> stream);

		private:

			boost::asio::ip::tcp::endpoint m_Endpoint;
			bool m_IsQuiet;
	};


	class BOBDestination
	{
		public:

			BOBDestination (std::shared_ptr<ClientDestination> localDestination,
					const std::string &nickname, const std::string &inhost, const std::string &outhost,
					const int inport, const int outport, const bool quiet);
			~BOBDestination ();

			void Start ();
			void Stop ();
			void StopTunnels ();
			void CreateInboundTunnel (int port, const std::string& inhost);
			void CreateOutboundTunnel (const std::string& outhost, int port, bool quiet);
			const std::string& GetNickname() const { return m_Nickname; }
			const std::string& GetInHost() const { return m_InHost; }
			const std::string& GetOutHost() const { return m_OutHost; }
			int GetInPort() const { return m_InPort; }
			int GetOutPort() const { return m_OutPort; }
			bool GetQuiet() const { return m_Quiet; }
			const i2p::data::PrivateKeys& GetKeys () const { return m_LocalDestination->GetPrivateKeys (); };
			std::shared_ptr<ClientDestination> GetLocalDestination () const { return m_LocalDestination; };

		private:

			std::shared_ptr<ClientDestination> m_LocalDestination;
			BOBI2POutboundTunnel * m_OutboundTunnel;
			BOBI2PInboundTunnel * m_InboundTunnel;

			std::string m_Nickname;
			std::string m_InHost, m_OutHost;
			int m_InPort, m_OutPort;
			bool m_Quiet;
	};

	class BOBCommandChannel;
	class BOBCommandSession: public std::enable_shared_from_this<BOBCommandSession>
	{
		public:

			BOBCommandSession (BOBCommandChannel& owner);
			~BOBCommandSession ();
			void Terminate ();

			boost::asio::ip::tcp::socket& GetSocket () { return m_Socket; };
			void SendVersion ();

			// command handlers
			void ZapCommandHandler (const char * operand, size_t len);
			void QuitCommandHandler (const char * operand, size_t len);
			void StartCommandHandler (const char * operand, size_t len);
			void StopCommandHandler (const char * operand, size_t len);
			void SetNickCommandHandler (const char * operand, size_t len);
			void GetNickCommandHandler (const char * operand, size_t len);
			void NewkeysCommandHandler (const char * operand, size_t len);
			void SetkeysCommandHandler (const char * operand, size_t len);
			void GetkeysCommandHandler (const char * operand, size_t len);
			void GetdestCommandHandler (const char * operand, size_t len);
			void OuthostCommandHandler (const char * operand, size_t len);
			void OutportCommandHandler (const char * operand, size_t len);
			void InhostCommandHandler (const char * operand, size_t len);
			void InportCommandHandler (const char * operand, size_t len);
			void QuietCommandHandler (const char * operand, size_t len);
			void LookupCommandHandler (const char * operand, size_t len);
			void LookupLocalCommandHandler (const char * operand, size_t len);
			void ClearCommandHandler (const char * operand, size_t len);
			void ListCommandHandler (const char * operand, size_t len);
			void OptionCommandHandler (const char * operand, size_t len);
			void StatusCommandHandler (const char * operand, size_t len);
			void HelpCommandHandler (const char * operand, size_t len);

		private:

			void Receive ();
			void HandleReceivedLine(const boost::system::error_code& ecode, std::size_t bytes_transferred);
			void HandleReceived (const boost::system::error_code& ecode, std::size_t bytes_transferred);

			void Send ();
			void HandleSent (const boost::system::error_code& ecode, std::size_t bytes_transferred);
			void SendReplyOK (const char * msg = nullptr);
			void SendReplyError (const char * msg);
			void SendRaw (const char * data);

			void BuildStatusLine(bool currentTunnel, BOBDestination *destination, std::string &out);

		private:

			BOBCommandChannel& m_Owner;
			boost::asio::ip::tcp::socket m_Socket;
			boost::asio::streambuf m_ReceiveBuffer, m_SendBuffer;
			bool m_IsOpen, m_IsQuiet, m_IsActive;
			std::string m_Nickname, m_InHost, m_OutHost;
			int m_InPort, m_OutPort;
			i2p::data::PrivateKeys m_Keys;
			std::map<std::string, std::string> m_Options;
			BOBDestination * m_CurrentDestination;
	};
	typedef void (BOBCommandSession::*BOBCommandHandler)(const char * operand, size_t len);

	class BOBCommandChannel: private i2p::util::RunnableService
	{
		public:

			BOBCommandChannel (const std::string& address, int port);
			~BOBCommandChannel ();

			void Start ();
			void Stop ();

			boost::asio::io_service& GetService () { return GetIOService (); };
			void AddDestination (const std::string& name, BOBDestination * dest);
			void DeleteDestination (const std::string& name);
			BOBDestination * FindDestination (const std::string& name);

		private:

			void Accept ();
			void HandleAccept(const boost::system::error_code& ecode, std::shared_ptr<BOBCommandSession> session);

		private:

			boost::asio::ip::tcp::acceptor m_Acceptor;
			std::map<std::string, BOBDestination *> m_Destinations;
			std::map<std::string, BOBCommandHandler> m_CommandHandlers;
			std::map<std::string, std::string> m_HelpStrings;

		public:

			const decltype(m_CommandHandlers)& GetCommandHandlers () const { return m_CommandHandlers; };
			const decltype(m_HelpStrings)& GetHelpStrings () const { return m_HelpStrings; };
			const decltype(m_Destinations)& GetDestinations () const { return m_Destinations; };
	};
}
}

#endif
