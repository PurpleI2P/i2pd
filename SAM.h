#ifndef SAM_H__
#define SAM_H__

#include <inttypes.h>
#include <string>
#include <map>
#include <list>
#include <thread>
#include <boost/asio.hpp>
#include "Identity.h"
#include "LeaseSet.h"
#include "Streaming.h"

namespace i2p
{
namespace stream
{
	const size_t SAM_SOCKET_BUFFER_SIZE = 4096;
	const int SAM_SOCKET_CONNECTION_MAX_IDLE = 3600; // in seconds	
	const int SAM_CONNECT_TIMEOUT = 5; // in seconds
	const char SAM_HANDSHAKE[] = "HELLO VERSION";
	const char SAM_HANDSHAKE_REPLY[] = "HELLO REPLY RESULT=OK VERSION=3.1\n";
	const char SAM_SESSION_CREATE[] = "SESSION CREATE";
	const char SAM_SESSION_CREATE_REPLY_OK[] = "SESSION STATUS RESULT=OK DESTINATION=%s\n";
	const char SAM_SESSION_CREATE_DUPLICATED_ID[] = "SESSION STATUS RESULT=DUPLICATED_ID\n";
	const char SAM_SESSION_CREATE_DUPLICATED_DEST[] = "SESSION STATUS RESULT=DUPLICATED_DEST\n";	
	const char SAM_STREAM_CONNECT[] = "STREAM CONNECT";
	const char SAM_STREAM_STATUS_OK[] = "STREAM STATUS RESULT=OK\n";
	const char SAM_STREAM_STATUS_INVALID_ID[] = "STREAM STATUS RESULT=INVALID_ID\n";
	const char SAM_STREAM_STATUS_CANT_REACH_PEER[] = "STREAM STATUS RESULT=CANT_REACH_PEER\n";
	const char SAM_STREAM_STATUS_I2P_ERROR[] = "STREAM STATUS RESULT=I2P_ERROR\n";
	const char SAM_STREAM_ACCEPT[] = "STREAM ACCEPT";	
	const char SAM_DEST_GENERATE[] = "DEST GENERATE";
	const char SAM_DEST_REPLY[] = "DEST REPLY PUB=%s PRIV=%s\n";	
	const char SAM_DEST_REPLY_I2P_ERROR[] = "DEST REPLY RESULT=I2P_ERROR\n";
	const char SAM_NAMING_LOOKUP[] = "NAMING LOOKUP";
	const char SAM_NAMING_REPLY[] = "NAMING REPLY RESULT=OK NAME=ME VALUE=%s\n";
	const char SAM_NAMING_REPLY_INVALID_KEY[] = "NAMING REPLY RESULT=INVALID_KEY NAME=%s\n";	
	const char SAM_PARAM_STYLE[] = "STYLE";		
	const char SAM_PARAM_ID[] = "ID";	
	const char SAM_PARAM_SILENT[] = "SILENT";
	const char SAM_PARAM_DESTINATION[] = "DESTINATION";	
	const char SAM_PARAM_NAME[] = "NAME";		
	const char SAM_VALUE_TRANSIENT[] = "TRANSIENT";	
	const char SAM_VALUE_TRUE[] = "true";	
	const char SAM_VALUE_FALSE[] = "false";	

	enum SAMSocketType
	{
		eSAMSocketTypeUnknown,
		eSAMSocketTypeSession,
		eSAMSocketTypeStream,
		eSAMSocketTypeAcceptor	
	};

	class SAMBridge;
	class SAMSession;
	class SAMSocket
	{
		public:

			SAMSocket (SAMBridge& owner);
			~SAMSocket ();			

			boost::asio::ip::tcp::socket& GetSocket () { return m_Socket; };
			void ReceiveHandshake ();

		private:

			void Terminate ();
			void HandleHandshakeReceived (const boost::system::error_code& ecode, std::size_t bytes_transferred);
			void HandleHandshakeReplySent (const boost::system::error_code& ecode, std::size_t bytes_transferred);
			void HandleMessage (const boost::system::error_code& ecode, std::size_t bytes_transferred);
			void SendMessageReply (const char * msg, size_t len, bool close);			
			void HandleMessageReplySent (const boost::system::error_code& ecode, std::size_t bytes_transferred, bool close);
			void Receive ();
			void HandleReceived (const boost::system::error_code& ecode, std::size_t bytes_transferred);

			void I2PReceive ();	
			void HandleI2PReceive (const boost::system::error_code& ecode, std::size_t bytes_transferred);
			void HandleI2PAccept (i2p::stream::Stream * stream);
			void HandleWriteI2PData (const boost::system::error_code& ecode);

			void ProcessSessionCreate (char * buf, size_t len);
			void ProcessStreamConnect (char * buf, size_t len);
			void ProcessStreamAccept (char * buf, size_t len);
			void ProcessDestGenerate ();
			void ProcessNamingLookup (char * buf, size_t len);
			void ExtractParams (char * buf, size_t len, std::map<std::string, std::string>& params);

			void Connect (const i2p::data::LeaseSet& remote, SAMSession * session);
			void HandleDestinationRequestTimer (const boost::system::error_code& ecode, i2p::data::IdentHash ident, SAMSession * session);

		private:

			SAMBridge& m_Owner;
			boost::asio::ip::tcp::socket m_Socket;
			boost::asio::deadline_timer m_Timer;
			char m_Buffer[SAM_SOCKET_BUFFER_SIZE + 1];
			uint8_t m_StreamBuffer[SAM_SOCKET_BUFFER_SIZE];
			SAMSocketType m_SocketType;
			std::string m_ID; // nickname
			bool m_IsSilent;
			Stream * m_Stream;
			SAMSession * m_Session;
	};	

	struct SAMSession
	{
		StreamingDestination * localDestination;
		std::list<SAMSocket *> sockets;
	};

	class SAMBridge
	{
		public:

			SAMBridge (int port);
			~SAMBridge ();

			void Start ();
			void Stop ();
			
			boost::asio::io_service& GetService () { return m_Service; };
			SAMSession * CreateSession (const std::string& id, const std::string& destination = ""); // empty string  means transient
			void CloseSession (const std::string& id);
			SAMSession * FindSession (const std::string& id);

		private:

			void Run ();

			void Accept ();
			void HandleAccept(const boost::system::error_code& ecode);

		private:

			bool m_IsRunning;
			std::thread * m_Thread;	
			boost::asio::io_service m_Service;
			boost::asio::ip::tcp::acceptor m_Acceptor;
			SAMSocket * m_NewSocket;
			std::map<std::string, SAMSession> m_Sessions;
	};		
}
}

#endif

