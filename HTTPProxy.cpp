#include <boost/bind.hpp>
#include <boost/lexical_cast.hpp>
#include <boost/bind/protect.hpp>
#include <boost/regex.hpp>

#include "base64.h"
#include "Log.h"
#include "Tunnel.h"
#include "TransitTunnel.h"
#include "Transports.h"
#include "NetDb.h"
#include "Streaming.h"
#include "HTTPProxy.h"

namespace i2p
{
namespace proxy
{
	namespace misc_strings 
	{

		const char name_value_separator[] = { ':', ' ' };
		const char crlf[] = { '\r', '\n' };

	} // namespace misc_strings

	std::vector<boost::asio::const_buffer> HTTPConnection::reply::to_buffers()
	{
		std::vector<boost::asio::const_buffer> buffers;
		if (headers.size () > 0)
		{	
			buffers.push_back (boost::asio::buffer ("HTTP/1.0 200 OK\r\n")); // always OK
			for (std::size_t i = 0; i < headers.size(); ++i)
			{
				header& h = headers[i];
				buffers.push_back(boost::asio::buffer(h.name));
				buffers.push_back(boost::asio::buffer(misc_strings::name_value_separator));
				buffers.push_back(boost::asio::buffer(h.value));
				buffers.push_back(boost::asio::buffer(misc_strings::crlf));
			}
			buffers.push_back(boost::asio::buffer(misc_strings::crlf));
		}	
		buffers.push_back(boost::asio::buffer(content));
		return buffers;
	}

	void HTTPConnection::Terminate ()
	{
		m_Socket->close ();
		delete this;
	}

	void HTTPConnection::Receive ()
	{
		m_Socket->async_read_some (boost::asio::buffer (m_Buffer, 8192),
			 boost::bind(&HTTPConnection::HandleReceive, this,
				 boost::asio::placeholders::error, boost::asio::placeholders::bytes_transferred));
	}

	void HTTPConnection::HandleReceive (const boost::system::error_code& ecode, std::size_t bytes_transferred)
	{
		if (!ecode)
		{
			m_Buffer[bytes_transferred] = 0;
			
			request m_Request;
			ExtractRequest (m_Request);
			parseHeaders (m_Buffer, m_Request.headers);
			
			LogPrint("Requesting ", m_Request.host, " with path ", m_Request.uri, " and method ", m_Request.method);
			HandleDestinationRequest (m_Request.host, m_Request.uri);
		}
		else if (ecode != boost::asio::error::operation_aborted)
			Terminate ();
	}

	void HTTPConnection::parseHeaders(const std::string& h, std::vector<header>& hm) {
		std::string str (h);
		std::string::size_type idx;
		std::string t;
		int i = 0;
		while( (idx=str.find ("\r\n")) != std::string::npos) {
			t=str.substr (0,idx);
			str.erase (0,idx+2);
			if (t == "")
				break;
			idx=t.find(": ");
			if (idx == std::string::npos)
			{
				std::cout << "Bad header line: " << t << std::endl;
				break;
			}
			LogPrint ("Name: ", t.substr (0,idx), " Value: ", t.substr (idx+2));
			hm[i].name = t.substr (0,idx);
			hm[i].value = t.substr (idx+2);
			i++;
		}
	}

	void HTTPConnection::ExtractRequest (request &m_Request)
	{
		std::string requestString = m_Buffer;
		int idx=requestString.find(" ");
		std::string method = requestString.substr(0,idx);
		requestString = requestString.substr(idx+1);
		idx=requestString.find(" ");
		std::string requestUrl = requestString.substr(0,idx);
		LogPrint("method is: ", method, "\nRequest is: ", requestUrl);
		std::string server="";
		std::string port="80";
		boost::regex rHTTP("http://(.*?)(:(\\d+))?(/.*)");
		boost::smatch m;
		std::string path;
		if(boost::regex_search(requestUrl, m, rHTTP, boost::match_extra)) {
			server=m[1].str();
			if(m[2].str() != "") {
				port=m[3].str();
			}
			path=m[4].str();
		}
		LogPrint("server is: ",server, "\n path is: ",path);
		m_Request.uri = path;
		m_Request.method = method;
		m_Request.host = server;
	}
	
	void HTTPConnection::HandleWriteReply (const boost::system::error_code& ecode)
	{
		Terminate ();
	}

	void HTTPConnection::HandleWrite (const boost::system::error_code& ecode)
	{
		if (ecode || (m_Stream && !m_Stream->IsOpen ()))
			Terminate ();
		else // data keeps coming
			AsyncStreamReceive ();
	}

	void HTTPConnection::HandleDestinationRequest (const std::string& address, const std::string& uri)
	{
		i2p::data::IdentHash destination;
		std::string fullAddress;
		if (address.find (".b32.i2p") != std::string::npos)
		{
			int li = address.find_first_of (".");
			std::string newaddress = address.substr (0, li);
			if (i2p::data::Base32ToByteStream (newaddress.c_str (), newaddress.length (), (uint8_t *)destination, 32) != 32)
			{
				LogPrint ("Invalid Base32 address ", newaddress);
				return;
			}
			fullAddress = newaddress + ".b32.i2p";
		}
		else
		{	
			auto addr = i2p::data::netdb.FindAddress (address);
			if (!addr) 
			{
				LogPrint ("Unknown address ", address);
				SendReply("<html>"+ i2p::proxy::itoopieImage +"<br>Unknown address " + address + "</html>");
				return;
			}	
			destination = *addr;
			fullAddress = address;
		}
			
		auto leaseSet = i2p::data::netdb.FindLeaseSet (destination);
		if (!leaseSet || !leaseSet->HasNonExpiredLeases ())
		{
			i2p::data::netdb.Subscribe(destination);
			std::this_thread::sleep_for (std::chrono::seconds(10)); // wait for 10 seconds
			leaseSet = i2p::data::netdb.FindLeaseSet (destination);
			if (!leaseSet || !leaseSet->HasNonExpiredLeases ()) // still no LeaseSet
			{
				SendReply(leaseSet ? "<html>"+ i2p::proxy::itoopieImage +"<br>Leases expired</html>" : "<html>"+ i2p::proxy::itoopieImage +"LeaseSet not found</html>");
				return;
			}	
		}	
		if (!m_Stream)
			m_Stream = i2p::stream::CreateStream (*leaseSet);
		if (m_Stream)
		{
			std::string request = "GET " + uri + " HTTP/1.1\n Host:" + fullAddress + "\n";
			m_Stream->Send ((uint8_t *)request.c_str (), request.length (), 10);
			AsyncStreamReceive ();
		}
	}

	void HTTPConnection::AsyncStreamReceive ()
	{
		if (m_Stream)
			m_Stream->AsyncReceive (boost::asio::buffer (m_StreamBuffer, 8192),
				boost::protect (boost::bind (&HTTPConnection::HandleStreamReceive, this,
					boost::asio::placeholders::error, boost::asio::placeholders::bytes_transferred)),
				45); // 45 seconds timeout
	}

	void HTTPConnection::HandleStreamReceive (const boost::system::error_code& ecode, std::size_t bytes_transferred)
	{
		if (bytes_transferred)
		{
			boost::asio::async_write (*m_Socket, boost::asio::buffer (m_StreamBuffer, bytes_transferred),
				boost::bind (&HTTPConnection::HandleWrite, this, boost::asio::placeholders::error));
		}
		else
		{
			if (m_Stream && m_Stream->IsOpen ())
				SendReply ("<html>"+ i2p::proxy::itoopieImage +"<br>Not responding</html>");
			else
				Terminate ();
		}	
	}

	void HTTPConnection::SendReply (const std::string& content)
	{
		m_Reply.content = content;
		m_Reply.headers.resize(2);
		m_Reply.headers[0].name = "Content-Length";
		m_Reply.headers[0].value = boost::lexical_cast<std::string>(m_Reply.content.size());
		m_Reply.headers[1].name = "Content-Type";
		m_Reply.headers[1].value = "text/html";

		boost::asio::async_write (*m_Socket, m_Reply.to_buffers(),
			boost::bind (&HTTPConnection::HandleWriteReply, this,
				boost::asio::placeholders::error));
	}	
	
	
	HTTPProxy::HTTPProxy (int port): 
		m_Thread (nullptr), m_Work (m_Service), 
		m_Acceptor (m_Service, boost::asio::ip::tcp::endpoint (boost::asio::ip::tcp::v4(), port)),
		m_NewSocket (nullptr)
	{
		
	}

	HTTPProxy::~HTTPProxy ()
	{
		Stop ();
	}

	void HTTPProxy::Start ()
	{
		m_Thread = new std::thread (std::bind (&HTTPProxy::Run, this));
		m_Acceptor.listen ();
		Accept ();
	}

	void HTTPProxy::Stop ()
	{
		m_Acceptor.close();
		m_Service.stop ();
		if (m_Thread)
		{
			m_Thread->join ();
			delete m_Thread;
			m_Thread = nullptr;
		}
	}

	void HTTPProxy::Run ()
	{
		m_Service.run ();
	}	

	void HTTPProxy::Accept ()
	{
		m_NewSocket = new boost::asio::ip::tcp::socket (m_Service);
		m_Acceptor.async_accept (*m_NewSocket, boost::bind (&HTTPProxy::HandleAccept, this,
			boost::asio::placeholders::error));
	}

	void HTTPProxy::HandleAccept(const boost::system::error_code& ecode)
	{
		if (!ecode)
		{
			new HTTPConnection (m_NewSocket);
			Accept ();
		}
	}	
}
}

