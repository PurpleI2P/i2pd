#include <boost/lexical_cast.hpp>
#include <boost/regex.hpp>

#include "NetDb.h"
#include "HTTPProxy.h"

namespace i2p
{
namespace proxy
{
	void HTTPProxyConnection::parseHeaders(const std::string& h, std::vector<header>& hm) {
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

	void HTTPProxyConnection::ExtractRequest(request& r)
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
		LogPrint("server is: ",server, " port is: ", port, "\n path is: ",path);
		r.uri = path;
		r.method = method;
		r.host = server;
		r.port = boost::lexical_cast<int>(port);
	}


	void HTTPProxyConnection::RunRequest()
	{
		request r;
		ExtractRequest(r);
		parseHeaders(m_Buffer, r.headers);
		size_t addressHelperPos = r.uri.find ("i2paddresshelper");
		if (addressHelperPos != std::string::npos)
		{
			// jump service
			size_t addressPos = r.uri.find ("=", addressHelperPos);
			if (addressPos != std::string::npos)
			{
				LogPrint ("Jump service for ", r.host, " found. Inserting to address book");
				auto base64 = r.uri.substr (addressPos + 1);
				i2p::data::netdb.GetAddressBook ().InsertAddress (r.host, base64);
			}
		}			
	
		LogPrint("Requesting ", r.host, ":", r.port, " with path ", r.uri, " and method ", r.method);
		SendToAddress (r.host, r.port,  m_Buffer, m_BufferLen);
	}

}
}

