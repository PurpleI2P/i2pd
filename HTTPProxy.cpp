#include <boost/lexical_cast.hpp>
#include <boost/regex.hpp>

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
		LogPrint("server is: ",server, "\n path is: ",path);
		r.uri = path;
		r.method = method;
		r.host = server;
	}


	void HTTPProxyConnection::RunRequest()
	{
		request r;
		ExtractRequest(r);
		parseHeaders(m_Buffer, r.headers);
		size_t len = 0;
		const char * data = strstr (m_Buffer, "\r\n\r\n");	
		if (data)
		{	 
			data += 4;
			len = strlen (m_Buffer) - (data - m_Buffer);
		}
		LogPrint("Requesting ", r.host, " with path ", r.uri, " and method ", r.method);
		HandleDestinationRequest(r.host, r.method, len > 0 ? std::string (data, len) : "" , r.uri);
	}

}
}

