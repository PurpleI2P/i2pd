/*
* Copyright (c) 2013-2017, The PurpleI2P Project
*
* This file is part of Purple i2pd project and licensed under BSD3
*
* See full license text in LICENSE file at top of project tree
*/

#include <algorithm>
#include <utility>
#include "util.h"
#include "HTTP.h"
#include <ctime>

namespace i2p {
namespace http {
  const std::vector<std::string> HTTP_METHODS = {
    "GET", "HEAD", "POST", "PUT", "PATCH",
    "DELETE", "OPTIONS", "CONNECT"
  };
  const std::vector<std::string> HTTP_VERSIONS = {
    "HTTP/1.0", "HTTP/1.1"
  };

  inline bool is_http_version(const std::string & str) {
    return std::find(HTTP_VERSIONS.begin(), HTTP_VERSIONS.end(), str) != std::end(HTTP_VERSIONS);
  }

  inline bool is_http_method(const std::string & str) {
    return std::find(HTTP_METHODS.begin(), HTTP_METHODS.end(), str) != std::end(HTTP_METHODS);
  }
  
  void strsplit(const std::string & line, std::vector<std::string> &tokens, char delim, std::size_t limit = 0) {
    std::size_t count = 0;
    std::stringstream ss(line);
    std::string token;
    while (1) {
      count++;
      if (limit > 0 && count >= limit)
        delim = '\n'; /* reset delimiter */
      if (!std::getline(ss, token, delim))
        break;
      tokens.push_back(token);
    }
  }

  static std::pair<std::string, std::string> parse_header_line(const std::string& line) 
  {
    std::size_t pos = 0;
    std::size_t len = 2; /* strlen(": ") */
    std::size_t max = line.length();
    if ((pos = line.find(": ", pos)) == std::string::npos)
      return std::make_pair("", "");
    while ((pos + len) < max && isspace(line.at(pos + len)))
      len++;
    return std::make_pair(line.substr(0, pos), line.substr(pos + len));
  }

  void gen_rfc1123_date(std::string & out) {
    std::time_t now = std::time(nullptr);
    char buf[128];
    std::strftime(buf, sizeof(buf), "%a, %d %b %Y %H:%M:%S GMT", std::gmtime(&now));
    out = buf;
  }

  bool URL::parse(const char *str, std::size_t len) {
    std::string url(str, len ? len : strlen(str));
    return parse(url);
  }

  bool URL::parse(const std::string& url) {
    std::size_t pos_p = 0; /* < current parse position */
    std::size_t pos_c = 0; /* < work position */
    if(url.at(0) != '/' || pos_p > 0) {
      std::size_t pos_s = 0;
      /* schema */
      pos_c = url.find("://");
      if (pos_c != std::string::npos) {
        schema = url.substr(0, pos_c);
        pos_p = pos_c + 3;
      }
      /* user[:pass] */
      pos_s = url.find('/', pos_p); /* find first slash */
      pos_c = url.find('@', pos_p); /* find end of 'user' or 'user:pass' part */
      if (pos_c != std::string::npos && (pos_s == std::string::npos || pos_s > pos_c)) {
        std::size_t delim = url.find(':', pos_p);
        if (delim != std::string::npos && delim < pos_c) {
          user = url.substr(pos_p, delim - pos_p);
          delim += 1;
          pass = url.substr(delim, pos_c - delim);
        } else {
          user = url.substr(pos_p, pos_c - pos_p);
        }
        pos_p = pos_c + 1;
      }
      /* hostname[:port][/path] */
      pos_c = url.find_first_of(":/", pos_p);
      if (pos_c == std::string::npos) {
        /* only hostname, without post and path */
        host = url.substr(pos_p, std::string::npos);
        return true;
      } else if (url.at(pos_c) == ':') {
        host = url.substr(pos_p, pos_c - pos_p);
        /* port[/path] */
        pos_p = pos_c + 1;
        pos_c = url.find('/', pos_p);
        std::string port_str = (pos_c == std::string::npos)
          ? url.substr(pos_p, std::string::npos)
          : url.substr(pos_p, pos_c - pos_p);
        /* stoi throws exception on failure, we don't need it */
        for (char c : port_str) {
          if (c < '0' || c > '9')
            return false;
          port *= 10;
          port += c - '0';
        }
        if (pos_c == std::string::npos)
          return true; /* no path part */
        pos_p = pos_c;
      } else {
        /* start of path part found */
        host = url.substr(pos_p, pos_c - pos_p);
        pos_p = pos_c;
      }
    }

    /* pos_p now at start of path part */
    pos_c = url.find_first_of("?#", pos_p);
    if (pos_c == std::string::npos) {
      /* only path, without fragment and query */
      path = url.substr(pos_p, std::string::npos);
      return true;
    } else if (url.at(pos_c) == '?') {
      /* found query part */
      path = url.substr(pos_p, pos_c - pos_p);
      pos_p = pos_c + 1;
      pos_c = url.find('#', pos_p);
      if (pos_c == std::string::npos) {
        /* no fragment */
        query = url.substr(pos_p, std::string::npos);
        return true;
      } else {
        query = url.substr(pos_p, pos_c - pos_p);
        pos_p = pos_c + 1;
      }
    } else {
      /* found fragment part */
      path = url.substr(pos_p, pos_c - pos_p);
      pos_p = pos_c + 1;
    }

    /* pos_p now at start of fragment part */
    frag = url.substr(pos_p, std::string::npos);
    return true;
  }

  bool URL::parse_query(std::map<std::string, std::string> & params) {
    std::vector<std::string> tokens;
    strsplit(query, tokens, '&');

    params.clear();
    for (const auto& it : tokens) {
      std::size_t eq = it.find ('=');
      if (eq != std::string::npos) {
        auto e = std::pair<std::string, std::string>(it.substr(0, eq), it.substr(eq + 1));
        params.insert(e);
      } else {
        auto e = std::pair<std::string, std::string>(it, "");
        params.insert(e);
      }
    }
    return true;
  }

  std::string URL::to_string() {
    std::string out = "";
    if (schema != "") {
      out = schema + "://";
      if (user != "" && pass != "") {
        out += user + ":" + pass + "@";
      } else if (user != "") {
        out += user + "@";
      }
      if (port) {
        out += host + ":" + std::to_string(port);
      } else {
        out += host;
      }
    }
    out += path;
    if (query != "")
      out += "?" + query;
    if (frag != "")
      out += "#" + frag;
    return out;
  }

  void HTTPMsg::add_header(const char *name, std::string & value, bool replace) {
    add_header(name, value.c_str(), replace);
  }

  void HTTPMsg::add_header(const char *name, const char *value, bool replace) {
    std::size_t count = headers.count(name);
    if (count && !replace)
      return;
    if (count) {
      headers[name] = value;
      return;
    }
    headers.insert(std::pair<std::string, std::string>(name, value));
  }

  void HTTPMsg::del_header(const char *name) {
    headers.erase(name);
  }

  int HTTPReq::parse(const char *buf, size_t len) {
    std::string str(buf, len);
    return parse(str);
  }

  int HTTPReq::parse(const std::string& str) {
    enum { REQ_LINE, HEADER_LINE } expect = REQ_LINE;
    std::size_t eoh = str.find(HTTP_EOH); /* request head size */
    std::size_t eol = 0, pos = 0;
    URL url;

    if (eoh == std::string::npos)
      return 0; /* str not contains complete request */

    while ((eol = str.find(CRLF, pos)) != std::string::npos) {
      if (expect == REQ_LINE) {
        std::string line = str.substr(pos, eol - pos);
        std::vector<std::string> tokens;
        strsplit(line, tokens, ' ');
        if (tokens.size() != 3)
          return -1;
        if (!is_http_method(tokens[0]))
          return -1;
        if (!is_http_version(tokens[2]))
          return -1;
        if (!url.parse(tokens[1]))
          return -1;
        /* all ok */
        method  = tokens[0];
        uri     = tokens[1];
        version = tokens[2];
        expect = HEADER_LINE;
      } 
	  else 
	  {
        std::string line = str.substr(pos, eol - pos);
        auto p = parse_header_line(line);
		if (p.first.length () > 0)
			headers.push_back (p);
		else  
            return -1;
      }
      pos = eol + strlen(CRLF);
      if (pos >= eoh)
        break;
    }
    return eoh + strlen(HTTP_EOH);
  }

  void HTTPReq::write(std::ostream & o) 
  {
	  o << method << " " << uri << " " << version << CRLF;
	  for (auto & h : headers) 
  		o << h.first << ": " << h.second << CRLF;
	  o << CRLF;
  }

	std::string HTTPReq::to_string()
	{
		std::stringstream ss;
		write(ss);
		return ss.str();
	}

	void HTTPReq::AddHeader (const std::string& name, const std::string& value)
	{	
		headers.push_back (std::make_pair(name, value));
	}

	void HTTPReq::UpdateHeader (const std::string& name, const std::string& value)
	{
		 for (auto& it : headers)
			if (it.first == name)
			{
				it.second = value;
				break;
			}	
	}	
	
	void HTTPReq::RemoveHeader (const std::string& name, const std::string& exempt)
	{
		for (auto it = headers.begin (); it != headers.end ();)
		{
			if (!it->first.compare(0, name.length (), name) && it->first != exempt)	
				it = headers.erase (it);
			else
				it++;
		}	
	}	

	std::string HTTPReq::GetHeader (const std::string& name) const 
	{
		 for (auto& it : headers)
			if (it.first == name)
				return it.second;	
		return "";
	}	
	
  bool HTTPRes::is_chunked() const
 {
    auto it = headers.find("Transfer-Encoding");
    if (it == headers.end())
      return false;
    if (it->second.find("chunked") == std::string::npos)
      return true;
    return false;
  }

  bool HTTPRes::is_gzipped(bool includingI2PGzip) const
  {
    auto it = headers.find("Content-Encoding");
    if (it == headers.end())
      return false; /* no header */
    if (it->second.find("gzip") != std::string::npos)
      return true; /* gotcha! */
	if (includingI2PGzip &&  it->second.find("x-i2p-gzip") != std::string::npos)
	  return true;	  
    return false;
  }
	
  long int HTTPMsg::content_length() const
  {
    unsigned long int length = 0;
    auto it = headers.find("Content-Length");
    if (it == headers.end())
      return -1;
    errno = 0;
    length = std::strtoul(it->second.c_str(), (char **) NULL, 10);
    if (errno != 0)
      return -1;
    return length;
  }

  int HTTPRes::parse(const char *buf, size_t len) {
    std::string str(buf, len);
    return parse(str);
  }

  int HTTPRes::parse(const std::string& str) {
    enum { RES_LINE, HEADER_LINE } expect = RES_LINE;
    std::size_t eoh = str.find(HTTP_EOH); /* request head size */
    std::size_t eol = 0, pos = 0;

    if (eoh == std::string::npos)
      return 0; /* str not contains complete request */

    while ((eol = str.find(CRLF, pos)) != std::string::npos) {
      if (expect == RES_LINE) {
        std::string line = str.substr(pos, eol - pos);
        std::vector<std::string> tokens;
        strsplit(line, tokens, ' ', 3);
        if (tokens.size() != 3)
          return -1;
        if (!is_http_version(tokens[0]))
          return -1;
        code = atoi(tokens[1].c_str());
        if (code < 100 || code >= 600)
          return -1;
        /* all ok */
        version = tokens[0];
        status  = tokens[2];
        expect = HEADER_LINE;
      } else {
        std::string line = str.substr(pos, eol - pos);
        auto p = parse_header_line(line);
		if (p.first.length () > 0)
			headers.insert (p);  
		else	  
          return -1;
      }
      pos = eol + strlen(CRLF);
      if (pos >= eoh)
        break;
    }

    return eoh + strlen(HTTP_EOH);
  }

  std::string HTTPRes::to_string() {
    if (version == "HTTP/1.1" && headers.count("Date") == 0) {
      std::string date;
      gen_rfc1123_date(date);
      add_header("Date", date.c_str());
    }
    if (status == "OK" && code != 200)
      status = HTTPCodeToStatus(code); // update
    if (body.length() > 0 && headers.count("Content-Length") == 0)
        add_header("Content-Length", std::to_string(body.length()).c_str());
    /* build response */
    std::stringstream ss;
    ss << version << " " << code << " " << status << CRLF;
    for (auto & h : headers) {
      ss << h.first << ": " << h.second << CRLF;
    }
    ss << CRLF;
    if (body.length() > 0)
      ss << body;
    return ss.str();
  }

  const char * HTTPCodeToStatus(int code) {
    const char *ptr;
    switch (code) {
      case 105: ptr = "Name Not Resolved"; break;
      /* success */
      case 200: ptr = "OK"; break;
      case 206: ptr = "Partial Content"; break;
      /* redirect */
      case 301: ptr = "Moved Permanently"; break;
      case 302: ptr = "Found"; break;
      case 304: ptr = "Not Modified"; break;
      case 307: ptr = "Temporary Redirect"; break;
      /* client error */
      case 400: ptr = "Bad Request";  break;
      case 401: ptr = "Unauthorized"; break;
      case 403: ptr = "Forbidden"; break;
      case 404: ptr = "Not Found"; break;
      case 407: ptr = "Proxy Authentication Required"; break;
      case 408: ptr = "Request Timeout"; break;
      /* server error */
      case 500: ptr = "Internal Server Error"; break;
      case 502: ptr = "Bad Gateway"; break;
      case 503: ptr = "Not Implemented"; break;
      case 504: ptr = "Gateway Timeout"; break;
      default:  ptr = "Unknown Status";  break;
    }
    return ptr;
  }

  std::string UrlDecode(const std::string& data, bool allow_null) {
		std::string decoded(data);
    size_t pos = 0;
    while ((pos = decoded.find('%', pos)) != std::string::npos) {
      char c = strtol(decoded.substr(pos + 1, 2).c_str(), NULL, 16);
      if (c == '\0' && !allow_null) {
        pos += 3;
        continue;
      }
      decoded.replace(pos, 3, 1, c);
      pos++;
    }
    return decoded;
  }

  bool MergeChunkedResponse (std::istream& in, std::ostream& out) {
    std::string hexLen;
    while (!in.eof ()) {
      std::getline (in, hexLen);
      errno = 0;
      long int len = strtoul(hexLen.c_str(), (char **) NULL, 16);
      if (errno != 0)
        return false; /* conversion error */
      if (len == 0)
        return true; /* end of stream */
      if (len < 0 || len > 10 * 1024 * 1024) /* < 10Mb */
        return false; /* too large chunk */
      char * buf = new char[len];
      in.read (buf, len);
      out.write (buf, len);
      delete[] buf;
      std::getline (in, hexLen); // read \r\n after chunk
    }
    return true;
  }
} // http
} // i2p
