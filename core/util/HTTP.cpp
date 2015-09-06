#include "HTTP.h"
#include <boost/algorithm/string.hpp>
#include <sstream>

namespace i2p {
namespace util {
namespace http {

void Request::parseRequestLine(const std::string& line)
{
    std::stringstream ss(line);
    ss >> method;
    ss >> uri;
}

void Request::parseHeaderLine(const std::string& line)
{
    const std::size_t pos = line.find_first_of(':');
    headers[boost::trim_copy(line.substr(0, pos))] = boost::trim_copy(line.substr(pos + 1));
}

Request::Request(const std::string& data)
{
    std::stringstream ss(data);
    std::string line;
    std::getline(ss, line);
    parseRequestLine(line);

    while(std::getline(ss, line))
        parseHeaderLine(line);
}

std::string Request::getMethod() const
{
    return method;
}

std::string Request::getUri() const
{
    return uri;
}

std::string Request::getHost() const
{
    return host;
}

int Request::getPort() const
{
    return port;
}

std::string Request::getHeader(const std::string& name) const
{
    return headers.at(name);
}

}
}
}
