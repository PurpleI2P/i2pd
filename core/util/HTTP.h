#ifndef _HTTP_H__
#define _HTTP_H__

#include <string>
#include <map>

namespace i2p {
namespace util {
namespace http {

class Request {
    void parseRequestLine(const std::string& line);
    void parseHeaderLine(const std::string& line);
public:
    Request(const std::string& data);

    std::string getMethod() const;

    std::string getUri() const;

    std::string getHost() const;

    int getPort() const;

    /**
     * @throw std::out_of_range if no such header exists
     */
    std::string getHeader(const std::string& name) const;

private:
    std::string method;
    std::string uri;
    std::string host;
    int port;
    std::map<std::string, std::string> headers;
};

}
}
}

#endif // _HTTP_H__
