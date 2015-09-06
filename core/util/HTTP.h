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

    Request();

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

class Response {
public:

    Response(int status);

    /**
     * @note overrides existing header values with the same name
     */
    void setHeader(const std::string& name, const std::string& value);

    std::string toString() const;

    /**
     * @return the message associated with the satus of this response, or the
     *  empty string if the status number is invalid
     */
    std::string getStatusMessage() const;

private:
    int status;
    std::map<std::string, std::string> headers;
};

}
}
}

#endif // _HTTP_H__
