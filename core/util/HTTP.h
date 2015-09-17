#ifndef _HTTP_H__
#define _HTTP_H__

#include <string>
#include <map>
#include <sstream>

namespace i2p {
namespace util {
namespace http {

class Request {

    void parseRequestLine(const std::string& line);

    void parseHeaderLine(const std::string& line);

    void parseHeader(std::stringstream& ss);

    void setIsComplete();
public:
    Request() = default;

    Request(const std::string& data);

    std::string getMethod() const;

    std::string getUri() const;

    std::string getHost() const;

    int getPort() const;

    /**
     * @throw std::out_of_range if no such header exists
     */
    std::string getHeader(const std::string& name) const;

    std::string getContent() const;

    bool hasData() const;

    bool isComplete() const;

    void clear();

    void update(const std::string& data);

private:
    std::string header_part;

    std::string method;
    std::string uri;
    std::string host;
    std::string content;
    int port;
    std::map<std::string, std::string> headers;
    bool has_data;
    bool has_header;
    bool is_complete;
};

class Response {
public:
    Response() = default;

    Response(int status, const std::string& content = "");

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

    void setContentLength();

private:
    int status;
    std::string content;
    std::map<std::string, std::string> headers;
};

/**
 * Handle server side includes.
 */
std::string preprocessContent(const std::string& content, const std::string& path);

/**
 * @return the MIME type based on the extension of the given filename
 */
std::string getMimeType(const std::string& filename);

}
}
}

#endif // _HTTP_H__
