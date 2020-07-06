/*
* Copyright (c) 2013-2020, The PurpleI2P Project
*
* This file is part of Purple i2pd project and licensed under BSD3
*
* See full license text in LICENSE file at top of project tree
*/

#ifndef HTTP_H__
#define HTTP_H__

#include <cstring>
#include <map>
#include <list>
#include <sstream>
#include <string>
#include <vector>

namespace i2p
{
namespace http
{
	const char CRLF[] = "\r\n";         /**< HTTP line terminator */
	const char HTTP_EOH[] = "\r\n\r\n"; /**< HTTP end-of-headers mark */
	extern const std::vector<std::string> HTTP_METHODS;  /**< list of valid HTTP methods */
	extern const std::vector<std::string> HTTP_VERSIONS; /**< list of valid HTTP versions */

	struct URL
	{
		std::string schema;
		std::string user;
		std::string pass;
		std::string host;
		unsigned short int port;
		std::string path;
		std::string query;
		std::string frag;

		URL(): schema(""), user(""), pass(""), host(""), port(0), path(""), query(""), frag("") {};

		/**
		 * @brief Tries to parse url from string
		 * @return true on success, false on invalid url
		 */
		bool parse (const char *str, std::size_t len = 0);
		bool parse (const std::string& url);

		/**
		 * @brief Parse query part of url to key/value map
		 * @note Honestly, this should be implemented with std::multimap
		 */
		bool parse_query(std::map<std::string, std::string> & params);

		/**
		 * @brief Serialize URL structure to url
		 * @note Returns relative url if schema if empty, absolute url otherwise
		 */
		std::string to_string ();

		/**
		 * @brief return true if the host is inside i2p
		 */
		bool is_i2p() const;
	};

	struct HTTPMsg
	{
		std::map<std::string, std::string> headers;

		void add_header(const char *name, std::string & value, bool replace = false);
		void add_header(const char *name, const char *value, bool replace = false);
		void del_header(const char *name);

		/** @brief Returns declared message length or -1 if unknown */
		long int content_length() const;
	};

	struct HTTPReq
	{
		std::list<std::pair<std::string, std::string> > headers;
		std::string version;
		std::string method;
		std::string uri;

		HTTPReq (): version("HTTP/1.0"), method("GET"), uri("/") {};

		/**
		 * @brief Tries to parse HTTP request from string
		 * @return -1 on error, 0 on incomplete query, >0 on success
		 * @note Positive return value is a size of header
		 */
		int parse(const char *buf, size_t len);
		int parse(const std::string& buf);

		/** @brief Serialize HTTP request to string */
		std::string to_string();
		void write(std::ostream & o);

		void AddHeader (const std::string& name, const std::string& value);
		void UpdateHeader (const std::string& name, const std::string& value);
		void RemoveHeader (const std::string& name, const std::string& exempt); // remove all headers starting with name, but exempt
		void RemoveHeader (const std::string& name) { RemoveHeader (name, ""); };
		std::string GetHeader (const std::string& name) const;
	};

	struct HTTPRes : HTTPMsg {
		std::string version;
		std::string status;
		unsigned short int code;
		/**
		 * @brief Simplifies response generation
		 *
		 * If this variable is set, on @a to_string() call:
		 *   * Content-Length header will be added if missing,
		 *   * contents of @a body will be included in generated response
		 */
		std::string body;

		HTTPRes (): version("HTTP/1.1"), status("OK"), code(200) {}

		/**
		 * @brief Tries to parse HTTP response from string
		 * @return -1 on error, 0 on incomplete query, >0 on success
		 * @note Positive return value is a size of header
		 */
		int parse(const char *buf, size_t len);
		int parse(const std::string& buf);

		/**
		 * @brief Serialize HTTP response to string
		 * @note If @a version is set to HTTP/1.1, and Date header is missing,
		 *   it will be generated based on current time and added to headers
		 * @note If @a body is set and Content-Length header is missing,
		 *   this header will be added, based on body's length
		 */
		std::string to_string();

		void write(std::ostream & o);

		/** @brief Checks that response declared as chunked data */
		bool is_chunked() const ;

		/** @brief Checks that response contains compressed data */
		bool is_gzipped(bool includingI2PGzip = true) const;
	};

	/**
	 * @brief returns HTTP status string by integer code
	 * @param code HTTP code [100, 599]
	 * @return Immutable string with status
	 */
	const char * HTTPCodeToStatus(int code);

	/**
	 * @brief Replaces %-encoded characters in string with their values
	 * @param data Source string
	 * @param null If set to true - decode also %00 sequence, otherwise - skip
	 * @return Decoded string
	 */
	std::string UrlDecode(const std::string& data, bool null = false);

	/**
	 * @brief Merge HTTP response content with Transfer-Encoding: chunked
	 * @param in  Input stream
	 * @param out Output stream
	 * @return true on success, false otherwise
	 */
	bool MergeChunkedResponse (std::istream& in, std::ostream& out);
} // http
} // i2p

#endif /* HTTP_H__ */
