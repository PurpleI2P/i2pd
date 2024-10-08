/*
* Copyright (c) 2013-2024, The PurpleI2P Project
*
* This file is part of Purple i2pd project and licensed under BSD3
*
* See full license text in LICENSE file at top of project tree
*/

#ifndef HTTP_PROXY_H__
#define HTTP_PROXY_H__

namespace i2p {
namespace proxy {
	class HTTPProxy: public i2p::client::TCPIPAcceptor
	{
		public:

			HTTPProxy(const std::string& name, const std::string& address, uint16_t port, const std::string & outproxy, 
				bool addresshelper, bool senduseragent, std::shared_ptr<i2p::client::ClientDestination> localDestination);
			HTTPProxy(const std::string& name, const std::string& address, uint16_t port, std::shared_ptr<i2p::client::ClientDestination> localDestination = nullptr) :
				HTTPProxy(name, address, port, "", true, false, localDestination) {} ;
			~HTTPProxy() {};

			std::string GetOutproxyURL() const { return m_OutproxyUrl; }
			bool GetHelperSupport() const { return m_Addresshelper; }
			bool GetSendUserAgent () const { return m_SendUserAgent; }

		protected:

			// Implements TCPIPAcceptor
			std::shared_ptr<i2p::client::I2PServiceHandler> CreateHandler(std::shared_ptr<boost::asio::ip::tcp::socket> socket);
			const char* GetName() { return m_Name.c_str (); }

		private:

			std::string m_Name;
			std::string m_OutproxyUrl;
			bool m_Addresshelper, m_SendUserAgent;
	};
} // http
} // i2p

#endif
