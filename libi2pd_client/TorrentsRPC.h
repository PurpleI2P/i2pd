/*
* Copyright (c) 2026, The PurpleI2P Project
*
* This file is part of Purple i2pd project and licensed under BSD3
*
* See full license text in LICENSE file at top of project tree
*/

#ifndef TORRENTS_RPC_H__
#define TORRENTS_RPC_H__

#include <inttypes.h>
#include <memory>
#include <string>
#include <string_view>
#include <map>
#include <boost/asio.hpp>
#include <boost/beast.hpp>
#include "util.h"

namespace i2p
{
namespace torrents
{
	class TorrentsRPCServer;
	class TorrentsRPCSession: public std::enable_shared_from_this<TorrentsRPCSession>
	{
		public:

			TorrentsRPCSession (TorrentsRPCServer& server, boost::asio::ip::tcp::socket&& s);

			void ReceiveRequest ();

		private:

			void HandleRequest (const boost::system::error_code& ecode, size_t bytes_transferred);
			void SendResponse (boost::beast::http::status result, std::string_view data = "");

		private:

			TorrentsRPCServer& m_Server;
			boost::asio::ip::tcp::socket m_Socket;
			boost::beast::flat_buffer m_ReceiveBuffer;
			boost::beast::http::request<boost::beast::http::string_body> m_Request;
			boost::beast::http::response<boost::beast::http::string_body> m_Response;
	};

	class TorrentsTunnel;
	class TorrentsRPCServer final: private i2p::util::RunnableServiceWithWork
	{
		public:

			TorrentsRPCServer (uint16_t port);

			auto& GetService () { return GetIOService (); }
			void Start ();
			void Stop ();

			void AddTunnel (std::string_view path, std::shared_ptr<TorrentsTunnel> tunnel);
			std::shared_ptr<TorrentsTunnel> GetTunnel (std::string_view path) const;

		private:

			void Accept ();

		private:

			boost::asio::ip::tcp::acceptor m_Acceptor;
			std::map<std::string, std::weak_ptr<TorrentsTunnel>, std::less<> > m_Tunnels; // path->tunnel
	};
}
}

#endif
