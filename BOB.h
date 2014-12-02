#ifndef BOB_H__
#define BOB_H__

#include <thread>
#include <memory>
#include <list>
#include <boost/asio.hpp>
#include "Streaming.h"

namespace i2p
{
namespace client
{
	class BOBDataStream: public std::enable_shared_from_this<BOBDataStream>
	{
		public:

			BOBDataStream (std::shared_ptr<boost::asio::ip::tcp::socket> socket,
				std::shared_ptr<i2p::stream::Stream> stream);

		private:

			std::shared_ptr<boost::asio::ip::tcp::socket> m_Socket;
			std::shared_ptr<i2p::stream::Stream> m_Stream;	
	};	

	class BOBCommandChannel
	{
		public:

			BOBCommandChannel (int port);
			~BOBCommandChannel ();

			void Start ();
			void Stop ();

		private:

			void Run ();
			void Accept ();
			void HandleAccept(const boost::system::error_code& ecode, std::shared_ptr<boost::asio::ip::tcp::socket> socket);

		private:

			bool m_IsRunning;
			std::thread * m_Thread;	
			boost::asio::io_service m_Service;
			boost::asio::ip::tcp::acceptor m_Acceptor;
			std::list<std::shared_ptr<BOBDataStream> > m_DataStreams;
	};	
}
}

#endif

