#ifndef SAM_H__
#define SAM_H__

#include <thread>
#include <boost/asio.hpp>

namespace i2p
{
namespace stream
{
	class SAMBridge
	{
		public:

			SAMBridge (int port);
			~SAMBridge ();

			void Start ();
			void Stop ();

		private:

			void Run ();

			void Accept ();
			void HandleAccept(const boost::system::error_code& ecode);

		private:

			bool m_IsRunning;
			std::thread * m_Thread;	
			boost::asio::io_service m_Service;
			boost::asio::ip::tcp::acceptor m_Acceptor;
			boost::asio::ip::tcp::socket * m_NewSocket;
	};		
}
}

#endif

