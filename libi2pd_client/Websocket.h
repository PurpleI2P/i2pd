#ifndef WEBSOCKET_H__
#define WEBSOCKET_H__
#include "Event.h"
namespace i2p
{
	namespace event
	{

		class WebsocketServerImpl;
		
		class WebsocketServer
		{
		public:
			WebsocketServer(const std::string & addr, int port);
			~WebsocketServer();

			void Start();
			void Stop();

			EventListener * ToListener();
			
		private:
			WebsocketServerImpl * m_impl;
		};

	}
}
#endif
