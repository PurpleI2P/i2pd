#ifndef EVENT_H__
#define EVENT_H__
#include <map>
#include <string>
#include <memory>

#include <boost/asio.hpp>

typedef std::map<std::string, std::string> EventType;

namespace i2p
{
	namespace event
	{
		class EventListener	 {
		public:
			virtual ~EventListener() {};
			virtual void HandleEvent(const EventType & ev) = 0;
		};

		class EventCore
		{
		public:
			void QueueEvent(const EventType & ev);
			void SetListener(EventListener * l);
			
		private:
			EventListener * m_listener = nullptr;
		};
#ifdef WITH_EVENTS		
		extern EventCore core;
#endif
	}
}
void EmitEvent(const EventType & ev);

#endif
