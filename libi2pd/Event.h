#ifndef EVENT_H__
#define EVENT_H__
#include <map>
#include <string>
#include <memory>
#include <mutex>
#include <tuple>

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
      /** @brief handle collected event when pumped */
      virtual void HandlePumpEvent(const EventType & ev, const uint64_t & val) = 0;
		};

		class EventCore
		{
		public:
			void QueueEvent(const EventType & ev);
      void CollectEvent(const std::string & type, const std::string & ident, uint64_t val);
			void SetListener(EventListener * l);
      void PumpCollected(EventListener * l);
      
		private:
      std::mutex m_collect_mutex;
      struct CollectedEvent
      {
        std::string Key;
        std::string Ident;
        uint64_t Val;
      };
      std::map<std::string, CollectedEvent> m_collected;
			EventListener * m_listener = nullptr;
		};
#ifdef WITH_EVENTS		
		extern EventCore core;
#endif
	}
}

void QueueIntEvent(const std::string & type, const std::string & ident, uint64_t val);
void EmitEvent(const EventType & ev);

#endif
