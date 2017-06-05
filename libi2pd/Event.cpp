#include "Event.h"
#include "Log.h"

namespace i2p
{
	namespace event
	{
#ifdef WITH_EVENTS
		EventCore core;
#endif

		void EventCore::SetListener(EventListener * l)
		{
			m_listener = l;
			LogPrint(eLogInfo, "Event: listener set");
		}

		void EventCore::QueueEvent(const EventType & ev)
		{
			if(m_listener) m_listener->HandleEvent(ev);
		}

		void EventCore::CollectEvent(const std::string & type, const std::string & ident, uint64_t val)
		{
			std::unique_lock<std::mutex> lock(m_collect_mutex);
			std::string key = type + "." + ident;
			if (m_collected.find(key) == m_collected.end())
			{
				m_collected[key] = {type, key, 0};
			}
		  m_collected[key].Val += val;
		}
		
		void EventCore::PumpCollected(EventListener * listener)
		{
			std::unique_lock<std::mutex> lock(m_collect_mutex);
			if(listener)
			{
				for(const auto & ev : m_collected) {
					listener->HandlePumpEvent({{"type", ev.second.Key}, {"ident", ev.second.Ident}}, ev.second.Val);
				}
			}
			m_collected.clear();
		}
	}
}

void QueueIntEvent(const std::string & type, const std::string & ident, uint64_t val)
{
#ifdef WITH_EVENTS
	i2p::event::core.CollectEvent(type, ident, val);
#endif
}

void EmitEvent(const EventType & e)
{
#if WITH_EVENTS
	i2p::event::core.QueueEvent(e);
#endif
}

