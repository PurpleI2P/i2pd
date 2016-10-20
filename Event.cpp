#include "Event.h"
#include "Log.h"

namespace i2p
{
  namespace event
  {
    EventCore core;

    void EventCore::SetListener(EventListener * l)
    {
      m_listener = l;
      LogPrint(eLogInfo, "Event: listener set");
    }

    void EventCore::QueueEvent(const EventType & ev)
    {
      if(m_listener)
        m_listener->HandleEvent(ev);
    }
  }
}

void EmitEvent(const EventType & e)
{
  i2p::event::core.QueueEvent(e);
}

