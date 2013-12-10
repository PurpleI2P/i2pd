#ifndef LOG_H__
#define LOG_H__

#include <iostream>
#include <sstream>
#include "Queue.h"

struct LogMsg
{
	std::stringstream s;
	std::ostream& output;	

	LogMsg (std::ostream& o = std::cout): output (o) {};
	
	void Process () 
	{
		output << s.str ();
	}
};

extern i2p::util::MsgQueue<LogMsg> g_Log;

template<typename TValue>
void LogPrint (std::stringstream& s, TValue arg) 
{
	s << arg;
}
 
template<typename TValue, typename... TArgs>
void LogPrint (std::stringstream& s, TValue arg, TArgs... args) 
{
	LogPrint (s, arg);
	LogPrint (s, args...);
}

template<typename... TArgs>
void LogPrint (TArgs... args) 
{
	LogMsg * msg = new LogMsg ();
	LogPrint (msg->s, args...);
	msg->s << std::endl;
	g_Log.Put (msg);
}	

#endif
