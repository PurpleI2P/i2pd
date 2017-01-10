#ifndef UTIL_H
#define UTIL_H

#include <map>
#include <string>
#include <iostream>
#include <boost/asio.hpp>

#ifdef ANDROID
#include <boost/lexical_cast.hpp>
namespace std
{
template <typename T>
std::string to_string(T value)
{
   return boost::lexical_cast<std::string>(value);
}

inline int stoi(const std::string& str)
{
	return boost::lexical_cast<int>(str);
}
}
#endif

namespace i2p
{
namespace util
{

	template<class T> 
	class MemoryPool
	{
		public:

			MemoryPool (): m_Head (nullptr) {};
			~MemoryPool () 
			{ 
				while (m_Head) 
				{
					auto tmp = m_Head;
					m_Head = static_cast<T*>(*(void * *)m_Head); // next
					delete tmp;
				}
			} 

			template<typename... TArgs>
			T * Acquire (TArgs... args)
			{
				if (!m_Head) return new T(args...);
				else
				{
					auto tmp = m_Head;
					m_Head = static_cast<T*>(*(void * *)m_Head); // next
					return new (tmp)T(args...);
				}
			}

			void Release (T * t)
			{
				t->~T ();
				*(void * *)t = m_Head;
				m_Head = t;	
			}

		private:

			T * m_Head;
	};	

	namespace net
	{
		int GetMTU (const boost::asio::ip::address& localAddress);
		const boost::asio::ip::address GetInterfaceAddress(const std::string & ifname, bool ipv6=false);
	}
}
}

#endif
