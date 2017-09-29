#ifndef UTIL_H
#define UTIL_H

#include <string>
#include <functional>
#include <memory>
#include <mutex>
#include <utility>
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
		BOOST_STATIC_ASSERT_MSG(sizeof(T) >= sizeof(void*), "size cannot be less that general pointer size");

		public:

			MemoryPool (): m_Head (nullptr) {}
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
			T * Acquire (TArgs&&... args)
			{
				if (!m_Head) return new T(std::forward<TArgs>(args)...);
				else
				{
					auto tmp = m_Head;
					m_Head = static_cast<T*>(*(void * *)m_Head); // next
					return new (tmp)T(std::forward<TArgs>(args)...);
				}
			}

			void Release (T * t)
			{
				if (!t) return;
				t->~T ();
				*(void * *)t = m_Head; // next
				m_Head = t;	
			}

			template<typename... TArgs>
			std::unique_ptr<T, std::function<void(T*)> > AcquireUnique (TArgs&&... args)
			{
				return std::unique_ptr<T, std::function<void(T*)> >(Acquire (std::forward<TArgs>(args)...),
					std::bind (&MemoryPool<T>::Release, this, std::placeholders::_1));
			}
			
			template<typename... TArgs>
			std::shared_ptr<T> AcquireShared (TArgs&&... args)
			{
				return std::shared_ptr<T>(Acquire (std::forward<TArgs>(args)...),
					std::bind (&MemoryPool<T>::Release, this, std::placeholders::_1));
			}

		protected:

			T * m_Head;
	};	

	template<class T>
	class MemoryPoolMt: public MemoryPool<T>
	{
		public:

			MemoryPoolMt () {}
			template<typename... TArgs>
			T * AcquireMt (TArgs&&... args)
			{
				if (!this->m_Head) return new T(std::forward<TArgs>(args)...);
				std::lock_guard<std::mutex> l(m_Mutex);
				return this->Acquire (std::forward<TArgs>(args)...);
			}

			void ReleaseMt (T * t)
			{
				std::lock_guard<std::mutex> l(m_Mutex);
				this->Release (t);	
			}

			template<template<typename, typename...>class C, typename... R>
			void ReleaseMt(const C<T *, R...>& c)	
			{
				std::lock_guard<std::mutex> l(m_Mutex);
				for (auto& it: c)
					this->Release (it);
			}	

		private:
		
			std::mutex m_Mutex;
	};

	namespace net
	{
		int GetMTU (const boost::asio::ip::address& localAddress);
		const boost::asio::ip::address GetInterfaceAddress(const std::string & ifname, bool ipv6=false);
	}
}
}

#endif
