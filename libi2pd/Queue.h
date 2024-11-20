/*
* Copyright (c) 2013-2024, The PurpleI2P Project
*
* This file is part of Purple i2pd project and licensed under BSD3
*
* See full license text in LICENSE file at top of project tree
*/

#ifndef QUEUE_H__
#define QUEUE_H__

#include <list>
#include <mutex>
#include <thread>
#include <condition_variable>
#include <functional>
#include <utility>

namespace i2p
{
namespace util
{
	template<typename Element>
	class Queue
	{
		public:

			void Put (Element e)
			{
				std::unique_lock<std::mutex> l(m_QueueMutex);
				m_Queue.push_back (std::move(e));
				m_NonEmpty.notify_one ();
			}

			void Put (std::list<Element>& list)
			{
				if (!list.empty ())
				{
					std::unique_lock<std::mutex> l(m_QueueMutex);
					m_Queue.splice (m_Queue.end (), list); 
					m_NonEmpty.notify_one ();
				}	
			}		
		
			Element GetNext ()
			{
				std::unique_lock<std::mutex> l(m_QueueMutex);
				auto el = GetNonThreadSafe ();
				if (!el)
				{
					m_NonEmpty.wait (l);
					el = GetNonThreadSafe ();
				}
				return el;
			}

			Element GetNextWithTimeout (int usec)
			{
				std::unique_lock<std::mutex> l(m_QueueMutex);
				auto el = GetNonThreadSafe ();
				if (!el)
				{
					m_NonEmpty.wait_for (l, std::chrono::milliseconds (usec));
					el = GetNonThreadSafe ();
				}
				return el;
			}

			void Wait ()
			{
				std::unique_lock<std::mutex> l(m_QueueMutex);
				m_NonEmpty.wait (l);
			}

			bool Wait (int sec, int usec)
			{
				std::unique_lock<std::mutex> l(m_QueueMutex);
				return m_NonEmpty.wait_for (l, std::chrono::seconds (sec) + std::chrono::milliseconds (usec)) != std::cv_status::timeout;
			}

			bool IsEmpty ()
			{
				std::unique_lock<std::mutex> l(m_QueueMutex);
				return m_Queue.empty ();
			}

			int GetSize () const
			{
				std::unique_lock<std::mutex> l(m_QueueMutex);
				return m_Queue.size ();
			}

			void WakeUp () { m_NonEmpty.notify_all (); };

			Element Get ()
			{
				std::unique_lock<std::mutex> l(m_QueueMutex);
				return GetNonThreadSafe ();
			}

			Element Peek ()
			{
				std::unique_lock<std::mutex> l(m_QueueMutex);
				return GetNonThreadSafe (true);
			}

			void GetWholeQueue (std::list<Element>& queue)
			{
				if (!queue.empty ())
				{	
					std::list<Element> newQueue;
					queue.swap (newQueue);
				}	
				{
					std::unique_lock<std::mutex> l(m_QueueMutex);
					m_Queue.swap (queue);
				}
			}		

		private:
		
			Element GetNonThreadSafe (bool peek = false)
			{
				if (!m_Queue.empty ())
				{
					auto el = m_Queue.front ();
					if (!peek)
						m_Queue.pop_front ();
					return el;
				}
				return nullptr;
			}

		private:

			std::list<Element> m_Queue;
			mutable std::mutex m_QueueMutex;
			std::condition_variable m_NonEmpty;
	};
}
}

#endif
