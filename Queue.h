#ifndef QUEUE_H__
#define QUEUE_H__

#include <queue>
#include <mutex>
#include <thread>
#include <condition_variable>

namespace i2p
{
namespace util
{
	template<typename Element>
	class Queue
	{	
		public:

			void Put (Element * e)
			{
				std::unique_lock<std::mutex>  l(m_QueueMutex);
				m_Queue.push (e);	
				m_NonEmpty.notify_one ();
			}

			Element * GetNext ()
			{
				std::unique_lock<std::mutex> l(m_QueueMutex);
				Element * el = GetNonThreadSafe ();
				if (!el)
				{
					m_NonEmpty.wait (l);
					el = GetNonThreadSafe ();
				}	
				return el;
			}

			Element * GetNextWithTimeout (int usec)
			{
				std::unique_lock<std::mutex> l(m_QueueMutex);
				Element * el = GetNonThreadSafe ();
				if (!el)
				{
					m_NonEmpty.wait_for (l, std::chrono::milliseconds (usec));
					el = GetNonThreadSafe ();
				}	
				return el;
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
			
			void WakeUp () { m_NonEmpty.notify_one (); };

			Element * Get ()
			{
				std::unique_lock<std::mutex> l(m_QueueMutex);
				return GetNonThreadSafe ();
			}	

			Element * Peek ()
			{
				std::unique_lock<std::mutex> l(m_QueueMutex);
				return GetNonThreadSafe (true);
			}	
			
		private:

			Element * GetNonThreadSafe (bool peek = false)
			{
				if (!m_Queue.empty ())
				{
					Element * el = m_Queue.front ();
					if (!peek)
						m_Queue.pop ();
					return el;
				}				
				return nullptr;
			}	
			
		private:

			std::queue<Element *> m_Queue;
			std::mutex m_QueueMutex;
			std::condition_variable m_NonEmpty;
	};	

	template<class Msg>
	class MsgQueue: public Queue<Msg>
	{
		public:

			MsgQueue (): m_Thread (std::bind (&MsgQueue<Msg>::Run, this)) {};

		private:
			void Run ()
			{
				Msg * msg = nullptr;
				while ((msg = Queue<Msg>::GetNext ()) != nullptr)
				{
					msg->Process ();
					delete msg;
				}	
			}	
			
		private:
			std::thread m_Thread;
	};	
}		
}	

#endif
