/*
* Copyright (c) 2013-2020, The PurpleI2P Project
*
* This file is part of Purple i2pd project and licensed under BSD3
*
* See full license text in LICENSE file at top of project tree
*/

#ifndef CRYPTO_WORKER_H_
#define CRYPTO_WORKER_H_

#include <condition_variable>
#include <mutex>
#include <deque>
#include <thread>
#include <vector>
#include <memory>

namespace i2p
{
namespace worker
{
	template<typename Caller>
	struct ThreadPool
	{
		typedef std::function<void(void)> ResultFunc;
		typedef std::function<ResultFunc(void)> WorkFunc;
		typedef std::pair<std::shared_ptr<Caller>, WorkFunc> Job;
		typedef std::mutex mtx_t;
		typedef std::unique_lock<mtx_t> lock_t;
		typedef std::condition_variable cond_t;
		ThreadPool(int workers)
		{
			stop = false;
			if(workers > 0)
			{
				while(workers--)
				{
					threads.emplace_back([this] {
							for (;;)
							{
								Job job;
								{
									lock_t lock(this->queue_mutex);
									this->condition.wait(
										lock, [this] { return this->stop || !this->jobs.empty(); });
									if (this->stop && this->jobs.empty()) return;
									job = std::move(this->jobs.front());
									this->jobs.pop_front();
								}
								ResultFunc result = job.second();
								job.first->GetService().post(result);
							}
					});
				}
			}
		};

		void Offer(const Job & job)
		{
			{
				lock_t lock(queue_mutex);
				if (stop) return;
				jobs.emplace_back(job);
			}
			condition.notify_one();
		}

		~ThreadPool()
		{
			{
				lock_t lock(queue_mutex);
				stop = true;
			}
			condition.notify_all();
			for(auto &t: threads) t.join();
		}

		std::vector<std::thread> threads;
		std::deque<Job> jobs;
		mtx_t queue_mutex;
		cond_t condition;
		bool stop;
	};
}
}

#endif
