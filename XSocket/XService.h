/*
 * Copyright: 7thTool Open Source <i7thTool@qq.com>
 * All rights reserved.
 * 
 * Author	: Scott
 * Email	：i7thTool@qq.com
 * Blog		: http://blog.csdn.net/zhangzq86
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 */
#ifndef _H_XSERVICE_H_
#define _H_XSERVICE_H_

#include <atomic>
#include <mutex>
#ifdef WIN32
#include <shared_mutex>
#else
#include <condition_variable>
#endif
#include <thread>
#include <future>
#include <functional>
#include <algorithm>
#include <vector>
#include <queue>
#include <map>
#include <set>
#include <unordered_map>
#include <unordered_set>
#include <chrono>
#include <iomanip>
#include <sstream>
#if USE_BOOST
#include <boost/lockfree/queue.hpp>
#endif

#include "XSocketDef.h"

namespace XSocket {

	class Service;
	
/*!
 *	@brief IDGenerator 定义.
 *
 *	封装IDGenerator，实现基本服务框架
 */
template<typename _Ty>
class IDGenerator 
{
public:
	static IDGenerator<_Ty>& Inst() {
		static IDGenerator<_Ty> _inst;
		return _inst;
	}
	IDGenerator():id_(0) {}
	_Ty get() {
		return ++id_;
	}
private:
	std::atomic<_Ty> id_;
};
// template<typename _Ty>
// INLINE_GLOBAL IDGenerator<_Ty>::id_;

// /*!
//  *	@brief IDManager 定义.
//  *
//  *	封装IDManager，实现ID管理，判断ID是否存在
//  */
// template<typename _Kty, typename _Ty>
// class IDManager
// {
// public:
// 	static IDManager<_Kty, _Ty>& Inst() {
// 		static IDManager<_Kty, _Ty> _inst;
// 		return _inst;
// 	}

// 	inline void Add(const _Kty& id, const _Ty& val) {
// 		//std::lock_guard<std::mutex> lock(mutex_);
// 		std::unique_lock<std::shared_mutex> lock(mutex_);
// 		map_id2vs_.emplace(id,val);
// 	}
// 	inline bool AddBidi(const _Kty& id, const _Ty& val) {
// 		//std::lock_guard<std::mutex> lock(mutex_);
// 		std::unique_lock<std::shared_mutex> lock(mutex_);
// 		map_id2vs_.emplace(id,val);
// 		map_v2id_.emplace(val,id);
// 		return true;
// 	}
// 	inline void Remove(const _Kty& id) {
// 		//std::lock_guard<std::mutex> lock(mutex_);
// 		std::unique_lock<std::shared_mutex> lock(mutex_);
// 		map_id2vs_.erase(id);
// 	}
// 	inline void RemoveBidi(const _Kty& id) {
// 		//std::lock_guard<std::mutex> lock(mutex_);
// 		std::unique_lock<std::shared_mutex> lock(mutex_);
// 		auto pr = map_id2vs_.equal_range(id);
// 		if(pr.first != map_id2vs_.end()) {
// 			for(auto it = pr.first; it != pr.second; ++it)
// 			{
// 				map_v2id_.erase(it->second);
// 			}
// 			map_id2vs_.erase(pr.first,pr.second);
// 		}
// 	}
// 	inline void RemoveByVal(const _Ty& val) {
// 		//std::lock_guard<std::mutex> lock(mutex_);
// 		std::unique_lock<std::shared_mutex> lock(mutex_);
// 		auto it = map_v2id_.find(val);
// 		if(it != map_v2id_.end()) {
// 			auto itt = map_id2vs_.find(it->second);
// 			while(itt != map_id2vs_.end()) {
// 				if(itt->second == val) {
// 					map_id2vs_.erase(itt);
// 					break;
// 				}
// 				++itt;
// 			}
// 			map_v2id_.erase(it);
// 		}
// 	}
// 	inline bool Find(const _Kty& id) {
// 		//std::lock_guard<std::mutex> lock(mutex_);
// 		std::shared_lock<std::shared_mutex> lock(mutex_);
// 		auto it = map_id2vs_.find(id);
// 		if(it != map_id2vs_.end()) {
// 			return true;
// 		}
// 		return false;
// 	}
// 	inline bool FindByVal(const _Ty& val) {
// 		//std::lock_guard<std::mutex> lock(mutex_);
// 		std::shared_lock<std::shared_mutex> lock(mutex_);
// 		auto it = map_v2id_.find(val);
// 		if(it != map_v2id_.end()) {
// 			return true;
// 		}
// 		return false;
// 	}
// private:
// 	//std::mutex mutex_;
// 	std::shared_mutex mutex_;
// 	std::multimap<_Kty,_Ty> map_id2vs_;
// 	std::unordered_map<_Ty,_Kty> map_v2id_;
// };

/*!
 *	@brief Service 定义.
 *
 *	封装Service，实现基本服务框架
 */
class Service 
{
protected:
    //停止标记，默认停止状态，启动后停止状态为false
    std::atomic<bool> stop_flag_;
	uint32_t idle_flag_:1; //空闲处理标志,0表示不执行空闲任务，1表示执行空闲任务
	uint32_t notify_flag_:1; //通知处理标志,0表示没有通知任务，1表示有通知任务
	uint32_t wait_timeout_:30; //服务等待时间（毫秒）
	std::chrono::steady_clock::time_point timer_time_; //最短定时任务时间,0表示没有定时任务，非0表示最短定时任务
public:
	//static Service* service();

	Service():stop_flag_(true),idle_flag_(true),notify_flag_(false),wait_timeout_(0)
	{

	}
	virtual ~Service() 
	{
		
	}

	inline bool StartTest()
	{
		bool expected = true;
		if (!stop_flag_.compare_exchange_strong(expected, false)) {
			return false; //已经Start过了
		}
		return true;
	}
	inline void Start() { ASSERT(!IsStopFlag()); }
	inline bool StopTest()
	{
		bool expected = false;
		if (!stop_flag_.compare_exchange_strong(expected, true)) {
			return false; //已经Stop过了
		}
		return true;
	}
	inline void Stop() { ASSERT(IsStopFlag()); }
	inline bool IsStopFlag() { return stop_flag_; }

	inline void SetWaitTimeOut(size_t millis) { wait_timeout_ = millis; }
	inline size_t GetWaitTimeOut() { return wait_timeout_; }
	
	inline void PostNotify() { notify_flag_ = true; idle_flag_ = false; }
	inline void PostTimer(size_t millis) { 
		std::chrono::steady_clock::time_point time = std::chrono::steady_clock::now() + std::chrono::milliseconds(millis);
		if(!timer_time_.time_since_epoch().count()) {
			timer_time_ = time;
		} else if(timer_time_ > time) { 
			timer_time_ = time; 
		} 
	}
	
protected:
	//
	inline size_t GetWaitingTimeOut()
	{
		if(notify_flag_) {
			return 0;
		}
		if(timer_time_.time_since_epoch().count()) {
			std::chrono::milliseconds span = std::chrono::duration_cast<std::chrono::milliseconds>(timer_time_ - std::chrono::steady_clock::now());
			int64_t span_count = span.count();
			if(span_count <= 0) {
				return 0;
			}
			if(span_count < wait_timeout_) {
				return span_count;
			}
		}
		return wait_timeout_;
	}

	virtual bool OnStart()
	{
		return true;
	}

	virtual void OnStop()
	{

	}

	virtual void OnNotify()
	{

	}

	virtual void OnWait()
	{

	}
	
	virtual void OnTimer()
	{

	}

	virtual void OnIdle()
	{

	}
	
	virtual void OnRun()
	{
		if(OnStart()) {
			while (!IsStopFlag()) {
				std::chrono::steady_clock::time_point tp = std::chrono::steady_clock::now();
				if(notify_flag_) {
					notify_flag_ = false;
					idle_flag_ = true;
					OnNotify();
				}
				if(IsStopFlag()) {
					break;
				}
				OnWait();
				if(IsStopFlag()) {
					break;
				}
				if(timer_time_.time_since_epoch().count()) {
					if(timer_time_ <= std::chrono::steady_clock::now()) {
						timer_time_ = std::chrono::steady_clock::time_point();
						OnTimer();
					}
				}
				if(idle_flag_) {
					if(IsStopFlag()) {
						break;
					}
					OnIdle(/*std::chrono::duration_cast<std::chrono::milliseconds>(tp.time_since_epoch()).count()*/);
					if(IsStopFlag()) {
						break;
					}
					if(!wait_timeout_) {
						static const std::chrono::microseconds max_span(200);
						std::chrono::microseconds tp_span = std::chrono::duration_cast<std::chrono::microseconds>(std::chrono::steady_clock::now() - tp);
						if(tp_span < max_span) {
							//std::this_thread::yield();
							//std::this_thread::sleep_for(std::chrono::nanoseconds(1));
							std::this_thread::sleep_for(max_span-tp_span);
						}
					}
				}
			}
		}
		OnStop();
	}
};

/*!
 *	@brief TaskID 定义.
 *
 *	封装TaskID，实现Task唯一表示，和比较大小
 */
struct TaskID
{
	TaskID() : id(0), time() {}
	TaskID(size_t _delay) : id(IDGenerator<size_t>::Inst().get()), time(std::chrono::steady_clock::now() + std::chrono::milliseconds(_delay)) {}

	inline operator bool() const { return id != 0; }

	inline bool operator<(const TaskID &o) const
	{
		if (time < o.time) {
			return true;
		} else if (time > o.time) {
			return false;
		}
		return id < o.id;
	}

	const size_t id;
	const std::chrono::steady_clock::time_point time;
};

/*!
 *	@brief TaskQue 模板定义.
 *
 *	封装TaskQue，任务池
 */
class TaskQue
{
public:
	inline void Push(const TaskID& key, std::function<void()> && task)
	{
		//std::lock_guard<std::mutex> lock(mutex_);
		auto it = tasks_.emplace(key,std::move(task));
		ASSERT(it.second);
#ifdef _DEBUG
		printf("task pool delay queue:");
		for(auto& pr : tasks_) {
			ssize_t delay = std::chrono::duration_cast<std::chrono::milliseconds>(pr.first.time-std::chrono::steady_clock::now()).count();
			printf("%d ", (int)delay);
		}
		printf("\n");
#endif//
	}

	inline void Push(std::function<void()> && task)
	{		
		// TaskID key;
		// Post(key, std::move(task));
		//std::lock_guard<std::mutex> lock(mutex_);
		tasks_que_.emplace(std::move(task));
	}

	inline void Remove(const TaskID& t)
	{
		//std::unique_lock<std::mutex> lock(mutex_);
		tasks_.erase(t);
	}

	inline size_t Count() { return tasks_que_.size() + tasks_.size(); }
	inline bool IsEmpty() { return tasks_que_.empty() && tasks_.empty(); }

	inline bool Pop(std::function<void()>& task, ssize_t* dealy)
	{
		if (!tasks_que_.empty()) {
			task = std::move(tasks_que_.front());
			tasks_que_.pop();
			return true;
		} else if(!tasks_.empty()) {
			auto it = tasks_.begin();
			if(IsActive(it->first, dealy)) {
				task = std::move(it->second);
				tasks_.erase(it);
				return true;
			}
		}
		return false;
	}

protected:
	inline bool IsActive(const TaskID& t, ssize_t* delay) {
		ssize_t diff = std::chrono::duration_cast<std::chrono::milliseconds>(t.time-std::chrono::steady_clock::now()).count();
		if(delay) {
			*delay = diff;
		}
		return diff <= 0;
	}
	
private:
	std::map<TaskID,std::function<void()>> tasks_;
	std::queue<std::function<void()>> tasks_que_;
};

/*!
 *	@brief ThreadPool 模板定义.
 *
 *	封装ThreadPool，线程池
 */
class ThreadPool : public TaskQue
{
public:
	static ThreadPool& Inst() {
		static ThreadPool _inst(std::thread::hardware_concurrency() + 1);
		return _inst;
	}

	ThreadPool() : stop_flag_(true)
	{
		
	}
	ThreadPool(size_t threads) : stop_flag_(true)
	{
		Start(threads);
	}

	~ThreadPool()
	{
		Stop();
	}

	inline bool IsStopFlag() {
		return stop_flag_;
	}

	void Start(size_t threads)
	{
		bool expected = true;
		if (!stop_flag_.compare_exchange_strong(expected, false)) {
			return;
		}
		for (size_t i = 0; i < threads; ++i) {
			workers_.emplace_back(
				[this] {
					std::chrono::milliseconds timeout(3000);
					for (;;)
					{
						std::function<void()> task;
						{
							std::unique_lock<std::mutex> lock(mutex_);
							if(!cv_.wait_for(lock, timeout, [this] { return stop_flag_ || !TaskQue::IsEmpty(); })) {
								continue;
							}
							if (stop_flag_)
								break;
							
							ssize_t delay = 0;
							TaskQue::Pop(task,&delay);
							if(delay > 0) {
								timeout = std::chrono::milliseconds(delay);
							} else {
								timeout = std::chrono::milliseconds(3000);
							}
							// if(!tasks_que_.empty()) {
							// 	task = std::move(tasks_que_.front());
							// 	tasks_que_.pop();
							// } else {
							// 	auto it = tasks_.begin();
							// 	std::chrono::steady_clock::time_point tp_now = std::chrono::steady_clock::now();
							// 	if(it->first.time > tp_now) {
							// 		timeout = std::chrono::duration_cast<std::chrono::milliseconds>(it->first.time - tp_now);
							// 		continue;
							// 	} else {
							// 		timeout = std::chrono::milliseconds(3000);
							// 	}
							// 	task = std::move(it->second);
							// 	tasks_.erase(it);
							// }
						}
						task();
					}
				});
		}
		//return true;
	}

	void Stop()
	{
		bool expected = false;
		if (!stop_flag_.compare_exchange_strong(expected, true)) {
			return;
		}
		cv_.notify_all();
		for (auto &worker : workers_) {
			worker.join();
		}
		workers_.clear();
	}

	TaskID Post(const size_t delay, std::function<void()> && task)
	{
		TaskID key(delay);
		std::lock_guard<std::mutex> lock(mutex_);
		TaskQue::Push(key, std::move(task));
		cv_.notify_one();
		return key;
	}

	void Post(std::function<void()> && task)
	{		
		// TaskID key;
		// Post(key, std::move(task));
		std::lock_guard<std::mutex> lock(mutex_);
		TaskQue::Push(std::move(task));
		cv_.notify_one();
	}

	template<class F, class... Args>
	auto Send(const size_t delay, F&& f, Args&&... args) 
		-> std::future<typename std::result_of<F(Args...)>::type>
	{
		using return_type = typename std::result_of<F(Args...)>::type;

		auto task = std::make_shared< std::packaged_task<return_type()> >(
				std::bind(std::forward<F>(f), std::forward<Args>(args)...)
			);
			
		std::future<return_type> res = task->get_future();
		{
			Post(delay, [task](){ (*task)(); });
		}
		return res;
	}

	template<class F, class... Args>
	auto Send(F&& f, Args&&... args) 
		-> std::future<typename std::result_of<F(Args...)>::type>
	{
		// TaskID key;
		// return Send(key, std::forward<F>(f), std::forward<Args>(args)...);
		using return_type = typename std::result_of<F(Args...)>::type;

		auto task = std::make_shared< std::packaged_task<return_type()> >(
				std::bind(std::forward<F>(f), std::forward<Args>(args)...)
			);
			
		std::future<return_type> res = task->get_future();
		{
			Post([task](){ (*task)(); });
		}
		return res;
	}

	void Cancel(const TaskID& t)
	{
		std::unique_lock<std::mutex> lock(mutex_);
		TaskQue::Remove(t);
	}

private:
	std::atomic<bool> stop_flag_;
	std::vector<std::thread> workers_;
	// std::map<TaskID,std::function<void()>> tasks_;
	// std::queue<std::function<void()>> tasks_que_;
	std::mutex mutex_;
	std::condition_variable cv_;
};

class ThreadGroupPool
{
public:
	static ThreadGroupPool& Inst() {
		static ThreadGroupPool _inst(std::thread::hardware_concurrency()+1);
		return _inst;
	}

	ThreadGroupPool() : stop_flag_(true)
	{
		
	}
	ThreadGroupPool(size_t threads) : stop_flag_(true)
	{
		Start(threads);
	}

	~ThreadGroupPool()
	{
		Stop();
	}

	inline bool IsStopFlag() {
		return stop_flag_;
	}

	void Start(size_t threads)
	{
		bool expected = true;
		if (!stop_flag_.compare_exchange_strong(expected, false)) {
			return;
		}

		for (size_t i = 0; i < threads; ++i) {
			workers_.emplace_back(std::make_shared<ThreadPool>(1));
		}
	}

	void Stop()
	{
		bool expected = false;
		if (!stop_flag_.compare_exchange_strong(expected, true)) {
			return;
		}
		for (auto &worker : workers_) {
			worker->Stop();
		}
		workers_.clear();
	}

	ThreadPool& operator[](size_t n) {
		n %= workers_.size();
		return *workers_[n];
	}
	const ThreadPool& operator[](size_t n) const {
		n %= workers_.size();
		return *workers_[n];
	}
private:
	std::atomic<bool> stop_flag_;
	std::vector<std::shared_ptr<ThreadPool>> workers_;
};

/*!
 *	@brief TaskService 定义.
 *
 *	封装TaskService，实现简单事件服务
 */
template<class TBase/* = Service*/>
class TaskServiceT : public TBase, public TaskQue
{
	typedef TBase Base;
public:
	inline TaskID Post(const size_t delay, std::function<void()> && task)
	{
		TaskID key(delay);
 		std::lock_guard<std::mutex> lock(mutex_);
// 		auto it = tasks_.emplace(key,std::move(task));
// 		ASSERT(it.second);
// #ifdef _DEBUG
// 		printf("task delay queue:");
// 		for(auto& pr : tasks_) {
// 			ssize_t delay = 0;
// 			IsActive(pr.first,&delay);
// 			printf("%d ", (int)delay);
// 		}
// 		printf("\n");
// #endif//
		TaskQue::Push(key, std::move(task));
		if (!delay) {
			Base::PostNotify();	
		} else {
			Base::PostTimer(delay);
		}
		return key;
	}

	inline void Post(std::function<void()> && task)
	{
		// TaskID key;
		// Post(key, std::move(task));
		std::lock_guard<std::mutex> lock(mutex_);
		// tasks_que_.emplace(std::move(task));
		TaskQue::Push(std::move(task));
		Base::PostNotify();	
	}

	template<class F, class... Args>
	auto Send(const size_t delay, F&& f, Args&&... args) 
		-> std::future<typename std::result_of<F(Args...)>::type>
	{
		using return_type = typename std::result_of<F(Args...)>::type;

		auto task = std::make_shared< std::packaged_task<return_type()> >(
				std::bind(std::forward<F>(f), std::forward<Args>(args)...)
			);
			
		std::future<return_type> res = task->get_future();
		{
			Post(delay, [task](){ (*task)(); });
		}
		return res;
	}

	template<class F, class... Args>
	inline auto Send(F&& f, Args&&... args) 
		-> std::future<typename std::result_of<F(Args...)>::type>
	{
		// TaskID key;
		// return Send(key, std::forward<F>(f), std::forward<Args>(args)...);
		using return_type = typename std::result_of<F(Args...)>::type;

		auto task = std::make_shared< std::packaged_task<return_type()> >(
				std::bind(std::forward<F>(f), std::forward<Args>(args)...)
			);
			
		std::future<return_type> res = task->get_future();
		{
			Post([task](){ (*task)(); });
		}
		return res;
	}

	void Cancel(const TaskID& t)
	{
		std::unique_lock<std::mutex> lock(mutex_);
		TaskQue::Remove(t);
	}

protected:
	//
	void DoTask()
	{
		// //从头开始消费
		std::unique_lock<std::mutex> lock(mutex_);
		
		// size_t i = 0, j = tasks_que_.size();
		// for(; i < j; i++)
		// {
		// 	auto task = std::move(tasks_que_.front());
		// 	tasks_que_.pop();
		// 	lock.unlock();
		// 	task();
		// 	lock.lock();
		// 	if (tasks_que_.empty()) {
		// 		break;
		// 	}
		// } 

		// i = 0, j = tasks_.size();
		// for(; i < j; i++)
		// {
		// 	auto it = tasks_.begin();
		// 	ssize_t delay = 0;
		// 	if (IsActive(it->first,&delay)) {
		// 		auto task(std::move(it->second));
		// 		tasks_.erase(it);
		// 		lock.unlock();
		// 		task();
		// 		lock.lock();
		// 	} else {
		// 		Base::PostTimer(delay);
		// 		break;
		// 	}
		// 	if (tasks_.empty()) {
		// 		break;
		// 	}
		// }
		
		std::function<void()> task;
		size_t i = 0, j = TaskQue::Count();
		for(; i < j; i++) {
			ssize_t delay = 0;
			if(TaskQue::Pop(task,&delay)) {
				lock.unlock();
				task();
				lock.lock();
			} else {
				if(delay > 0) {
					Base::PostTimer(delay);
				}
				break;
			}
		}
	}
	
	// virtual void OnIdle()
	// {
	// 	DoTask();
	// }
	
	virtual void OnNotify()
	{
		DoTask();
	}
	
	virtual void OnTimer()
	{
		DoTask();
	}

private:
// 	inline bool IsActive(const TaskID& t, ssize_t* delay) {
// 		ssize_t diff = std::chrono::duration_cast<std::chrono::milliseconds>(t.time-std::chrono::steady_clock::now()).count();
// 		if(delay) {
// 			*delay = diff;
// 		}
// 		return diff <= 0;
// 	}
// 	std::map<TaskID,std::function<void()>> tasks_;
// 	std::queue<std::function<void()>> tasks_que_;
	std::mutex mutex_;
};

/*!
 *	@brief CVServiceT 模板定义.
 *
 *	封装CVServiceT，线程池
 */
template<class TBase = Service>
class CVServiceT : public TBase
{
	typedef TBase Base;
public:

	inline void Stop()
	{
		cv_.notify_one(); 
		Base::Stop();
	}
	
	inline void PostNotify() { 
		//std::lock_guard<std::mutex> lock(mutex_);
		Base::PostNotify();
		cv_.notify_one(); 
	}
	
protected:
	//
	virtual void OnWait()
	{
		size_t timeout = Base::GetWaitingTimeOut();
		if (timeout) {
			std::unique_lock<std::mutex> lock(mutex_);
			cv_.wait_for(lock, std::chrono::milliseconds(timeout));
		}
	}

protected:
	std::mutex mutex_;
	std::condition_variable cv_;
};

/*!
 *	@brief ThreadServiceT 定义.
 *
 *	封装ThreadServiceT，实现线程服务服务
 */
template<class TBase = Service>
class ThreadServiceT : public TBase
{
	typedef ThreadServiceT<TBase> This;
	typedef TBase Base;
public:
	bool Start()
	{
		Stop();
		if(!Base::StartTest()) {
			return true; //说明其他线程调用Start了，这里直接返回true
		}
		Base::Start();
		//thread_ = std::thread(std::bind(&This::OnRun, this));
		thread_ptr_ = std::make_shared<std::thread>(std::bind(&This::OnRun,this));
		return true;
	}

	void Stop()
	{
		if(!Base::StopTest()) {
			return; //说明其他线程调用Stop了，这里直接返回
		}
		//thread_.join();
		if(thread_ptr_) {
			thread_ptr_->join();
			thread_ptr_.reset();
		}
		Base::Stop();
	}

protected:
	//线程
	//std::thread thread_;
	std::shared_ptr<std::thread> thread_ptr_;
};

typedef ThreadServiceT<Service> ThreadService;
typedef ThreadServiceT<CVServiceT<Service>> ThreadCVService;

}

#endif//_H_XSERVICE_H_