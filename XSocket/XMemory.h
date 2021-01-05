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
#ifndef _H_XMEMORY_H_
#define _H_XMEMORY_H_

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

#if USE_MEMORY_POOL

	/*!
	 *	@brief MemoryPool 模板定义.
	 *
	 *	封装MemoryPool，内存池
	 */
	class MemoryPool
	{
	public:
		class Memory 
		{ 
		public:
			//内存块 
			struct Block 
			{ 
				size_t total_size;		//可分配内存总大小 
				size_t free_num;		//可分配内存单元数目 
				size_t next_pos;		//下一个可分配的内存位置
				Block* next_ptr;		//指向下一个内存块
				char data[1];

				//num : 是指内存单元的个数， unit_size : 是指单个内存单元大小
				void* operator new(size_t, const size_t& num, const size_t& unit_size) {
					return ::operator new(sizeof(Block) + num * unit_size);
				}

				void operator delete(void* del, size_t) {
					::operator delete(del);
				}

				//num : 是指内存单元的个数， unit_size : 是指单个内存单元大小
				Block(const size_t& num, const size_t& unit_size):total_size(num*unit_size),free_num(num),next_pos(0),next_ptr(0) {
					PRINTF("Block(size_t num = %ld, unit_size = %ld)", num, unit_size);
					//初始都是自由内存，让它们记住自己被分配后，下一个可分配内存的位置,形成位置环路，0指向位置1，最后指向位置0
					char* p = data;
					for(size_t i=1; i<num; i++) {
						*reinterpret_cast<size_t*>(p) = i;
						p += unit_size;
					}
					*reinterpret_cast<size_t*>(p) = 0;
				} 

				~Block(){
					PRINTF("~Block(size_t num = %ld, unit_size = %ld)", free_num, total_size/free_num);
				} 
			}; 
		private: 
			size_t unit_size_;		//一个可分配单元的大小
			size_t init_num_;		//第一个可分配空间数目
			size_t grow_num_;		//新增的可分配空间数目
			Block* first_ptr_;		//指向第一个内存块

			void FreeBlock()//销毁内存
			{ 
				//PRINTF("FreeBlock");
				Block* block_ptr = first_ptr_;
				while(block_ptr)  {
					first_ptr_ = block_ptr->next_ptr;
					delete block_ptr;
					block_ptr = first_ptr_;
				}
				first_ptr_ = nullptr;
			} 
		public: 
			//单元大小，第一个内存块的可分配空间数目，第二个内存块之后的可分配空间数目 
			Memory(const size_t& unit_size, const size_t& init_num = 1024, const size_t& grow_num = 1024)
			:first_ptr_(0), init_num_(init_num), grow_num_(grow_num) { 
				const size_t MEMPOOL_ALIGNMENT = sizeof(size_t); 
				if(unit_size > MEMPOOL_ALIGNMENT) {//unit_size_ 取整到大于unit_size的最大的MEMPOOL_ALIGNMENT的倍数. 
					unit_size_ = (unit_size + (MEMPOOL_ALIGNMENT - 1)) & ~(MEMPOOL_ALIGNMENT - 1);
				} else {
					unit_size_ = MEMPOOL_ALIGNMENT;
				}
				PRINTF("Memory(unit_size_=%d, init_num_=%d, grow_num_=%d", unit_size_, init_num_, grow_num_);
			} 

			~Memory()
			{ 
				FreeBlock(); 
			} 

			void* Alloc()			//分配内存 
			{ 
				if(!first_ptr_) {
					Block* pmb_first = new (init_num_, unit_size_)Block(init_num_, unit_size_);
					first_ptr_ = pmb_first;
				}

				Block* block_ptr = first_ptr_;
				while(block_ptr && block_ptr->free_num == 0)  { 
					block_ptr = block_ptr->next_ptr; 
				} 
				if(!block_ptr) {
					block_ptr = new (grow_num_, unit_size_)Block(grow_num_, unit_size_);
					if(block_ptr) {
						block_ptr->next_ptr = first_ptr_;
						first_ptr_ = block_ptr;
					}
				}
				if(block_ptr) {
					char* pfree = block_ptr->data + (block_ptr->next_pos * unit_size_);
					block_ptr->next_pos = *((size_t*)pfree);	//下一个可分配的内存位置
					block_ptr->free_num--;
					//PRINTF("New[%d]", block_ptr->free_num);
					return (void*)pfree;
				}
				return nullptr;
			} 

			void Free(void* pfree)	//回收内存
			{ 
				Block* block_ptr = first_ptr_;
				Block* old_block_ptr = nullptr;
				while(block_ptr && 
					(pfree<block_ptr->data || pfree>=(block_ptr->data+block_ptr->total_size))) { 
						old_block_ptr = block_ptr;
						block_ptr = block_ptr->next_ptr;
				}
				if (block_ptr) {
					block_ptr->free_num++;
					*((size_t*)pfree) = block_ptr->next_pos;
					block_ptr->next_pos = (size_t)((char*)pfree - block_ptr->data)/unit_size_;//下一个可分配的内存位置
					if(block_ptr->free_num * unit_size_ >= block_ptr->total_size) {//如果该块已全部释放
						if (old_block_ptr) {
							old_block_ptr->next_ptr = block_ptr->next_ptr;
							delete block_ptr;
						} else {//只有这一块，释放了，所以first_ptr_ = nullptr
							//first_ptr_ = nullptr;
							//保留最后一块内存块,这样也能避免后面有重新new内存块
						}
					}
					//PRINTF("Delete[%d]", block_ptr->free_num);
				} else {
					ASSERT(0);
				}
			}
		};
		class MemoryMt : public Memory
		{
		protected:
			std::mutex mutex_;
		public:
			using Memory::Memory;

			void* Alloc() {
				std::lock_guard<std::mutex> lock(mutex_);
				return Memory::Alloc();
			}

			void Free(void* pfree) {
				std::lock_guard<std::mutex> lock(mutex_);
				Memory::Free(pfree);
			}
		};
	protected:
		size_t use_free_ = 0; //最大使用free内存大小
		std::mutex mutex_; //free内存锁
		std::vector<size_t*> free_; //当前使用free内存列表
		size_t free_size_ = 0; //当前使用free内存总大小
		//
		std::map<size_t,MemoryMt*> pool_;
	public:
		static MemoryPool& Inst() {
			static MemoryPool _inst;
			return _inst;
		}

		MemoryPool()
		{
		}

		~MemoryPool()
		{
			if(use_free_) {
				for(auto& pfree : free_) 
				{
					free(pfree);
				}
				free_.clear();
				free_size_ = 0;
			}
			for(auto& pr : pool_)
			{
				delete pr.second;
			}
			pool_.clear();
		}

		inline void UseFree(size_t max_size = (size_t)-1) { use_free_ = max_size; }

		inline void AddAllocator(const size_t& unit_size, const size_t& init_num = 1024, const size_t& grow_num = 1024)
		{
			const size_t MEMPOOL_ALIGNMENT = sizeof(size_t); 
			size_t key = MEMPOOL_ALIGNMENT;
			if(unit_size > MEMPOOL_ALIGNMENT) {//取整到大于unit_size的最大的MEMPOOL_ALIGNMENT的倍数. 
				key = (unit_size + (MEMPOOL_ALIGNMENT - 1)) & ~(MEMPOOL_ALIGNMENT - 1);
			}
			pool_[key] = new MemoryMt(unit_size, init_num, grow_num);
		}

		inline void AddDefaultAllocator()
		{
			AddAllocator(64);
			AddAllocator(256);
			AddAllocator(1024);
			AddAllocator(4096);
			AddAllocator(4096*4);
		}

		void* Alloc(size_t size) 
		{//分配内存 
			auto it_pool = pool_.rbegin();
			if(it_pool == pool_.rend() || size > it_pool->first) {
				if(use_free_) {
					if(free_size_ > size) {
						ASSERT(!free_.empty());
						std::lock_guard<std::mutex> lock(mutex_);
						auto it_free = std::lower_bound(free_.begin(), free_.end(), &size, [this](size_t* x, size_t* y) {
							return *x < *y;
						});
						while(it_free != free_.end()) {
							auto pfree = *it_free;
							if(*pfree >= size) {
								free_.erase(it_free);
								free_size_ -= *pfree;
								return pfree + 1;
								break;
							}
							++it_free;
						}
					}
					//do {
						size_t* pfree  = (size_t*)malloc(sizeof(size_t) + size);
						if(pfree) {
							*pfree = size;
							return pfree + 1;
						}
					// 	if(free_.empty()) {
					// 		break;
					// 	}
					// 	{
					// 		std::lock_guard<std::mutex> lock(mutex_);
					// 		auto it_free = free_.rbegin();
					// 		pfree = *it_free;
					// 		free_.erase(it_free.base());
					// 	}
					// 	free(pfree);
					// } while(true);
				} else {
					return malloc(size);
				}
			} else {
				auto it_larger = it_pool++;
				while(it_pool != pool_.rend()) {
					if (size > it_pool->first) {
						return it_larger->second->Alloc();
					} 
					it_larger = it_pool++;
				}
				return it_larger->second->Alloc();
			}
			return nullptr;
		}

		void Free(void* ptr, size_t size) 
		{//回收内存
			auto it_pool = pool_.rbegin();
			if(it_pool == pool_.rend() || size > it_pool->first) {
				if(use_free_) {
					auto pfree = (size_t*)ptr - 1;
					ASSERT(*pfree >= size);
					if((free_size_ + size) < use_free_) {
						std::lock_guard<std::mutex> lock(mutex_);
						auto it_free = std::lower_bound(free_.begin(), free_.end(), pfree, [this](size_t* x, size_t* y) {
							return *x < *y;
						});
						free_.insert(it_free, pfree);
						free_size_ += *pfree;
					} else {
						free(pfree);
					}
				} else {
					free(ptr);
				}
			} else {
				auto it_larger = it_pool++;
				while(it_pool != pool_.rend()) {
					if (size > it_pool->first) {
						it_larger->second->Free(ptr);
						return;
					} 
					it_larger = it_pool++;
				}
				it_larger->second->Free(ptr);
			}
		}

		void Free()
		{//清理内存，释放部分可以释放的内存
			if(use_free_) {
				std::lock_guard<std::mutex> lock(mutex_);
				for(auto& pfree : free_) 
				{
					free(pfree);
				}
				free_.clear();
				free_size_ = 0;
			}
		}
	};
	
	template <class T>
	class AllocatorT : public std::allocator<T>
	{
		typedef AllocatorT<T> This;
		typedef std::allocator<T> Base;
	public:
		using value_type = T;
		using size_type = size_t;

		template <class U>
		struct rebind
		{
			using other = AllocatorT<U>;
		};
	public:
		using Base::Base;

		T *allocate(size_type n, std::allocator<void>::const_pointer hint = 0)
		{
			return static_cast<T *>(MemoryPool::Inst().Alloc(sizeof(T) * n));
			//return static_cast<T *>(operator new(sizeof(T) * n));
		}

		void deallocate(T *p, size_type n)
		{
			MemoryPool::Inst().Free(p, sizeof(T) * n);
			//operator delete(p);
		}
	};

#else

	template <class T>
	using AllocatorT = std::allocator<T>;

#endif//

	/*!
	 *	@brief ObjectPool 模板定义.
	 *
	 *	封装ObjectPool，对象池
	 */
	class ObjectPool
	{
	public:
#if USE_MEMORY_POOL
		template<class TBase>
		class ObjectNewT : public TBase
		{
			typedef ObjectNewT<TBase> This;
			typedef TBase Base;
		public:
			using Base::Base;

			void* operator new(size_t size)
			{
				ASSERT(size == sizeof(This));
				return MemoryPool::Inst().Alloc(size);
			}

			void operator delete(void *p)
			{
				MemoryPool::Inst().Free(p, sizeof(This));
			}
		};
	public:
		template<class _Ty, class... _Types> inline
		static _Ty* make_new(_Types&&... _Args)
		{	// new a pointer
			return new ObjectNewT<_Ty>(std::forward<_Types>(_Args)...);
		}

		template<class _Ty, class... _Types> inline
		static std::shared_ptr<_Ty> make_shared(_Types&&... _Args)
		{	// make a shared_ptr
			_Ty* p = MemoryPool::Inst().Alloc(sizeof(_Ty));
			::new ((void *)p) _Ty(std::forward<_Types>(_Args)...);
			return std::shared_ptr<_Ty>(p,[](_Ty* p) {
				MemoryPool::Inst().Free(p, sizeof(_Ty));
			});
		}
#else
		template<class _Ty, class... _Types> inline
		static std::shared_ptr<_Ty> make_shared(_Types&&... _Args)
		{	// make a shared_ptr
			return std::make_shared<_Ty>(std::forward<_Types>(_Args)...);
		}
#endif//
	};

	/*!
	 *	@brief ObjectPoolT 模板定义.
	 *
	 *	封装ObjectPoolT，对象池
	 */
	template<class T, class _Ty>
	class ObjectPoolT
	{
	public:
		ObjectPoolT():count_(0)
		{
		}
		ObjectPoolT(size_t count, size_t max_count = 0)
		{
			Init(count, max_count);
		}
		~ObjectPoolT()
		{
			Release();
		}

		void Init(size_t count, size_t max_count = 0)
		{
			T* pT = static_cast<T*>(this);
			count_ = count;
			max_count_ = max_count;
			for(size_t i = 0; i < count_; i++)
			{
	#if USE_BOOST
				objptrs_.push(pT->Alloc());
	#else
				objptrs_.emplace(pT->Alloc());
	#endif
			}
		}

		void Release()
		{
			T* pT = static_cast<T*>(this);
	#if USE_BOOST
			while(count_ != objptrs_.size())) {
				std::this_thread::sleep_for(std::chrono::nanoseconds(1000));
			}
			auto objptr = nullptr;
			while(!objptrs_.pop(objptr)) {
				pT->Free(objptr);
			}
	#else
			std::unique_lock<std::mutex> lock(mutex_);
			while(count_ != objptrs_.size()) {
				cv_.wait(lock);
			}
			count_ = 0;
			max_count_ = 0;
			while(!objptrs_.empty()) {
				auto objptr = objptrs_.front();
				pT->Free(objptr);
				objptrs_.pop();
			}
	#endif
		}

		inline size_t MaxCount() { return max_count_; }
		inline size_t Count() { return count_; }

		/*template<typename _Rep, typename _Period>
		std::shared_ptr<_Ty> New(const std::chrono::duration<_Rep, _Period>& timeout)
		{
			std::unique_lock<std::mutex> lock(mutex_);
			if(!cv_.wait_for(lock,timeout,[this] { return !objptrs_.empty(); })) {
				return nullptr;
			}
			auto objptr = std::shared_ptr<_Ty>(objptrs_.front(),[this](_Ty* objptr){ 
				std::lock_guard<std::mutex> lock(mutex_);
				objptrs_.emplace(objptr);
				cv_.notify_one();
			});
			objptrs_.pop();
			return objptr;
		}*/

		std::shared_ptr<_Ty> New()
		{
			T* pT = static_cast<T*>(this);
			_Ty* objptr = nullptr;
	#if USE_BOOST
			if(!objptrs_.pop(objptr)) {
				if(max_count_ && count_ > max_count_) {
					do {
						std::this_thread::sleep_for(std::chrono::nanoseconds(1000));
					} while(!objptrs_.pop(objptr));
				} else {
					objptr = pT->Alloc();
					count_++;
				}
			} 
			auto sp_objptr = std::shared_ptr<_Ty>(objptr,[this](_Ty* objptr) { 
				objptrs_.push(objptr);
			});
			return sp_objptr;
	#else
			std::unique_lock<std::mutex> lock(mutex_);
			if(objptrs_.empty()) {
				if(max_count_ && count_ > max_count_) {
					cv_.wait(lock);
					objptr = objptrs_.front();
					objptrs_.pop();
				} else {
					objptr = pT->Alloc();
					count_++;
				}
			} else {
				objptr = objptrs_.front();
				objptrs_.pop();
			}
			auto sp_objptr = std::shared_ptr<_Ty>(objptr,[this](_Ty* objptr) { 
				std::lock_guard<std::mutex> lock(mutex_);
				objptrs_.emplace(objptr);
				cv_.notify_one();
			});
			return sp_objptr;
	#endif
		}
	protected:
		inline _Ty* Alloc() { return new _Ty(); }
		inline void Free(_Ty* ptr) { return delete ptr; }
	private:
		size_t max_count_ = 0; //0表示不限制
		std::atomic<size_t> count_;
	#if USE_BOOST
		boost::lockfree::queue<_Ty > objptrs_;
	#else
		std::queue<_Ty*> objptrs_;
		std::mutex mutex_;
		std::condition_variable cv_;
	#endif
	};
}

#endif//_H_XMEMORY_H_