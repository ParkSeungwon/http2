#pragma once
#include <thread>
#include <condition_variable>
#include <deque>
#include <mutex>

template <typename T> class WaitQueue
{
public:
	WaitQueue(std::function<void(T)> consumer);
	WaitQueue(WaitQueue&& r);
	virtual ~WaitQueue();
	void push_back(T s);

protected:
	std::deque<T> q;
	std::function<void(T)> consumer;
	bool finish = false;
	std::thread tho;
	std::mutex mtx;
	std::condition_variable cv;
	void consume();
};

template <typename T> class AsyncQueue : public WaitQueue<T>
{//for asyncronous connection
public:
	AsyncQueue(std::function<T()> provider, std::function<void(T)> consumer);
	AsyncQueue(AsyncQueue&& r);
	virtual ~AsyncQueue();
	
protected:
	std::function<T()> provider;///<auto respond func
	void provide();
	std::thread thi;
};

