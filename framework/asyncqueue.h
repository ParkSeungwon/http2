#pragma once
#include <thread>
#include <condition_variable>
#include<functional>
#include <deque>
#include <mutex>

template <typename T> class WaitQueue
{//wait without polling until data is stored by push_back -> consume data
public:
	WaitQueue(std::function<void(T)> consumer);
	WaitQueue(WaitQueue&& r);
	void push_back(T s);

private:
	std::deque<T> q;
	std::function<void(T)> consumer;
	std::thread tho;
	std::timed_mutex mtx;
	std::condition_variable_any cv;
	void consume();
};

template <typename T> class AsyncQueue : public WaitQueue<T>
{//for asyncronous connection
public:
	AsyncQueue(std::function<T()> provider, std::function<void(T)> consumer);
	AsyncQueue(AsyncQueue&& r);
	
private:
	std::function<T()> provider;///<auto respond func
	void provide();
	std::thread thi;
};

