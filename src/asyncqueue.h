#pragma once
#include <thread>
#include <condition_variable>
#include <deque>
#include <mutex>

template <typename T> class AsyncQueue 
{//for asyncronous connection
public:
	AsyncQueue(std::function<T()> provider, std::function<void(T)> consumer);
	AsyncQueue(AsyncQueue&& r);
	~AsyncQueue();
	void push_back(T s);
	
protected:
	std::deque<T> q;///<queue to send
	std::function<T()> provider;///<auto respond func
	std::function<void(T)> consumer;
	bool finish = false;

private:
	std::thread thi, tho;
	std::mutex mtx;
	std::condition_variable cv;
	void provide();
	void consume();
};

template <typename T> class WaitQueue : public AsyncQueue<T>
{//asyncqueue without provider, push_back from outside
public:
	WaitQueue(std::function<void(T)> f);
	
private:
	T wait();
};

