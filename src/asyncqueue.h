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

private:
	std::thread thi, tho;
	std::mutex mtx;
	std::condition_variable cv;
	bool finish = false;
	void provide();
	void consume();
};
