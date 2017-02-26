#include<iostream>
#include<functional>
#include<chrono>
#include "asyncqueue.h"
using namespace std;

template class AsyncQueue<std::string>;

template <typename T> 
AsyncQueue<T>::AsyncQueue(function<T()> provider, function<void(T)> consumer)
{
	this->provider = provider;
	this->consumer = consumer;
	thi = thread(&AsyncQueue::provide, this);
	tho = thread(&AsyncQueue::consume, this);
}

template <typename T> AsyncQueue<T>::AsyncQueue(AsyncQueue&& r)
{
	q = move(r.q);
	thi = move(r.thi);
	tho = move(r.tho);
	provider = move(r.provider);
	consumer = move(r.consumer);
}

template <typename T> AsyncQueue<T>::~AsyncQueue()
{
	finish = true;
	thi.join();
	tho.join();
}

template <typename T> void AsyncQueue<T>::provide()
{///recv->functor->q->notify to sendf
	while(!finish) push_back(provider());
}
	
template <typename T> void AsyncQueue<T>::consume()
{
	unique_lock<mutex> lck{mtx, defer_lock};
	while(!finish) {
		lck.lock();
		while(q.empty()) cv.wait(lck);
		consumer(q.front());
		q.pop_front();
		lck.unlock();
	}
}

template <typename T> void AsyncQueue<T>::push_back(T s)
{///asynchronous send, ->sendf()
	unique_lock<mutex> lck{mtx};
	q.push_back(s);
	lck.unlock();
	cv.notify_all();
}

