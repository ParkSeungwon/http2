#include<iostream>
#include<functional>
#include<chrono>
#include "asyncqueue.h"
#include"middle.h"

using namespace std;

template class AsyncQueue<Packet>;
template class AsyncQueue<string>;

template<typename T> WaitQueue<T>::WaitQueue(function<void(T)> consumer)
{
	this->consumer = consumer;
	tho = thread(&WaitQueue::consume, this);
}

template <typename T> 
AsyncQueue<T>::AsyncQueue(function<T()> provider, function<void(T)> consumer) 
	: WaitQueue<T>{consumer}
{
	this->provider = provider;
	thi = thread(&AsyncQueue::provide, this);
}

template<typename T> WaitQueue<T>::WaitQueue(WaitQueue&& r)
{
	q = move(r.q);
	tho = move(r.tho);
	consumer = move(r.consumer);
}

template <typename T> AsyncQueue<T>::AsyncQueue(AsyncQueue&& r) : WaitQueue<T>{move(r)}
{
	thi = move(r.thi);
	provider = move(r.provider);
}

template<typename T> WaitQueue<T>::~WaitQueue()
{
	finish = true;
	tho.join();
}

template <typename T> AsyncQueue<T>::~AsyncQueue()
{
	thi.join();
}

template <typename T> void AsyncQueue<T>::provide()
{///recv->functor->q->notify to sendf
	while(!WaitQueue<T>::finish) WaitQueue<T>::push_back(provider());
}
	
template <typename T> void WaitQueue<T>::consume()
{
	unique_lock<mutex> lck{mtx, defer_lock};
	while(!finish) {
		lck.lock();
		while(q.empty()) cv.wait(lck);
		for(auto& a : q) consumer(a);
		q.clear();
		lck.unlock();
	}
}

template <typename T> void WaitQueue<T>::push_back(T s)
{///asynchronous send, ->sendf()
	unique_lock<mutex> lck{mtx};
	q.push_back(s);
	lck.unlock();
	cv.notify_all();
}
