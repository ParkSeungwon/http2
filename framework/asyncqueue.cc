#include<iostream>
#include<functional>
#include<chrono>
#include"asyncqueue.h"
#include"middle.h"

using namespace std;

template class AsyncQueue<Packet>;//automatically create WaitQueue object also
template class AsyncQueue<string>;//prevent undefined reference

template<typename T> WaitQueue<T>::WaitQueue(function<void(T)> consumer)
{
	this->consumer = consumer;
	tho = thread(&WaitQueue::consume, this);
	tho.detach();//blocking functions cannot be joined
}

template<typename T> WaitQueue<T>::WaitQueue(WaitQueue&& r)
{
	q = move(r.q);
	tho = move(r.tho);
	consumer = move(r.consumer);
}

template <typename T> void WaitQueue<T>::consume()
{
	unique_lock<timed_mutex> lck{mtx, defer_lock};
	while(1) {
		lck.lock();
		while(q.empty()) cv.wait(lck);
		for(auto& a : q) consumer(a);
		q.clear();
		lck.unlock();
	}
}

template <typename T> void WaitQueue<T>::push_back(T s)
{///asynchronous send, ->sendf()
	if(mtx.try_lock_for(1s)) {
		q.push_back(s);
		mtx.unlock();
		cv.notify_all();
	}
}

template <typename T> 
AsyncQueue<T>::AsyncQueue(function<T()> provider, function<void(T)> consumer) 
	: WaitQueue<T>{consumer}
{
	this->provider = provider;
	thi = thread(&AsyncQueue::provide, this);
	thi.detach();
}

template <typename T> AsyncQueue<T>::AsyncQueue(AsyncQueue&& r) : WaitQueue<T>{move(r)}
{
	thi = move(r.thi);
	provider = move(r.provider);
}

template <typename T> void AsyncQueue<T>::provide()
{///recv->functor->q->notify to sendf
	while(1) WaitQueue<T>::push_back(provider());
}
