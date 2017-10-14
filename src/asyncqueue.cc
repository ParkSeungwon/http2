#include<iostream>
#include<functional>
#include<chrono>
#include "asyncqueue.h"
#include"middle.h"

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
		for(auto& a : q) consumer(a);
		q.clear();
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

template<typename T> WaitQueue<T>::WaitQueue(std::function<void(T)> f) 
	: AsyncQueue<T>{bind(&WaitQueue<T>::wait, this), f}
{}

template<typename T>  T WaitQueue<T>::wait()
{
	while(!AsyncQueue<T>::finish) this_thread::sleep_for(1s);
}


static void init()
{
	AsyncQueue<Packet> aq{[](){return Packet{0,0,""};}, [](Packet p){}};
	WaitQueue<Packet> wq{[](Packet p){}};
}
