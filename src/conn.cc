#include "tcpip.h"
using namespace std;

Connection::Connection(function<string(string)> f) : thi(in, f, this)
{
	functor = f;
	thi = thread(&Connection::recvf, this);
	tho = thread(&Connection::sendf, this);
}

Connection::~Connection()
{
	finish = true;
	thi.join();
	tho.join();
}

void Connection::recvf()
{///recv->functor->q->notify to sendf
	unique_lock<mutex> lck{mtx, defer_lock};
	while(!finish) {
		lck.lock();
		q.push_back(functor(recv()));
		lck.unlock();
		cv.notify_all();
	}
}
	
void Connection::sendf()
{
	unique_lock<mutex> lck{mtx, defer_lock};
	while(!finish) {
		lck.lock();
		while(q.empty()) cv.wait(lck);
		send(q.front());
		q.pop_front();
		lck.unlock();
	}
}

void Connection::send(string s)
{///asynchronous send, ->sendf()
	unique_lock<mutex> lck{mtx};
	q.push_back(s);
	lck.unlock();
	cv.notify_all();
}
