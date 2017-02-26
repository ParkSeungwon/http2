#pragma once
#include <thread>
#include <condition_variable>
#include <deque>
#include <mutex>
#include"tcpip.h"

class Connection : public Tcpip
{//for asyncronous connection
public:
	Connection(std::function<std::string(std::string)> f, int port = 2001);
	virtual ~Connection();
	void send(std::string s);
	
protected:
	std::deque<std::string> q;///<queue to send
	std::function<std::string(std::string)> functor;///<auto respond func

private:
	std::thread thi, tho;
	std::mutex mtx;
	std::condition_variable cv;
	bool finish = false;
	void recvf();
	void sendf();
};
