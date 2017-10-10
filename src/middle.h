#pragma once
#include<map>
#include<memory>
#include"asyncqueue.h"
#include"server.h"

class MiddleConn : public Client, public AsyncQueue<std::string>
{
public:
	MiddleConn(std::string& s, int port = 2001, std::string ip = "127.0.0.1");
	std::condition_variable cv_;
	std::mutex mtx_;

protected:
	std::unique_lock<std::mutex> lck_;
	std::string& s_;

private:
	void set_result(std::string s);
};
	
class Middle 
{
public:
	Middle(int port = 2001);
	virtual ~Middle();
	std::string operator()(std::string s);

protected:
	static std::map<int, MiddleConn*> idNconn_;

private:
	int id_ = 0;
	const int port_;
};
