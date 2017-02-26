#pragma once
#include<list>
#include"tcpip.h"
#include"asyncqueue.h"

class Client : public Tcpip
{
public:
	Client(std::string ip = "127.0.0.1", int port = 2001); ///<constructor
	AsyncQueue<std::string> aq;
private:
	void consumer(std::string s);
	
};

class Server : public Tcpip
{
public:
	Server(int port = 2001, unsigned int time_out = 600, int queue_limit = 10, 
			std::string end_string = "end");
	void start();

protected:
	std::string end_string;
	int time_out;
	std::list<AsyncQueue<std::string>> li;
};
