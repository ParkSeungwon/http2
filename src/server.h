#pragma once
#include<functional>
#include"tcpip.h"

class Client : public Tcpip
{
public:
	Client(std::string ip = "127.0.0.1", int port = 2001); ///<constructor
};

class Server : public Tcpip
{
public:
	Server(int port = 2001, unsigned int time_out = 600, int queue_limit = 10,
			std::string end_string = "end");
	void start(std::function<std::string(std::string)> f);

protected:
	std::string end_string;
	int time_out;
};
