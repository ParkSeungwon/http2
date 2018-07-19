#pragma once
#include<functional>
#include"tcpip.h"

class Http : public Tcpip
{
public:
	Http(int port);
	std::string recv();

protected:
	std::string trailing_string_;
};

class Client : public Http
{
public:
	Client(std::string ip = "127.0.0.1", int port = 2001); ///<constructor
private:
	std::string get_addr(std::string host);
};

class Server : public Http
{
public:
	Server(int port = 2001, unsigned int time_out = 600, int queue_limit = 10,
			std::string end_string = "end");
	void start(std::function<std::string(std::string)> f);
	void nokeep_start(std::function<std::string(std::string)> f);

protected:
	std::string end_string;
	int time_out;
};

