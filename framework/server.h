#pragma once
#include<functional>
#include"tcpip.h"

class Vrecv : public Tcpip
{//virtual class that provide interface to get recv that works just as expected
public:
	Vrecv(int port);
	std::string recv();//check content length header and get one full request
protected:
	std::string trailing_string_;
	virtual int get_full_length(const std::string& s);
};

class Http : public Vrecv
{
public:
	Http(int port);

protected:
	int get_full_length(const std::string& s);
};

class TlsLayer : public Vrecv
{
public:
	TlsLayer(int port);

protected:
	int get_full_length(const std::string& s);
};

template<class T> class Client : public T
{
public:
	Client(std::string ip = "127.0.0.1", int port = 2001) {
		T::server_addr.sin_addr.s_addr = inet_addr(get_addr(ip).c_str());
		if(-1 == T::connect(T::client_fd, (sockaddr*)&T::server_addr, sizeof(T::server_addr)))
			std::cout << "connect() error" << std::endl;
		else std::cout << "connecting to " << ip << ':' << port  <<std::endl;
	}
private:
	std::string get_addr(std::string host) {///get ip from dns
		auto* a = gethostbyname(host.data());
		return inet_ntoa(*(struct in_addr*)a->h_addr);
	}
};

template<class T> class Server : public T
{
public:
	Server(int port = 2001, unsigned int time_out = 600, int queue_limit = 10,
			std::string end_string = "end") : Http(port) {
		this->end_string = end_string;
		this->time_out = time_out;
		T::server_addr.sin_addr.s_addr = htonl(INADDR_ANY);
		if(bind(T::server_fd, (sockaddr*)&T::server_addr, sizeof(T::server_addr)) == -1)
			std::cout << "bind() error" << std::endl;
		else std::cout << "binding" << std::endl;
		if(listen(server_fd, queue) == -1) std::cout << "listen() error" << std::endl;
		else std::cout << "listening" << std::endl;
	}
	void start(std::function<std::string(std::string)> f) {
		int cl_size = sizeof(client_addr);
		while(1) {
			client_fd = accept(server_fd, (sockaddr*)&client_addr, (socklen_t*)&cl_size);
			if(client_fd == -1) cout << "accept() error" << endl;
			else if(!fork()) {
				for(string s; (s = recv()) != end_string; send(f(s)));
				break;//forked process ends here
			}
		}
	}
	void nokeep_start(std::function<std::string(std::string)> f)
	{//does not keep connection
		int cl_size = sizeof(client_addr);
		while(true) {
			client_fd = accept(server_fd, (sockaddr*)&client_addr, (socklen_t*)&cl_size);
			if(client_fd == -1) cout << "accept() error" << endl;
			else {//connection established
				cout << "accepting" << endl;
				send(f(recv()));
			}
		}
	}

protected:
	std::string end_string;
	int time_out;
};

