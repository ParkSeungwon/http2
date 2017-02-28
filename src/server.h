#pragma once
#include<iostream>
#include<functional>
#include<unistd.h>
#include"tcpip.h"
#include"asyncqueue.h"

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
	template <typename T> void start(T& f) {
		int cl_size = sizeof(client_addr);
		while(true) {
			client_fd = accept(server_fd, (sockaddr*)&client_addr, (socklen_t*)&cl_size);
			if(client_fd == -1) std::cout << "accept() error" << std::endl;
			else {//connection established
				std::cout << "accepting" << std::endl;
				if(!fork()) {//child process begin here, current fd & addr is copied
					int time_left;
					auto ff = [&](std::string s) {//add timer to server function
						time_left = time_out;
						return f(s);
					};
					AsyncQueue<std::string> aq{bind(&Tcpip::recv, this), //multi thread
						bind(&Tcpip::send, this, bind(ff, std::placeholders::_1))};
					//timer. aq will destroy its thread automatically when out of range
					while(time_left--) std::this_thread::sleep_for(std::chrono::seconds(1));
				}
			}
		}
	}


protected:
	std::string end_string;
	int time_out;
};
