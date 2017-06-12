#include<iostream>
#include<thread>
#include<chrono>
#include<unistd.h>
#include<netdb.h>//gethostbyname
#include<sys/wait.h>
#include"server.h"
#include"asyncqueue.h"
using namespace std;

Client::Client(string ip, int port) : Tcpip(port)
{
	server_addr.sin_addr.s_addr = inet_addr(get_addr(ip).c_str());
	if(-1 == connect(client_fd, (sockaddr*)&server_addr, sizeof(server_addr)))
		cout << "connect() error" << endl;
	else cout << "connecting"  <<endl;
}

string Client::get_addr(string host)
{///get ip from dns
	auto* a = gethostbyname(host.data());
	return inet_ntoa(*(struct in_addr*)a->h_addr);
}

Server::Server(int port, unsigned int t, int queue, string e) : Tcpip(port) 
{
	end_string = e;
	time_out = t;
	server_addr.sin_addr.s_addr = htonl(INADDR_ANY);
	if(bind(server_fd, (sockaddr*)&server_addr, sizeof(server_addr)) == -1)
		cout << "bind() error" << endl;
	else cout << "binding" << endl;
	if(listen(server_fd, queue) == -1) cout << "listen() error" << endl;
	else cout << "listening" << endl;
}

template<typename T> void Server::start(T& f)
{//changed from functional to template to enable inner state of server
	int cl_size = sizeof(client_addr);
	while(true) {
		client_fd = accept(server_fd, (sockaddr*)&client_addr, (socklen_t*)&cl_size);
		if(client_fd == -1) cout << "accept() error" << endl;
		else {//connection established
			cout << "accepting" << endl;
			if(!fork()) {//child process begin here, current fd & addr is copied
				int time_left;
				auto ff = [&](string s) {//add timer to server function
					time_left = time_out;
					return f(s);
				};
				AsyncQueue<string> aq{bind(&Tcpip::recv, this), //multi thread
					bind(&Tcpip::send, this, bind(ff, placeholders::_1))};
				//timer. aq will destroy its thread automatically when out of range
				while(time_left--) this_thread::sleep_for(chrono::seconds(1));
			}
		}
	}
}

void Server::init_template()
{
	Functor f;
	start(f);
}
