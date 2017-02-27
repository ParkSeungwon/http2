#include<iostream>
#include<unistd.h>
#include"server.h"
#include"asyncqueue.h"
using namespace std;

Client::Client(string ip, int port) : Tcpip(port)
{
	server_addr.sin_addr.s_addr = inet_addr(ip.c_str());
	if(-1 == connect(client_fd, (sockaddr*)&server_addr, sizeof(server_addr)))
		cout << "connect() error" << endl;
	else cout << "connecting"  <<endl;
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

void Server::start(function<string(string)> f)
{
	int cl_size = sizeof(client_addr);
	while(true) {
		client_fd = accept(server_fd, (sockaddr*)&client_addr, (socklen_t*)&cl_size);
		if(client_fd == -1) cout << "accept() error" << endl;
		else {
			cout << "accepting" << endl;
			if(!fork()) {
				AsyncQueue<string> aq{bind(&Tcpip::recv, this), 
					bind(&Tcpip::send, this, bind(f, placeholders::_1))};
				while(1);
			}
		}
	}
}

