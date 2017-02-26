#include<iostream>
#include<functional>
#include"server.h"
using namespace std;

Client::Client(string ip, int port) : Tcpip(port), 
	aq{bind(&Tcpip::recv, this), bind(&Client::consumer, this, placeholders::_1)}
{
	server_addr.sin_addr.s_addr = inet_addr(ip.c_str());
	if(-1 == connect(client_fd, (sockaddr*)&server_addr, sizeof(server_addr)))
		cout << "connect() error" << endl;
	else cout << "connecting"  <<endl;
}

void Client::consumer(string s)
{
	static int n = 0;
	cout << ++n << " : " << s << endl;
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

void Server::start()
{
	int cl_size = sizeof(client_addr);
	while(true) {
		client_fd = accept(server_fd, (sockaddr*)&client_addr, (socklen_t*)&cl_size);
		if(client_fd == -1) cout << "accept() error" << endl;
		else {
			cout << "accepting" << endl;
			li.push_back(AsyncQueue<string>{bind(&Tcpip::recvfd, this, client_fd), 
					bind(&Tcpip::sendfd, this, placeholders::_1, client_fd)});
		}
	}
}
