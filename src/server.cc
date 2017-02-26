#include<iostream>
#include"server.h"
using namespace std;

Client::Client(function<string(string)> f, string ip, int port) 
	: Connection(f, port) 
{
	server_addr.sin_addr.s_addr = inet_addr(ip.c_str());
	if(-1 == connect(client_fd, (sockaddr*)&server_addr, sizeof(server_addr)))
		cout << "connect() error" << endl;
	else cout << " connecting"  <<endl;
}

