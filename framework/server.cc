#include<utility>
#include<iostream>
#include<thread>
#include<chrono>
#include<unistd.h>
#include<netdb.h>//gethostbyname
#include<regex>
#include<sys/wait.h>
#include"server.h"
#include"asyncqueue.h"
using namespace std;

Vrecv::Vrecv(int port) : Tcpip{port}
{ }

string Vrecv::recv()
{
	string s = Tcpip::recv();
	s = trailing_string_ + s;
	trailing_string_ = "";
	int len = get_full_length(s);
	if(len < s.size()) {//two packet once
		trailing_string_ = s.substr(len + 1);
		s = s.substr(0, len);
	} else if(len > s.size()) {//more to come
		for(int n; s.size() < len; s += string(buffer, n))
			n = read(client_fd, buffer, min(BUF_SIZE, (int)(len - s.size())));
	}
	return s;
}

Http::Http(int port) : Vrecv{port}
{ }

int Http::get_full_length(const string &s)
{//get full length of one request. assume that s is a first received string
	smatch m;
	if(regex_search(s, m, regex{R"(Content-Length:\s*(\d+))"})) 
		return stoi(m[1].str()) + s.find("\r\n\r\n") + 4;
	else return s.size();
}

Client::Client(string ip, int port) : Http(port)
{
	server_addr.sin_addr.s_addr = inet_addr(get_addr(ip).c_str());
	if(-1 == connect(client_fd, (sockaddr*)&server_addr, sizeof(server_addr)))
		cout << "connect() error" << endl;
	else cout << "connecting to " << ip << ':' << port  <<endl;
}

string Client::get_addr(string host)
{///get ip from dns
	auto* a = gethostbyname(host.data());
	return inet_ntoa(*(struct in_addr*)a->h_addr);
}

Server::Server(int port, unsigned int t, int queue, string e) : Http(port) 
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
	while(1) {
		client_fd = accept(server_fd, (sockaddr*)&client_addr, (socklen_t*)&cl_size);
		if(client_fd == -1) cout << "accept() error" << endl;
		else if(!fork()) {
			for(string s; (s = recv()) != end_string; send(f(s)));
			break;//forked process ends here
		}
	}
}

void Server::nokeep_start(function<string(string)> f)
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

