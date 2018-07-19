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

int Vrecv::get_full_length(const string& s) 
{//this should be replaced with inherent class function
	return 0;
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

TlsLayer::TlsLayer(int port) : Vrecv{port}
{ }

int TlsLayer::get_full_length(const string& s)
{
	return s[3] * 0x16 + s[4];
}


