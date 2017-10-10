#include<iostream>
#include<regex>
#include"middle.h"
using namespace std;

map<int, MiddleConn*> Middle::idNconn_;
Middle::Middle(int port) : port_{port} {}

MiddleConn::MiddleConn(string& s, int port, string ip)
	: s_{s}, Client{ip, port}, lck_{mtx_, defer_lock}, 
	  AsyncQueue{bind(&Tcpip::recv, this), 
			     bind(&MiddleConn::set_result, this, placeholders::_1)} 
{ }

void MiddleConn::set_result(string s)
{
	lck_.lock();
	s_ = s;
	lck_.unlock();
	cv_.notify_all();
}


string Middle::operator()(string s)
{
	regex e{R"(Cookie:.*middleID=(\d+))"};
	smatch m;
	if(regex_search(s, m, e)) {//if already connected
		int id = stoi(m[1].str());
		idNconn_[id]->send(s);
		return idNconn_[id]->recv();
	} else {//first connected
		string r;
		idNconn_[++id_] = new MiddleConn{r, port_, "128.0.0.1"};
		idNconn_[id_]->send(s);
		unique_lock<mutex> lck{idNconn_[id_]->mtx_};
		while(r == "") idNconn_[id_]->cv_.wait(lck);
		cout << "sending" << endl << s << endl << "receiving" << endl << r;
//		r.replace(16, 1, "\nSet-Cookie: middleID=" + to_string(id_) + "\r\n");
		return r;
	}
}

Middle::~Middle()
{
	for(auto& a : idNconn_) delete a.second;
}
