#include<iostream>
#include<regex>
#include"middle.h"
using namespace std;

mutex MiddleConn::mtx_;
condition_variable MiddleConn::cv_;
bool MiddleConn::ok_ = false;
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
	ok_ = true;
	cv_.notify_all();
}


string Middle::operator()(string s)
{
	cout << "receiving " << s << endl;
	regex e{R"(Cookie:.*middleID=(\d+))"};
	smatch m; int id;
	if(regex_search(s, m, e)) id = stoi(m[1].str());//if already connected
	else idNconn_[id = ++id_] = new MiddleConn{result_, port_, "localhost"};
	idNconn_[id]->send(s);//should implement when id is not present
	unique_lock<mutex> lck{idNconn_[id]->mtx_};
	while(!idNconn_[id]->ok_) idNconn_[id]->cv_.wait(lck);
	idNconn_[id]->ok_ = false;
	result_.replace(16, 1, "\nSet-Cookie: middleID=" + to_string(id_) + "\r\n");
	cout << "sending " << result_ << endl;
	return result_;
}

Middle::~Middle()
{
	for(auto& a : idNconn_) delete a.second;
}
