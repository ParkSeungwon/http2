#include<iostream>
#include<cassert>
#include<regex>
#include"middle.h"
using namespace std;

Middle::Middle(int outport, int inport)
	: outport_{outport}, inport_{inport}, 
	  influx_{bind(&Middle::recv, this), },
	  outflux_{, bind(&Middle::send, this, placeholders::_1)}
{ }

Packet Middle::recv()
{//no need to lock around client_fd. cause async class provide it
	client_fd = accept(server_fd, (sockaddr*)&client_addr, (socklen_t*)&cl_size);
	assert(client_fd != -1);// cout << "accept() error" << endl;
	string s = Tcpip::recv();
	cout << "receiving " << s << endl;
	regex e{R"(Cookie:.*middleID=(\d+))"};
	int id = 0;
	if(regex_search(s, m, e)) id = stoi(m[1].str());//if already connected
	return {client_fd, id, s};
}

void Middle::send(Packet p)
{
//	if(!p.id) p.content.replace(16, 1, "\nSet-Cookie: middleID=" + to_string(id_) + "\r\n");
	write(p.fd, p.content.data(), p.content.size()+1);
	close(p.fd);
}

void Middle::start()
{
	while(1) this_thread::sleep_for(1s);
}

void Middle::alloc2clients(Packet p)
{
	if(!p.id) idNconn_[p.id = ++id_] = new Client{"localhost", inport_};
	if(idNconn_[p.id]) idNconn_[p.id]->send(p.content);
	string s = idNconn_[p.id]->recv();
}

Packet Middle::gather_from_clients()
{
	
}

string Middle::operator()(string s)
{
	smatch m; int id;
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
