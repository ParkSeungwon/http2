#include<iostream>
#include<cassert>
#include<regex>
#include<unistd.h>//write
#include"middle.h"
using namespace std;

Middle::Middle(int outport, int inport)
	: Server{outport}, inport_{inport}, 
	  influx_{bind(&Middle::recv, this), bind(&Middle::sow, this, placeholders::_1)},
	  outflux_{bind(&Middle::send, this, placeholders::_1)},
	  th{&Middle::garbage_collection, this}, lck_{mtx_, defer_lock}
{ }

Packet Middle::recv()
{//no need to lock around client_fd. cause async class provide it
	int cl_size = sizeof(client_addr);
	client_fd = accept(server_fd, (sockaddr*)&client_addr, (socklen_t*)&cl_size);
	assert(client_fd != -1);// cout << "accept() error" << endl;
	string s = Tcpip::recv();
//	cout << "receiving " << s << endl;
	regex e{R"(Cookie:.*middleID=(\d+))"};
	int id = 0;
	smatch m;
	if(regex_search(s, m, e)) id = stoi(m[1].str());//if already connected
	return {client_fd, id, s};
}

void Middle::send(Packet p)
{
	write(p.fd, p.content.data(), p.content.size()+1);
	close(p.fd);
}

void Middle::sow(Packet p)
{//recv -> sow -> send
	bool newly_connected = false;
	if(!p.id) {//rafting, same connection use same furrow(middle <-> htmlserver)
		idNconn_[p.id = ++id_] = new Client{"localhost", inport_};
		newly_connected = true;
	}
	if(!idNconn_[p.id]) idNconn_[p.id] = new Client{"localhost", inport_};//reconnect
	lck_.lock();
	idNtime_[p.id] = std::chrono::system_clock::now();//set time for garbage collection
	idNconn_[p.id]->send(p.content);//sow to server
	p.content = idNconn_[p.id]->recv();//reap from html server
	lck_.unlock();
	if(newly_connected)//set id for the browser
		p.content.replace(16, 1, "\nSet-Cookie: middleID=" + to_string(id_) + "\r\n");
//	cout << p.content << endl;
	outflux_.push_back(p);//sell to browser
}

void Middle::garbage_collection()
{
	while(1) {
		int k = 0;
		for(auto& a : idNtime_) if(a.second < chrono::system_clock::now() - 300s) {
			lck_.lock();
			idNconn_[a.first]->send("end");
			this_thread::sleep_for(1s);
			delete idNconn_[a.first];
			idNconn_.erase(a.first);
			idNtime_.erase(a.first);
			k++;
			lck_.unlock();
		}
		if(k) cout << "colleced " << k << " garbages" << endl;
		this_thread::sleep_for(10s);
	}
}

Middle::~Middle()
{
	for(auto& a : idNconn_) if(a.second) delete a.second;
}

void Middle::start()
{
	string s;
	cout << "starting middle server, enter \'end\' to end the server." << endl;
	while(cin >> s) if(s == "end") break;
}
