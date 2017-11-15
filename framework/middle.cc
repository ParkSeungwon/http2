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
	  th_{&Middle::garbage_collection, this}
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

Channel::Channel(int port, WaitQueue<Packet>& out)
	: WaitQueue<Packet>{bind(&Channel::consumer, this, placeholders::_1)},
	  Client{"localhost", port}, out_{out}
{ }

void Channel::consumer(Packet p)
{
	time_stamp_ = chrono::system_clock::now();
	send(p.content);
	p.content = recv();
	if(p.id < 0) p.content.replace(16, 1, 
			"\nSet-Cookie: middleID=" + to_string(p.id = -p.id) + "\r\n");
	out_.push_back(p);
}

void Middle::send(Packet p)
{
	write(p.fd, p.content.data(), p.content.size()+1);
	close(p.fd);
}

void Middle::sow(Packet p)
{//recv -> sow -> send
	//rafting, same connection use same furrow(middle <-> htmlserver)new conn -> -
	//time check 500 - 600, no need to use mutex
	if(!p.id || idNchannel_[p.id]->time_stamp_ < chrono::system_clock::now() - 500s) {
		idNchannel_[++id_] = new Channel{inport_, outflux_};
		p.id = -id_;
	} else if(!idNchannel_[p.id])//reconnect
		idNchannel_[p.id] = new Channel{inport_, outflux_};
	idNchannel_[abs(p.id)]->push_back(p);//sow to server
}

void Middle::garbage_collection()
{
	while(1) {
		int k = 0;
		for(auto& a : idNchannel_) {
			if(a.second->time_stamp_ < chrono::system_clock::now() - 600s) {
				a.second->send("end");
				delete a.second;
				idNchannel_.erase(a.first);
				k++;
			}
		}
		if(k) cout << "colleced " << k << " garbages" << endl;
		this_thread::sleep_for(60s);
	}
}

Middle::~Middle()
{
	for(auto& a : idNchannel_) if(a.second) delete a.second;
}

void Middle::start()
{
	string s;
	cout << "starting middle server, enter \'end\' to end the server." << endl;
	while(cin >> s) if(s == "end") break;
}
