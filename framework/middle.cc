#include<iostream>
#include<cassert>
#include<regex>
#include<unistd.h>//write
#include"middle.h"
using namespace std;
using namespace std::chrono;

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
	if(debug) cout << "receiving " << s << endl;
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
	this->time_point::operator=(system_clock::now());
	send(p.content);
	p.content = recv();
	if(p.id < 0) p.content.replace(16, 1, //16 : first new line position in header
			"\nSet-Cookie: middleID=" + to_string(p.id = -p.id) + "\r\n");
	out_.push_back(p);
}

void Middle::send(Packet p)
{//recv -> sow -> send
	write(p.fd, p.content.data(), p.content.size());//erased +1
	close(p.fd);
	if(debug) cout << "sending " << p.content << endl;
}

void Middle::sow(Packet p)
{//rafting, same connection use same furrow(middle <-> htmlserver)new conn -> -
	if(!p.id || !idNchannel_[p.id] ||//new connection or reconnect after disconnect
			//time check 1400 - 1500, no need to use mutex, sequence of || important
			*idNchannel_[p.id] < system_clock::now() - seconds(time_out_) + 100s) {
		cout << "new channel : " << ++id_ << endl;
		idNchannel_[-(p.id = -id_)] = new Channel{inport_, outflux_};//mark p.id -
	}
	idNchannel_[abs(p.id)]->push_back(p);//sow to server
}

void Middle::garbage_collection()
{
	while(1) {
		int k = 0;
		for(auto& a : idNchannel_) {
			if(*a.second < system_clock::now() - seconds(time_out_)) {
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
	cout << "starting middle server, enter 'end' to end the server." << endl;
	while(cin >> s) {
		if(s == "end") break;
		else if(s == "time") for(auto& a : idNchannel_) 
			cout << a.first << " : " << (system_clock::now() - *a.second).count()
					/ 1'000'000'000 << " seconds since last communication" << endl;
		else if(s == "conn") cout << idNchannel_.size() << endl;
		else if(s == "debug") debug = !debug;
		else if(s == "help") cout << "time, conn, debug, end, timeout [sec]" << endl;
		else if(s == "timeout") {
			cin >> time_out_;
			cout << "time out set " << time_out_ << endl;
		}
	}
}
