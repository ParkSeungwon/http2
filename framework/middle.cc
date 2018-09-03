#include<iostream>
#include<cassert>
#include<regex>
#include<iomanip>
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
	string s = Http::recv();
	if(debug) {
		cout << "receiving " << s << endl;
		for(int i=0; i<s.size(); i++) cout << hex << setw(2) << setfill('0') << +static_cast<unsigned char>(s[i]) << (i%16 == 15 ? '\n' : ' ');
	}
	int id = 0;
	if(smatch m; regex_search(s, m, regex{R"(Cookie:.*middleID=(\d+))"}))
		id = stoi(m[1].str());//if already connected
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
	if(!p.id || idNchannel_.find(p.id) == idNchannel_.end() ||
			//new connection or reconnect after disconnect
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
		for(auto& a : idNchannel_) 
			if(*a.second < system_clock::now() - seconds(time_out_))
				free(a.first), k++;
		if(k) cout << "colleced " << k << " garbages" << endl;
		this_thread::sleep_for(60s);
	}
}

void Middle::free(int k)
{//free id k connection
	idNchannel_[k]->send("end");//end http server
	delete idNchannel_[k];//end client
	idNchannel_.erase(k);//delete map
}

Middle::~Middle()
{
	for(auto& a : idNchannel_) free(a.first);
}

void Middle::start()
{//middle server can be managed here
	string s;
	cout << "starting middle server, enter '?' to see commands." << endl;
	while(cin >> s) {
		if(s == "end") break;
		else if(s == "time") for(auto& a : idNchannel_) 
			cout << a.first << " : " << (system_clock::now() - *a.second).count()
				/ 1'000'000'000 << " seconds passed since last communication" << endl;
		else if(s == "conn") cout << idNchannel_.size() << endl;
		else if(s == "debug") debug = !debug;
		else if(s == "help" || s == "?") 
			cout << "time, conn, debug, end, timeout [sec], kill [id]" << endl;
		else if(s == "timeout") {
			cin >> time_out_;
			cout << "time out set " << time_out_ << endl;
		} else if(s == "kill") {//can cause hang if not careful
			int k; cin >> k;
			free(k);
			cout << "id " << k << " killed." << endl;
		}
	}
}
