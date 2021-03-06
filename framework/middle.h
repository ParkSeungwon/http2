#pragma once
#include<map>
#include<chrono>
#include<mutex>
#include"asyncqueue.h"
#include"server.h"

struct Packet
{
	int fd, id;//client_fd, cookie id
	std::string content;
};

class Channel : public WaitQueue<Packet>, public Client, 
				public std::chrono::system_clock::time_point
{
public:
	Channel(int port, WaitQueue<Packet>& out);

private:
	WaitQueue<Packet>& out_;
	void consumer(Packet p);
};


class Middle : public Server
{//middle server that will connect to html server, provide state to html server
public:
	Middle(int outport = 3000, int inport = 2001);
	void start();
	virtual ~Middle();

protected:
	AsyncQueue<Packet> influx_;
	WaitQueue<Packet> outflux_;
	std::map<int, Channel*> idNchannel_;

private:
	Packet recv();
	void send(Packet p), sow(Packet p);
	void garbage_collection();
	void free(int k);
	const int inport_;
	int id_ = 0, time_out_ = 1500;
	bool debug = false;
	std::thread th_;
};
