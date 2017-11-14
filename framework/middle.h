#pragma once
#include<map>
#include<chrono>
#include<mutex>
#include<shared_mutex>
#include"asyncqueue.h"
#include"server.h"

struct Packet
{
	int fd, id;//client_fd, cookie id
	std::string content;
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
	std::map<int, Client*> idNconn_;
	std::map<int, std::chrono::system_clock::time_point> idNtime_;
	std::vector<std::thread> ths_;

private:
	Packet recv();
	void send(Packet p), sow(Packet p);
	void garbage_collection();
	const int inport_;
	int id_ = 0;
	std::thread th_;
	std::shared_mutex mtx_;
	std::unique_lock<std::mutex> lck_;
};
