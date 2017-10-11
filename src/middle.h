#pragma once
#include<map>
#include"asyncqueue.h"
#include"server.h"

struct Packet
{
	int fd, id;
	std::string content;
};

class Middle : public Server
{
public:
	Middle(int outport = 3000, int inport = 2001);
	virtual ~Middle();
	Packet loop();

protected:
	AsyncQueue<Packet> influx_, outflux_;
	std::map<int, Client*> idNconn_;

private:
	Packet recv();
	void send(Packet p), sow(Packet p);
	std::deque<Packet> q_;
	const int inport_, outport_;
	int id_ = 0;
};
