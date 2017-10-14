#pragma once
#include<map>
#include"asyncqueue.h"
#include"server.h"

struct Packet
{
	int fd, id;//client_fd, cookie id
	std::string content;
};

class Middle : public Server
{
public:
	Middle(int outport = 3000, int inport = 2001);
	virtual ~Middle();

protected:
	AsyncQueue<Packet> influx_;
	WaitQueue<Packet> outflux_;
	std::map<int, Client*> idNconn_;

private:
	Packet recv();
	void send(Packet p), sow(Packet p);
	const int inport_;
	int id_ = 0;
};
