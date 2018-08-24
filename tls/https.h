#pragma once
#include<map>
#include<chrono>
#include"framework/server.h"

class HTTPS : public TlsLayer
{//use thread for multiple connection, should overload read func-> return exact one req
public:
	HTTPS(int outport = 4430, int inport = 2001, int time_out = 1800, int queue_limit = 10, std::string end_string = "end");
	virtual ~HTTPS();
	void start();

protected:
	struct Channel : public Client, std::chrono::system_clock::time_point {
		Channel(int port);
		std::array<unsigned char, 32 * 4> keys;
	};
	std::map<std::array<unsigned char, 32>, HTTPS::Channel*> idNchannel_;
	int inport_, time_out;
	std::string end_string;

private:
	void connected(int client_fd);
	bool find_id(std::array<unsigned char, 32> id);
	std::array<unsigned char, 32> new_id();
};


