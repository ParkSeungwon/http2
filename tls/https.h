#pragma once
#include<map>
#include<chrono>
#include"server.h"

class HTTPS : public Server
{//use thread for multiple connection
public:
	HTTPS(int outport = 4000, int inport = 2001);
	virtual ~HTTPS();
	void start();

protected:
	struct Channel : public Client, std::chrono::system_clock::time_point {
		Channel(int port);
		std::array<unsigned char, 64> keys;
	};
	std::map<std::array<unsigned char, 32>, HTTPS::Channel*> idNchannel_;
	int inport_;

private:
	void connected(int client_fd);
	bool find_id(std::array<unsigned char, 32> id);
	std::array<unsigned char, 32> new_id();
};

