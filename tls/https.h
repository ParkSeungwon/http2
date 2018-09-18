#pragma once
#include<map>
#include<chrono>
#include"framework/server.h"
#include"tls.h"

class HTTPS : public Server
{//use thread for multiple connection, should overload read func-> return exact one req
public:
	HTTPS(int outport = 4430, int inport = 2001, int time_out = 1800, int queue_limit = 10, std::string end_string = "end");
	void start();

protected:
	struct Channel : public Client {
		Channel(int port);
		std::array<unsigned char, KEY_SZ> keys;
		std::chrono::system_clock::time_point last_transmission;
	};
	std::map<std::array<unsigned char, 32>, HTTPS::Channel*> idNchannel_;
	int inport_;
	bool debug_ = false;

private:
	void connected(int client_fd), garbage_collection(), conn(), free(std::array<unsigned char, 32> id);
	bool find_id(std::array<unsigned char, 32> id);
	std::array<unsigned char, 32> new_id();
	int get_full_length(const std::string &s);
};


