#pragma once
#include<map>
#include<chrono>
#include"framework/server.h"
#include"tls.h"

class HTTPS : public Server
{//use thread for multiple connection, should overload read func-> return exact one req
public:
	HTTPS(int outport = 4433, int inport = 2001, int time_out = 1800, int queue_limit = 10, std::string end_string = "end");
	void start();

protected:
	int inport_;
	bool debug_ = false;

private:
	void connected(int client_fd), conn();
	std::array<unsigned char, 32> new_id();
	int get_full_length(const std::string &s);
};


