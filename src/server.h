#pragma once
#include"conn.h"

class Client : public Connection
{
public:
	Client(std::function<std::string(std::string)> f, 
			std::string ip = "127.0.0.1", int port = 2001); ///<constructor
};

