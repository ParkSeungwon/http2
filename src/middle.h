#pragma once
#include<map>
#include"server.h"

class Middle 
{
public:
	Middle(int port = 2001);
	std::string operator()(std::string s);

protected:
	static std::map<int, Client> idNconn_;

private:
	int id_ = 0;
	const int port_;
};
