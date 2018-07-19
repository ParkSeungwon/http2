//tcpip.h class definition
#pragma once
#include <string>
#include <arpa/inet.h>

class Tcpip 
{//c library wrapper 
public:
	Tcpip(int port = 2001);
	virtual ~Tcpip();
	void send(const std::string& s);
//	void send(int n);
	std::string recv();

protected:
	int server_fd;///<server_fd입니다.
	int client_fd;
	struct sockaddr_in server_addr, client_addr;
	char buffer[4096];

private:
};

