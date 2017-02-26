//tcpip.h class definition
#pragma once
#include <string>
#include <arpa/inet.h>

class Tcpip 
{//c library wrapper 
public:
	Tcpip(int port);
	virtual ~Tcpip();
	void send(std::string s);
	std::string recv();
	void sendfd(std::string s, int fd);
	std::string recvfd(int fd);

protected:
	int server_fd;///<server_fd입니다.
	int client_fd;
	int port;
	struct sockaddr_in server_addr, client_addr;
	char buffer[1024];

private:
};


