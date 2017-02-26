//tcpip.cc class 구현부
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>//close
#include <cstring>//memset
#include "tcpip.h"
using namespace std;

Tcpip::Tcpip(int port) 
{
	memset(&server_addr, 0, sizeof(server_addr));//fill 0 into memset
	memset(&client_addr, 0, sizeof(client_addr));
	server_addr.sin_family = AF_INET;
	server_addr.sin_port = htons(port);
	this->port = port;
	server_fd = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);//get file descriptor
	client_fd = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
}

Tcpip::~Tcpip()
{
	close(client_fd);
	close(server_fd);
}
void Tcpip::send(string s) 
{
	write(client_fd, s.c_str(), s.size()+1);
}
void Tcpip::sendfd(string s, int client_fd) 
{
	write(client_fd, s.c_str(), s.size()+1);
}

string Tcpip::recv()
{
	int i = read(client_fd, buffer, 1023);//error
	buffer[i] = '\0';
	return string(buffer);
}
string Tcpip::recvfd(int client_fd)
{
	int i = read(client_fd, buffer, 1023);//error
	buffer[i] = '\0';
	return string(buffer);
}

