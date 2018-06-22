//tcpip.cc class 구현부
#include<sys/socket.h>
#include<sys/types.h>
#include<unistd.h>//close
#include<cstring>//memset
#include<iostream>
#include"tcpip.h"
using namespace std;

Tcpip::Tcpip(int port)
{
	memset(&server_addr, 0, sizeof(server_addr));//fill 0 into memset
	memset(&client_addr, 0, sizeof(client_addr));
	server_addr.sin_family = AF_INET;
	server_addr.sin_port = htons(port);
	server_fd = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);//get file descriptor
	client_fd = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
}

Tcpip::~Tcpip()
{
	close(client_fd);
	close(server_fd);
	cout << "destroying Tcpip" << endl;
}
void Tcpip::send(const string& s) 
{
	write(client_fd, s.data(), s.size());
}

void Tcpip::send(int n)
{
	write(client_fd, buffer, n);
}

string Tcpip::recv()
{
	int i = read(client_fd, buffer, 4095999);//error
//	buffer[i] = '\0';
	return string(buffer, i);
}

