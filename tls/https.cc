#include<iostream>
#include<unistd.h>
#include<cassert>
#include<thread>
#include"https.h"
#include"crypt.h"
#include"options/log.h"
using namespace std;

HTTPS::HTTPS(int outport, int inport, int timeout, int queue, string end)
	: Server{outport, timeout, queue, end}, inport_{inport}
{//hI = this; 
	LOGI << "opening inner port " << inport << endl;
} 
	
int HTTPS::get_full_length(const string &s) 
{//this make HTTP recv into TLS recv
	return static_cast<unsigned char>(s[3]) * 0x100 + static_cast<unsigned char>(s[4]) + 5;
}
	
void HTTPS::conn()
{
	int cl_size = sizeof(client_addr);
	vector<thread> v;
	while(1) {
		client_fd = accept(server_fd, (sockaddr*)&client_addr, (socklen_t*)&cl_size);
		if(client_fd == -1) LOGF << "accept() error" << endl;
		else {
			v.emplace_back(thread{&HTTPS::connected, this, client_fd});
			v.back().detach();
		}
	}
}

void HTTPS::start()
{//middle server can be managed here
	thread th{&HTTPS::conn, this};
	string s;
	cout << "starting middle server, enter '?' to see commands." << endl;
	while(cin >> s) {
		if(s == "end") break;
		else if(s == "help" || s == "?")
			cout << "end, timeout [sec]" << endl << "current timeout " << time_out << endl;
		else if(s == "timeout") {
			cin >> time_out;
			cout << "time out set " << time_out << endl;
		}
	}
}

void HTTPS::connected(int client_fd)
{//will be used in parallel
	TLS t;//TLS is decoupled from file descriptor
	t.handshake(bind(&HTTPS::recv, this, client_fd),
			bind(&HTTPS::send, this, placeholders::_1, client_fd));
	Client cl{"localhost", inport_};
	while(1) {
		string s = recv(client_fd);
		if(s == "error") break;
		if(t.get_content_type(s).first == ALERT) {
			t.alert(move(s));
			send(t.encode(t.alert(1, 0).substr(5), ALERT), client_fd);
			break;
		} else cl.send(t.decode(move(s)));//to inner server
		send(t.encode(cl.recv()), client_fd);//to browser
	}
	close(client_fd); 		LOGI << "closing connection " << client_fd << endl;
}

