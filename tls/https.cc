#include<iostream>
#include<unistd.h>
#include<cassert>
#include<thread>
#include"https.h"
#include"crypt.h"
#include"options/log.h"
using namespace std;

HTTPS::HTTPS(int outport, int inport, int t, int queue, string end)
	: Server{outport, t, queue, end}, inport_{inport}
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
		else if(s == "help" || s == "?") {
			cout << "end, timeout [sec]" << endl
				<< "current timeout " << time_out << endl;
		} else if(s == "timeout") {
			cin >> time_out;
			cout << "time out set " << time_out << endl;
		}
	}
}

void HTTPS::connected(int client_fd)
{//will be used in parallel
	string s; TLS t;//TLS is decoupled from file descriptor
	switch(CLIENT_HELLO) {
	case CLIENT_HELLO:
		if(s = t.client_hello(recv(client_fd)); s != "") {//error -> alert return
			send(move(s));					LOGE << "handshake failed" << endl;
			break;
		} else 								LOGI << "client hello" << endl;
	case SERVER_HELLO:
		s = t.server_hello(); 				LOGI << "server hello" << endl;
		s += t.server_certificate(); 		LOGI << "server certificate" << endl;
		if(t.support_dhe())
			s += t.server_key_exchange(), 	LOGI << "server key exchange" << endl;
		s += t.server_hello_done(); 		LOGI << "server hello done" << endl;
		send(move(s), client_fd);
	case CLIENT_KEY_EXCHANGE:
		if(s = t.client_key_exchange(recv(client_fd)); s != "") {
			send(move(s)); 					LOGE<<"client key exchange failed"<<endl;
			break;
		} else 								LOGI << "client key exchange" << endl;
		t.change_cipher_spec(recv(client_fd)); 	LOGI << "change cipher spec" << endl;
		if(s = t.finished(recv(client_fd)); s != "") {
			send(move(s)); 					LOGE << "decrypt error" << endl;
			break;
		} else 								LOGI << "client finished" << endl;
	case CHANGE_CIPHER_SPEC:
		s = t.change_cipher_spec(); 		LOGI << "change cipher spec" << endl;
		s += t.finished(); 					LOGI << "server finished" << endl;
		send(move(s), client_fd);
	case APPLICATION_DATA:
		chrono::system_clock::time_point last_transmission =chrono::system_clock::now();
		thread th{[&]() {
			Client cl{"localhost", inport_};
			while(1) {
				string s = recv(client_fd);
				t.set_buf(s.data());
				if(t.get_content_type().first == ALERT) {
					t.alert();
					send(t.encode(t.alert(1, 0).substr(5), ALERT), client_fd);
					break;
				} else cl.send(t.decode());
				send(t.encode(cl.recv()), client_fd);
				last_transmission = chrono::system_clock::now();
			}
		}};
		th.detach();
		LOGI << "timeout " << time_out << 's' << endl;
		while(last_transmission > chrono::system_clock::now() - time_out * 1s + 45s)
			this_thread::sleep_for(30s);//data communication until garbage collection 
	}
	close(client_fd); 		LOGI << "closing connection " << client_fd << endl;
}

