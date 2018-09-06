#include<cstring>
#include<iostream>
#include<unistd.h>
#include<cassert>
#include<thread>
#include"https.h"
#include"crypt.h"
using namespace std;

HTTPS::HTTPS(int outport, int inport, int t, int queue, string end)
	: Server{outport, t, queue, end}, inport_{inport}
{//hI = this; 
	cout << "opening inner port " << inport << endl;
} 
	
int HTTPS::get_full_length(const string &s) 
{
	return static_cast<unsigned char>(s[3]) * 0x100 + static_cast<unsigned char>(s[4]) + 5;
}
	
bool HTTPS::find_id(array<uint8_t, 32> id)
{
	return idNchannel_.find(id) != idNchannel_.end();
}

HTTPS::Channel::Channel(int port) : Client{"localhost", port}
{ }
	
array<unsigned char, 32> HTTPS::new_id()
{
	array<unsigned char, 32> r;
	do mpz2bnd(random_prime(32), r.begin(), r.end());
	while(find_id(r));//check if new
	idNchannel_[r] = new HTTPS::Channel{inport_};
	return r;
}

void HTTPS::start()
{
	int cl_size = sizeof(client_addr);
	vector<thread> v;
	while(1) {
		client_fd = accept(server_fd, (sockaddr*)&client_addr, (socklen_t*)&cl_size);
		if(client_fd == -1) cout << "accept() error" << endl;
		else {
			v.emplace_back(thread{&HTTPS::connected, this, client_fd});
			v.back().detach();
		}
	}
}

void HTTPS::connected(int client_fd)
{//will be used in parallel
	TLS t;//TLS is decoupled from file descriptor
	array<unsigned char, 32> id; int i=0;
	for(unsigned char c : t.client_hello(recv())) id[i++] = c;
	if(id == array<unsigned char, 32>{} || !find_id(id)) {//new connection handshake
		try {
			t.session_id(id = new_id());
			send(t.server_hello() + t.server_certificate());
			cout << "server hello, server certificate " << endl;
			if(t.support_dhe())
				send(t.server_key_exchange()), cout << "server key exchange" << endl;
			send(t.server_hello_done()); cout << "server hello done" << endl;
			i = 0;
			for(unsigned char c : t.client_key_exchange(recv())) 
				idNchannel_[id]->keys[i++] = c; 
			cout << "client key exchange" << endl;
			t.change_cipher_spec(recv()); cout << "change cipher spec" << endl;
			t.finished(recv()); cout << "client finished" << endl;
			send(t.change_cipher_spec()); cout << "change cipher spec" << endl;
			send(t.finished()); cout << "server finished" << endl;
		} catch(const char* e) {
			cerr << e << endl; 
		} catch(const exception& e) {
			cerr << e.what() << endl;
		} catch(...) {
			cerr << "error found" << endl;
		}
	} else {//resume connection
		t.session_id(id);
		t.use_key(idNchannel_[id]->keys);
		send(t.server_hello() + t.finished());
		t.finished(recv());
	}

	using clock = std::chrono::system_clock;
	while(idNchannel_.find(id) != idNchannel_.end())
	{//data communication until garbage collection 
		idNchannel_[id]->send(t.decode(recv()));
		send(t.encode(idNchannel_[id]->recv()));
		idNchannel_[id]->clock::time_point::operator=(clock::now());
	}
	close(client_fd);
}

