#include<cstring>
#include<iostream>
#include<unistd.h>
#include<cassert>
#include<thread>
#include"https.h"
#include"tls.h"
#include"crypt.h"
using namespace std;

HTTPS::HTTPS(int outport, int inport) : Server{outport}, inport_{inport}
{ //hI = this; 
} 
	
HTTPS::~HTTPS() {}

bool HTTPS::find_id(array<uint8_t, 32> id)
{
	return idNchannel_.find(id) != idNchannel_.end();
}

HTTPS::Channel::Channel(int port) : Client{"localhost", port} {}
	
array<unsigned char, 32> HTTPS::new_id()
{
	array<unsigned char, 32> r;
	do {
		auto k = random_prime(32);
		mpz2bnd(k, r.begin(), r.end());
	} while(find_id(r));
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
			v.push_back(thread(&HTTPS::connected, this, client_fd));
			v.back().detach();
		}
	}
}

void HTTPS::connected(int client_fd)
{//multi thread function
	const int sz = 4096000;
	unsigned char buffer[sz];
	TLS t{buffer};//handshake
	read(client_fd, buffer, sz); auto id = t.client_hello();
	if(id == array<unsigned char, 32>{} || !find_id(id)) id = new_id();
	write(client_fd, buffer, t.server_hello(id));
	write(client_fd, buffer, t.server_certificate());
	write(client_fd, buffer, t.server_key_exchange());
	write(client_fd, buffer, t.server_hello_done());
	read(client_fd, buffer, sz); t.client_key_exchange();
	read(client_fd, buffer, sz); t.client_finished();
	write(client_fd, buffer, t.server_hello_done());

	while(1) {//data communication
		read(client_fd, buffer, sz);
		idNchannel_[id]->send(t.decode());
		write(client_fd, buffer, t.encode(idNchannel_[id]->recv()));
	}
	close(client_fd);
}

