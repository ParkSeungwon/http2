#include<cstring>
#include<iostream>
#include<unistd.h>
#include<cassert>
#include<thread>
#include"https.h"
#include"tls.h"
#include"crypt.h"
using namespace std;

HTTPS::HTTPS(int outport, int inport, int t, int queue, string end)
	: TlsLayer{outport}, inport_{inport}
{//hI = this; 
	end_string = end;
	time_out = t;
	server_addr.sin_addr.s_addr = htonl(INADDR_ANY);
	if(bind(server_fd, (sockaddr*)&server_addr, sizeof(server_addr)) == -1)
		cout << "bind() error" << endl;
	else cout << "binding" << endl;
	if(listen(server_fd, queue) == -1) cout << "listen() error" << endl;
	else cout << "listening" << endl;
} 
	
HTTPS::~HTTPS() {}

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
	unsigned char buf[10000];
	TLS t{nullptr, buf};//TLS is decoupled from file descriptor
	string s = recv();
	t.set_buf(s.data());
	auto id = t.client_hello();
	if(id == array<unsigned char, 32>{} || !find_id(id)) {//new connection handshake
		try {
			id = new_id();
			write(client_fd, buffer, t.server_hello(id));
			cout << "server hello done" << endl;
			write(client_fd, buffer, t.server_certificate());
			cout << "server certificate " << endl;
			write(client_fd, buffer, t.server_key_exchange());
			cout << "server key exchange" << endl;
			write(client_fd, buffer, t.server_hello_done());
			cout << "server hello done" << endl;
			s = recv();
			t.set_buf(s.data());
			idNchannel_[id]->keys=t.client_key_exchange();
			cout << "client key exchange" << endl;
			s = recv();
			t.set_buf(s.data());
			t.client_finished();
			cout << "client finished" << endl;
			write(client_fd, buffer, t.server_finished());
			cout << "server finished" << endl;
		} catch(const char* e) {
			cerr << e << endl; 
		} catch(const exception& e) {
			cerr << e.what() << endl;
		} catch(...) {
			cerr << "error found" << endl;
		}
	} else {//resume connection
		t.use_key(idNchannel_[id]->keys);
		write(client_fd, buffer, t.server_hello(id));
		write(client_fd, buffer, t.server_finished());
		s = recv();
		t.set_buf(s.data());
		t.client_finished();
	}

	using clock = std::chrono::system_clock;
	while(idNchannel_.find(id) != idNchannel_.end()) {//data communication
		s = recv();
		t.set_buf(s.data());
		idNchannel_[id]->send(t.decode());
		write(client_fd, buffer, t.encode(idNchannel_[id]->recv()));
		idNchannel_[id]->clock::time_point::operator=(clock::now());
	}
	close(client_fd);
}

