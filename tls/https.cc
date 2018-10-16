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
{//this make HTTP recv into TLS recv
	return static_cast<unsigned char>(s[3]) * 0x100 + static_cast<unsigned char>(s[4]) + 5;
}
	
bool HTTPS::find_id(array<uint8_t, 32> id)
{
	return idNchannel_.find(id) != idNchannel_.end();
}

HTTPS::Channel::Channel(int port) : Client{"localhost", port}
{ 
	last_transmission = chrono::system_clock::now();
}

array<unsigned char, 32> HTTPS::new_id()
{
	array<unsigned char, 32> r;
	do mpz2bnd(random_prime(32), r.begin(), r.end());
	while(find_id(r));//check if new
	idNchannel_[r] = new HTTPS::Channel{inport_};
	return r;
}

void HTTPS::garbage_collection()
{//every 60s, check channels unused longer than timeout duration
	while(1) {
		this_thread::sleep_for(60s);
		for(auto [id, ch] : idNchannel_)
			if(ch->last_transmission < chrono::system_clock::now() - time_out * 1s) 
				free(id);
	}
}

void HTTPS::free(array<unsigned char, 32> id) 
{
	idNchannel_[id]->send(end_string);
	delete idNchannel_[id];
	idNchannel_.erase(id);
}
			
void HTTPS::conn()
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

void HTTPS::start()
{//middle server can be managed here
	thread th1{&HTTPS::garbage_collection, this}, th2{&HTTPS::conn, this};
	string s;
	cout << "starting middle server, enter '?' to see commands." << endl;
	while(cin >> s) {
		if(s == "end") break;
		else if(s == "time") for(auto [id, ch] : idNchannel_) {
			cout << "id : 0x";
			for(unsigned char c : id) cout << hex << +c; cout << endl;
			cout << (chrono::system_clock::now() - ch->last_transmission).count()
				/ 1'000'000'000 << " seconds passed since last communication" << endl;
		} else if(s == "help" || s == "?") 
			cout << "time, end, timeout [sec], kill [last 2 hex digit of id]" << endl
				<< "current timeout " << time_out << endl;
		else if(s == "timeout") {
			cin >> time_out;
			cout << "time out set " << time_out << endl;
		} else if(s == "kill") {//can cause hang if not careful
			int k; cin >> hex >> k;
			for(auto [id, ch] : idNchannel_) if(id[31] == k) {
				free(id);
				cout << "id ";
				for(unsigned char c : id) cout << hex << +c;
				cout << " killed." << endl;
			}
		}
	}
}

void HTTPS::connected(int client_fd)
{//will be used in parallel
	TLS t;//TLS is decoupled from file descriptor
	array<unsigned char, 32> id; int i=0; string s;
	for(unsigned char c : t.client_hello(recv())) id[i++] = c;
	if(id == array<unsigned char, 32>{} || !find_id(id)) {//new connection handshake
		t.session_id(id = new_id());
		hexprint("session id", id);
		send((s = t.server_hello(), s + t.server_certificate()));
		cout << "server hello, server certificate " << endl;
		if(t.support_dhe())
			send(t.server_key_exchange()), cout << "server key exchange" << endl;
		send(t.server_hello_done()); cout << "server hello done" << endl;
		for(unsigned char c : t.client_key_exchange(recv())) 
			idNchannel_[id]->keys[i++] = c; 
		cout << "client key exchange" << endl;
		t.change_cipher_spec(recv()); cout << "change cipher spec" << endl;
		t.finished(recv()); cout << "client finished" << endl;
		send((s = t.change_cipher_spec(), s + t.finished()));
		cout << "change cipher spec, server finished" << endl;
	} else {//resume connection
		t.session_id(id);
		t.use_key(idNchannel_[id]->keys);
		send((s = t.server_hello(), s + t.finished()));
		t.finished(recv());
	}

	using clock = std::chrono::system_clock;
	thread th{[&]() {
		while(1) {
			idNchannel_[id]->send(t.decode(recv()));
			send(t.encode(idNchannel_[id]->recv()));
			idNchannel_[id]->last_transmission = clock::now();
		}
	}};
	cout << time_out << 's' << endl;
	while(idNchannel_[id]->last_transmission > clock::now() - time_out * 1s + 45s) {
		cout << "sleeping for 30s" << endl;
		this_thread::sleep_for(30s);//data communication until garbage collection 
	}
	close(client_fd);
}

