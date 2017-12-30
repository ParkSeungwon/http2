#include<cstring>
#include<iostream>
#include<unistd.h>
#include<cassert>
#include"tls.h"
#include"crypt.h"
using namespace std;

TLS::TLS(unsigned char* buffer)
{
	record_ = reinterpret_cast<TLSRecord*>(buffer);
}

int TLS::client_hello()
{
	assert(record_->content_type == 0x16);//handshake
	assert(record_->handshake_type == 1);//client hello
	memcpy(random_.data(), record_->unix_time, 32);//unix time + 28 random
	if(id_length_ = record_->session_id_length)
		memcpy(session_id_.data(), record_->session_id, id_length_);
	return 0;
}

int TLS::server_hello()
{//return data size
	record_->content_type = 0x16;
	record_->version = 0x0303;
	record_->length;
	record_->handshake_type = 2;
	record_->session_id_length = 32;
	if(id_length_ && hI->find_id(session_id_)) 
		memcpy(record_->session_id, session_id_.data(), 32);
	else memcpy(record_->session_id, hI->new_id().data(), 32);
	record_->cipher_suite[1] = 0x35;//0035 DHE RSA SHA1
	return 0;
}

int TLS::server_certificate()
{}

int TLS::server_key_exchange()
{}

int TLS::server_hello_done()
{
	record_->content_type = 0x16;
	record_->version = 0x0303;
	record_->length;
	record_->handshake_type = 14;
}

int TLS::client_key_exchange()//16
{}

HTTPS::HTTPS(int outport, int inport) : Server{outport}, inport_{inport}
{
	hI = this;
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

Interface* Interface::hI = nullptr;

void HTTPS::start()
{
	int cl_size = sizeof(client_addr);
	while(1) {
		cout << "0" << endl;
		client_fd = accept(server_fd, (sockaddr*)&client_addr, (socklen_t*)&cl_size);
		if(client_fd == -1) cout << "accept() error" << endl;
		else if(!fork()) {
//			gnutls_session_t session;
//			gnutls_datum_t session_id;
//			gnutls_init(&session, GNUTLS_SERVER);
//			gnutls_priority_set_direct(session, "NORMAL:+ANON-ECDH:+ANON-DH", NULL);
//			gnutls_credentials_set(session, GNUTLS_CRD_ANON, anoncred);
//			gnutls_session_get_id2(session, &session_id);
//			gnutls_transport_set_int(session, client_fd);
//			int ret;
//			do {
//				ret = gnutls_handshake(session);
//			} while (ret < 0 && gnutls_error_is_fatal(ret) == 0);
//
//			for(int n; (n = gnutls_record_recv(session, buffer, 40960000)) > 0;) {
//				if(idNchannel_.find(session_id.data) == idNchannel_.end()) 
//					idNchannel_[session_id.data] = new Channel(inport_);
//				idNchannel_[session_id.data]->send(string{buffer, n});
//				string s = idNchannel_[session_id.data]->recv();
//				cout << s << endl;
//				gnutls_record_send(session, s.data(), s.size());
//			}
//			gnutls_bye(session, GNUTLS_SHUT_WR);
//			gnutls_deinit(session);
			break;
		}
	}
}
