#include<cstring>
#include<iostream>
#include<unistd.h>
#include<cassert>
#include"tls.h"
using namespace std;

void TLS::client_hello()
{
	record_ = reinterpret_cast<TLSRecord*>(buffer);
	assert(record_->content_type == 0x16);//handshake
	assert(record_->encrypted_data[0] == 1);//client hello
	memcpy(random_, record_->encrypted_data + 6, 32);//unix time + 28 random
	if(id_length_ = record_->encrypted_data[38])
		memcpy(session_id_, record_->encrypted_data + 38, id_length_);
	server_hello();
}

void TLS::server_hello()
{
	record_->content_type = 0x16;
	record_->version = 0x0303;
	record_->length;
	record_->encrypted_data[0] = 2;
	server_hello_done();
}

void TLS::server_hello_done()
{
	record_->content_type = 0x16;
	record_->version = 0x0303;
	record_->length;
	record_->encrypted_data[0] = 14;
}


bool TLS::Less::operator()(const unsigned char* a, const unsigned char* b) const 
{
	return memcmp(a, b, 32) < 0;
}


void TLS::start()
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
