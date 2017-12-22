#include<cassert>
#include<cstring>
#include<unistd.h>
#include<iostream>
#include"server.h"
#include"tls.h"
#include<wolfssl/ssl.h>
using namespace std;

TLS::Channel::Channel(int port) : Client{"localhost", port} { }

TLS::TLS(int outport, int inport) : Server{outport}, inport_{inport}
{
	wolfSSL_Init();
	ctx_ = wolfSSL_CTX_new(wolfSSLv23_server_method());
	assert(wolfSSL_CTX_set_cipher_list(ctx_, "TLS_DH_anon_WITH_AES_128_CBC_SHA") == SSL_SUCCESS);
}

TLS::~TLS()
{
	wolfSSL_CTX_free(ctx_);
	wolfSSL_Cleanup();
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
			cout << "0.5" << endl;
			WOLFSSL* ssl = wolfSSL_new(ctx_);
			cout << "0.6" << endl;
			wolfSSL_set_fd(ssl, client_fd);
			cout << "0.7" << endl;
			const unsigned char* id = wolfSSL_get_sessionID(wolfSSL_get_session(ssl));
			cout << "0.8" << endl;
			wolfSSL_set_timeout(ssl, 500);
			cout << "1" << endl;
			for(int n; (n = wolfSSL_read(ssl, buffer, 40960000)) > 0;) {
				if(idNchannel_.find(id) == idNchannel_.end()) 
					idNchannel_[id] = new Channel(inport_);
				idNchannel_[id]->send(string{buffer, n});
				string s = idNchannel_[id]->recv();
				cout << s << endl;
				wolfSSL_write(ssl, s.data(), s.size());
			}
			wolfSSL_free(ssl);
			break;
		}
	}
}
