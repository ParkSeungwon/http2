#include"tls.h"
using namespace std;

TLS::TLS()
{
	wolfSSL_Init();
	ctx_ = wolfSSL_CTX_new(wolfTLSv1_2_server_method());
}

TLS::~TLS()
{
	wolfSSL_CTX_free(ctx_);
	wolfSSL_Cleanup();
}


void TLS::start()
{
	int cl_size = sizeof(client_addr);
	while(1) {
		client_fd = accept(server_fd, (sockaddr*)&client_addr, (socklen_t*)&cl_size);
		if(client_fd == -1) cout << "accept() error" << endl;
		else if(!fork()) {
			WOLFSSL* ssl = wolfSSL_new(ctx_);
			wolfSSL_set_fd(ssl, client_fd);
			unsigned char buf[40960000];
			unsigned char id[32];
			strncpy(id, wolfSSL_get_sessionID(ssl), 32);
			for(int n; (n = wolfSSL_read(ssl, buf, 40960000)) > 0;) {
				idNchannel_[id]->send(string{buf, n});
				auto s = idNchannel_[id]->recv();
				wolfSSL_write(ssl, s.data(), s.size());
			}
			break;
		}
	}
}
