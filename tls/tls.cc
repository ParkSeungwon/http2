#include<cassert>
#include<cstring>
#include<unistd.h>
#include<iostream>
#include"server.h"
#include"tls.h"
using namespace std;

TLS::Channel::Channel(int port) : Client{"localhost", port} { }

TLS::TLS(int outport, int inport) : Server{outport}, inport_{inport}
{
	gnutls_global_init();
	gnutls_anon_allocate_server_credentials(&anoncred);
	gnutls_anon_set_server_dh_params(anoncred, GNUTLS_DH_PARAMS);
}

TLS::~TLS()
{
	gnutls_anon_free_server_credentials(anoncred);
	gnutls_global_deinit();
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
			gnutls_session_t session;
			gnutls_datum_t session_id;
			gnutls_init(&session, GNUTLS_SERVER);
			gnutls_priority_set_direct(session, "NORMAL:+ANON-ECDH:+ANON-DH", NULL);
			gnutls_credentials_set(session, GNUTLS_CRD_ANON, anoncred);
			gnutls_session_get_id2(session, &session_id);
			gnutls_transport_set_int(session, client_fd);
			int ret;
			do {
				ret = gnutls_handshake(session);
			} while (ret < 0 && gnutls_error_is_fatal(ret) == 0);

			for(int n; (n = gnutls_record_recv(session, buffer, 40960000)) > 0;) {
				if(idNchannel_.find(session_id.data) == idNchannel_.end()) 
					idNchannel_[session_id.data] = new Channel(inport_);
				idNchannel_[session_id.data]->send(string{buffer, n});
				string s = idNchannel_[session_id.data]->recv();
				cout << s << endl;
				gnutls_record_send(session, s.data(), s.size());
			}
			gnutls_bye(session, GNUTLS_SHUT_WR);
			gnutls_deinit(session);
			break;
		}
	}
}
