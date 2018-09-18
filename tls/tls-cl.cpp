#include<functional>
#include<framework/asyncqueue.h>
#include<iostream>
#include"tls.h"
#include"framework/server.h"
using namespace std;

class TLS_client : public Client
{
public:
	TLS_client(string ip, int port) : Client{ip, port} {
		send(t.client_hello());
		t.server_hello(recv());
		t.server_certificate(recv());
		if(t.support_dhe()) t.server_key_exchange(recv());
		t.server_hello_done(recv());
		send(t.client_key_exchange() + t.change_cipher_spec() + t.finished());
		t.change_cipher_spec(recv());
		t.finished(recv());
	}
	TLS<false> t;

protected:

private:
	int get_full_length(const string &s) {
		return static_cast<unsigned char>(s[3]) * 0x100 + static_cast<unsigned char>(s[4]) + 5;
	}
};

int main(int ac, char **av) {
	int port = ac < 2 ? 4430 : atoi(av[1]);
	string ip = ac < 3 ? "localhost" : av[2];
	TLS_client t{ip, port};
	string s;
	AsyncQueue<string> aq {
		bind(&TLS_client::recv, &t),
		[&](string s) { cout << t.t.decode(move(s)); }
	};
	while(getline(cin, s)) t.send(t.t.encode(move(s)));
}


