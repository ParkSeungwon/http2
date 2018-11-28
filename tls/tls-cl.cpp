#include<functional>
#include<iostream>
#include"tls.h"
#include"framework/asyncqueue.h"
#include"framework/server.h"
#include"options/option.h"
#include"options/log.h"
using namespace std;

class TLS_client : public Client
{
public:
	TLS_client(string ip, int port) : Client{ip, port} {
		send(t.client_hello()); 			LOGI << "client hello" << endl;
		t.server_hello(recv()); 			LOGI << "server hello" << endl;
		t.server_certificate(recv()); 		LOGI << "server certificate" << endl;
		if(t.support_dhe()) 
			t.server_key_exchange(recv()), 	LOGI << "server key exchange" << endl;
		t.server_hello_done(recv()); 		LOGI << "server hello done" << endl;
		string a = t.client_key_exchange(); LOGI << "client key exchange" << endl;
		string b = t.change_cipher_spec(); 	LOGI << "change cipher spec" << endl;
		string c = t.finished(); 			LOGI << "client finished" << endl;
		send(a + b + c);
		t.change_cipher_spec(recv()); 		LOGI << "change cipher spec" << endl;
		t.finished(recv()); 				LOGI << "server finished" << endl;
	}
	TLS<false> t;

protected:

private:
	int get_full_length(const string &s) {
		return static_cast<unsigned char>(s[3]) * 0x100 + static_cast<unsigned char>(s[4]) + 5;
	}
};

int main(int ac, char **av) {
	CMDoption co{
		{"port", "port of the host", 4433},
		{"ip", "ip address of the host", "localhost"}
	};
	if(!co.args(ac, av)) return 0;
	TLS_client t{co.get<const char*>("ip"), co.get<int>("port")};
	AsyncQueue<string> aq {
		bind(&TLS_client::recv, &t, 0),
		[&t](string s) { cout << t.t.decode(move(s)); }
	};
	string s;
	while(getline(cin, s)) t.send(t.t.encode(move(s)));
}


