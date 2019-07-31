#include"tls.h"
#include"framework/server.h"
using namespace std;

class TServer : public Server {
public:
	TServer(int port) : Server{port} {}
private:
	int get_full_length(const string &s) {
		return s.size() < 5 ? 0 : static_cast<unsigned char>(s
				[3]) * 0x100 + static_cast<unsigned char>(s[4]) +
			5;
	}
};

class Func {
public:
	string operator()(string s) {
		string to_send;
		switch(count) {
		case 0 : t.client_hello(move(s));
				 to_send = t.server_hello();
				 to_send += t.server_certificate();
				 if(t.support_dhe()) to_send += t.
					 server_key_exchange();
				 to_send += t.server_hello_done();
				 break;
		case 1 : t.client_key_exchange(move(s)); break;
		case 2 : t.change_cipher_spec(move(s)); break;
		case 3 : t.finished(move(s));
				 to_send = t.change_cipher_spec();
				 to_send += t.finished();
				 break;
		default: cout << t.decode(move(s)) << endl;
				 to_send= t.encode("<html><h1>TLS 구현으로 배우는 암호학 </h1></html>");
		}
		count++;
		return to_send;
	}
private:
	static int count;
	TLS<true> t;
};

int Func::count = 0;

int main() {
	TServer sv{4433};
	Func func;
	sv.start(func);
}
