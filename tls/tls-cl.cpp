#include<unistd.h>
#include"tls.h"
#include"framework/server.h"
using namespace std;

class TLS_client : public Client
{
public:
	TLS_client(string ip, int port) : Client{ip, port} {
		auto a = t.client_hello();
		write(client_fd, &a, sizeof(a));
		string s = recv();
		t.set_buf(s.data());
		t.server_hello();
		s = recv();
		t.set_buf(s.data());
		t.server_certificate();
		s = recv();
		t.set_buf(s.data());
		t.server_key_exchange();
		s = recv();
		t.server_hello_done();
		auto b = t.client_key_exchange();
		write(client_fd, &b, sizeof(b));
		auto c = t.change_cipher_spec();
		write(client_fd, &c, sizeof(c));
	}

protected:
	TLS<false> t;

private:
	int get_full_length(const string &s) {
		return static_cast<unsigned char>(s[3]) * 0x100 + static_cast<unsigned char>(s[4]) + 5;
	}
};

int main(int ac, char **av) {
	int port = ac < 2 ? 4430 : atoi(av[1]);
	TLS_client t{"localhost", port};
}


