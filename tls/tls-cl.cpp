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
		t.server_key_exchange(recv());
		t.server_hello_done(recv());
		send(t.client_key_exchange() + t.change_cipher_spec() + t.finished());
		t.get_content_type(recv());
		t.finished(recv());
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


