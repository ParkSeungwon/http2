#include<map>
#include<chrono>
#include"server.h"


struct WOLFSSL_CTX;
class TLS : public Server
{
public:
	TLS(int outport = 3000, int inport = 2001);
	~TLS();
	void start();

protected:
	WOLFSSL_CTX* ctx_;
	struct Channel : public Client, public std::chrono::system_clock::time_point {
		Channel(int port);
	};
	struct Less {
		bool operator()(const unsigned char* a, const unsigned char* b) const;
	};
	std::map<const unsigned char*, TLS::Channel*, TLS::Less> idNchannel_;
	int inport_;
};

