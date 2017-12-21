#include"server.h"

class TLS : public Server
{
public:
	TLS();
	void start();

protected:
	WOLFSSL_CTX* ctx_;
};

