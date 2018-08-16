#include"framework/server.h"
#include"tls.h"
#include"https.h"
#include"crypt.h"
using namespace std;

int main(int ac, char** av) 
{
	int port = ac < 2 ? 3000 : atoi(av[1]);
	int inner_port = ac < 3 ? 2001 : atoi(av[2]);
	HTTPS sv{port, inner_port};
	sv.start();
}


