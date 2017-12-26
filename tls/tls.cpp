#include"server.h"
#include"tls.h"
using namespace std;


int main(int ac, char** av)
{//middle.x 3000 2001
	int port = ac < 2 ? 3000 : atoi(av[1]);
	int inner_port = ac < 3 ? 2001 : atoi(av[2]);
	TLS sv{port, inner_port};
	sv.start();
}


