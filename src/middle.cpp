#include"server.h"
#include"middle.h"
using namespace std;


int main(int ac, char** av)
{//middle.x 3000 2001
	int port = ac < 2 ? 3000 : atoi(av[1]);
	int inner_port = ac < 3 ? 2001 : atoi(av[2]);
	Middle sv{inner_port};
	sv.loop();
}

