#include"server.h"
#include"dndd.h"
using namespace std;


int main(int ac, char** av)
{
	DnDD f;
	int port = ac < 2 ? 2001 : atoi(av[1]);
	Server sv{port, 5};
	sv.start(f);
}
