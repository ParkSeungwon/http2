#include<iostream>
#include<string>
#include"server.h"
using namespace std;
int main(int ac, char** av)
{
	Functor f;
	int port = ac < 2 ? 2001 : atoi(av[1]);
	Server sv{port};
	sv.start(f);
}
