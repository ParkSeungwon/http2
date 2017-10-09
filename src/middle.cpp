#include<iostream>
#include<sstream>
#include<string>
#include<cstring>
#include"server.h"
#include"middle.h"
#include"util.h"
using namespace std;


int main(int ac, char** av)
{
	int port = ac < 2 ? 3000 : atoi(av[1]);
	int inner_port = ac < 3 ? 2001 : atoi(av[2]);
	Middle f{inner_port};
	Server sv{port, 5};
	sv.nokeep_start(f);
}

