#include<iostream>
#include<sstream>
#include<string>
#include<cstring>
#include"server.h"
#include"dndd.h"
#include"util.h"
using namespace std;


int main(int ac, char** av)
{
	Dndd f;
	int port = ac < 2 ? 2001 : atoi(av[1]);
	Server sv{port, 5};
	sv.nokeep_start(f);
}
