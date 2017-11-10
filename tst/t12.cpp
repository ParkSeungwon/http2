#include<iostream>
#include<server.h>
#include"src/htmlserver.h"
#include"src/dndd.h"
using namespace std;

//string f(string s) { 
//	cout << s << endl;
//	return s; }

int main(int ac, char** av)
{
	DnDD f;//DnDD bug proved
	Server sv{atoi(av[1])};
	sv.start(f);
}

