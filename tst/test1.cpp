#include<iostream>
#include"server.h"
using namespace std;

string f(string s) {
	cout << s << endl;
}

int main(int ac, char** av)
{
	int port = ac < 2 ? 2002 : atoi(av[1]);
	Server sv{port};
	sv.start(f);
}
