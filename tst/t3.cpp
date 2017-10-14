#include<iostream>
#include"server.h"
using namespace std;

string f(string s) {
	cout << s << endl;
}

struct M : public Server {
	M(int port) : Server{port} {}
};

int main(int ac, char** av)
{
	int port = ac < 2 ? 2002 : atoi(av[1]);
	M sv{port};
	sv.start(f);
}

