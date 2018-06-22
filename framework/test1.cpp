#include<sys/socket.h>
#include<sys/types.h>
#include<unistd.h>//close
#include<iostream>
#include<catch.hpp>
#include"server.h"
using namespace std;

class Test : public Server
{
public:
	Test(int port = 4000, unsigned int time_out = 600, int queue = 10)
		: Server{port, time_out, queue}
	{ }
	string recv() {
		char buf[1024];
		string s, r;
		for(int i; (i = read(client_fd, buf, 1024)) > 0;) r += string(buf, i);
		return r;
	}
};
		
string f(string s) {
	cout << s << endl;
}

int main(int ac, char** av) {
	int port = ac < 2 ? 4000 : atoi(av[1]);
	Test sv{port};
	sv.start(f);
}

