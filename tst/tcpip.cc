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

//TEST_CASE("tcpip buffer size small test") {
//	Test sv{4000};
//	sv.start(f);
//}
//
//TEST_CASE("client") {
//	Client cl("localhost", 4000);
//	string s;
//	for(int i=0; i<10000; i++) s += 's';
//	cl.send(s);
//}
//
