#include<thread>
#include<iostream>
#include"server.h"
using namespace std;

//class Test : public Server
//{
//public:
//	Test(int port = 4000, unsigned int time_out = 600, int queue = 10)
//		: Server{port, time_out, queue}
//	{ }
//	string recv() {
//		char buf[1024];
//		string s, r;
//		for(int i; (i = read(client_fd, buf, 1024)) > 0;) r += string(buf, i);
//		return r;
//	}
//};
//		
//
string f(string s) {
	this_thread::sleep_for(5s);
	cout << s << endl;
}

int main() {
	Server sv{4000};
	sv.start(f);
}
