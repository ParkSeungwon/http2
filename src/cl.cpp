#include<iostream>
#include<string>
#include<atomic>
#include"server.h"
#include"asyncqueue.h"
using namespace std;

void f(string s) {
	cout << s << endl;
}

int main(int ac, char** av)
{
	string host = ac < 3 ? "127.0.0.1" : av[1];
	int port = ac < 2 ? 2001 : atoi(av[2]);
	Client cl{host, port};
	AsyncQueue<string> aq{bind(&Client::recv, &cl), f};//how beautiful
	string s;
	while(cin >> s) {
		cl.send(s + "\r\n\r\n");
		if(s == "end") break;
	}
}
