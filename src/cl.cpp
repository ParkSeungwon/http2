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
	int j;
	while(cin >> j) {
		string s;
		for(int i=0; i<j; i++) s += 'a';
		cl.send(s + '\n');
		if(s == "end") break;
	}
}
