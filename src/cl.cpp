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
	Client cl;
	AsyncQueue<string> aq{bind(&Client::recv, &cl), f};
	string s;
	while(cin >> s) {
		cl.send(s);
		if(s == "end") break;
	}
}
