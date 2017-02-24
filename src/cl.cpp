#include<iostream>
#include<string>
#include"tcpip.h"
using namespace std;

int main()
{
	Client cl;
	string s;
	while(cin >> s) {
		cl.send(s);
		cout << cl.recv();
	}
}
