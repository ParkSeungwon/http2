#include<iostream>
#include<string>
#include"tcpip.h"
using namespace std;

int main(int ac, char** av)
{
	Client cl;
	string s;
	while(1) {
		cl.send("ok");
		cout << (s = cl.recv()) << endl;
		if(s == "end") break;
	}
}
