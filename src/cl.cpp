#include<iostream>
#include<string>
#include<atomic>
#include"server.h"
using namespace std;

string f(string s) {
	return s;
}
int main(int ac, char** av)
{

	Client cl{f, "125.209.222.142", 80};
	string s;
	while(cin >> s) {
		cl.send(s);
		if(s == "end") break;
	}
}
