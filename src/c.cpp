#include<iostream>
#include"framework/server.h"
using namespace std;

int main() {
	Client cl("localhost", 4000);
	string s;
//	for(int i=0; i<10000; i++) s += 's';
	while(cin >> s) cl.send(s);
}

