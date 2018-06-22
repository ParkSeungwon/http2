#include"server.h"
#include<iostream>
using namespace std;

int main(int ac, char** av) {
	int port = ac < 2 ? 4000 : atoi(av[1]);
	Client cl("localhost", port);
	string s, r;
	int k;
	while(cin >> k) {
		for(int j=0; j<2; j++) {
			s = "";
			for(int i=0; i<k; i++) s += 's';
			cl.send(s);
		}
	}
}



