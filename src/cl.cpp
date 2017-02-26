#include<iostream>
#include<string>
#include<atomic>
#include"tcpip.h"
using namespace std;

Client cl;
atomic<bool> ended {false};
void recv_th(Client& cl) {
	while(!ended) cout << cl.recv() << endl;
}
int main(int ac, char** av)
{
	string s;
	thread th{recv_th, ref(cl)};

	while(cin >> s) {
		cl.send(s);
		if(s == "end") break;
	}
	ended = true;
	th.join();
}
