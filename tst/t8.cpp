#include"server.h"
#include<fstream>
#include<iostream>
using namespace std;

int main()
{
	ifstream f("index.html");
	string t; char c;
	while(f >> noskipws >> c) t += c;
	Server sv{2002};
//	while(1) {
//		string s = sv.recv();
//		if(s != "") cout << s;
//	}
	sv.nokeep_start([&](string s) {
			cout << s.size() << s << endl; 
			return "HTTP/1.1 200 OK\r\nContent-type: text/html\r\n" + t;
		}
	);
}



