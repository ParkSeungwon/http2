#include"server.h"
#include<fstream>
#include<iostream>
using namespace std;

int main()
{
	Server sv{2002};
//	while(1) {
//		string s = sv.recv();
//		if(s != "") cout << s;
//	}
	sv.nokeep_start([](string s){cout << s.size() << s << endl; return s;});
}



