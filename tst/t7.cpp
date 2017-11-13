#include"server.h"
#include<fstream>
#include<iostream>
using namespace std;

int main()
{
	Client cl{"localhost", 2002};
	ifstream f("logo.jpg");
	string s; char c;
	while(f >> noskipws >> c) s += c;
	cout << s.size();
	cl.send(s);
}



