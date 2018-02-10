#include<gmpxx.h>
#include<thread>
#include<unistd.h>
#include<json/json.h>
#include<iostream>
#include<fstream>
#include<sstream>
#include"crypt.h"
using namespace std;

int main()
{
	vector<unsigned char> v{0b00101000, 6, 2, 1,1,2, 1, 3};//, 1, 5, 0x16, 0x0e, 0x41, 0x62, 0x79, 0x62,
//		0x6f, 0x64, 0x79, 0x20, 0x74, 0x68, 0x65, 0x72, 0x65, 0x3f};
	{
	stringstream ss;
	for(auto a : v) ss << a;
	cout << der2json(ss) << endl;
	}

	ifstream f("f.der");
	unsigned char c;
	v.clear();
	while(f >> noskipws >> c) v.push_back(c);
	{
	stringstream ss;
	for(auto a : v) ss << a;
//	cout << der2json(ss) << endl;
	}

}
