#include<json/json.h>
#include<iostream>
#include<fstream>
#include<sstream>
#include<iostream>
#include"crypt.h"
using namespace std;

int main(int ac, char** av)
{
//	vector<unsigned char> v{0b00101000, 3, 2, 1,1,2, 1, 3, 2,3,1,1,1, 12, 4, 120,2,3,50};//, 1, 5, 0x16, 0x0e, 0x41, 0x62, 0x79, 0x62,
//		0x6f, 0x64, 0x79, 0x20, 0x74, 0x68, 0x65, 0x72, 0x65, 0x3f};
//	vector<unsigned char> v{0b00101000, 0x09, 2, 3, 0x46, 0x6f, 0x6f, 2, 2, 1,2, 2,1,1};
	vector<unsigned char> v{0x30, 0x13,0x02,0x01,0x05,0x16,0x0e,0x41,0x6e,0x79,0x62,0x6f,0x64,0x79,0x20,0x74,0x68,0x65,0x72,0x65, 0x3f};
//	{
//		stringstream ss;
//		for(auto a : v) ss << a;
//		cout << ss.str() << endl;
//		cout << der2json(ss) << endl;
//	}

	ifstream f(ac > 1 ? av[1] : "cert.der");
	try {
		cout << der2json(f) << endl;
	} catch(const char* p) {
		cout << p << endl;
	}
}
