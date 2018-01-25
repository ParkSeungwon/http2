#include<cassert>
#include<iostream>
#include<iomanip>
#include<fstream>
#include<gmpxx.h>
#include"crypt.h"
using namespace std;

int main()
{
	const char* file[] = {"www.dndd.com.key", "www.dndd.com.pub", 
						  "www.dndd.com.cert", "www.dndd.com.mod"};
	mpz_class z[4];
	for(int i=0; i<3; i++) {
		unsigned char c; string s;
		ifstream f(file[i]);
		while(f >> noskipws >> c) s += c;
		auto a = base64_decode(s);
		z[i] = bnd2mpz(a.begin(), a.end());
	}
	ifstream f(file[3]);
	vector<unsigned char> v;
	for(string s; f >> setw(2) >> hex >> s;) v.push_back(stoi(s, nullptr,16));
	z[3] = bnd2mpz(v.begin(), v.end());
	for(auto a : z) cout << hex << a << endl;
	cout << powm(z[2], z[1], z[3]) << endl;
}

