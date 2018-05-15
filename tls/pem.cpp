#include<iostream>
#include<sstream>
#include<fstream>
#include"crypt.h"
#include"tls.h"
using namespace std;

vector<unsigned char> base64_decode(string);
string get_core_certificate(istream& is) {
	string s, r;
	while(s.substr(0, 10) != "-----BEGIN") getline(is, s);
	while(getline(is, s)) 
		if(s.substr(0, 8) != "-----END") r += s;
		else return r;
}

int main(int ac, char** av)
{
	if(ac < 2) {
		cout << "usage : " << av[0] << " [pem file]" << endl;
		return 0;
	}
	ifstream f(av[1]);
	auto v = base64_decode(get_core_certificate(f));
	stringstream ss;
	for(auto c : v) ss << c;
	auto jv = der2json(ss);
	try { cout << jv << endl; }
	catch(const char* e) { cerr << e << endl; }
	cout << jv[0][0][6][1] << endl;
}
