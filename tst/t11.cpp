#include<string>
#include<fstream>
#include"crypt.h"
using namespace std;

int main()
{
	ifstream f1("www.dndd.com.cert");
	string s;
	for(unsigned char c; f1 >> noskipws >> c;) s += c;
	ofstream f2("cert.der");
	auto v = base64_decode(s);
	for(auto a : v) f2 << a;
}

