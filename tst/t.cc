#include<catch.hpp>
#include<fstream>
#include<iostream>
#include<iomanip>
#include<gmpxx.h>
#include"crypt.h"
using namespace std;

string get_certificate_core(istream& is);
Json::Value pem2json(istream& is);

TEST_CASE("embed picture & html with base64 encode") {
	unsigned char c; vector<unsigned char> v;
	ifstream f("chicago.jpg");
	while(f >> noskipws >> c) v.push_back(c);
	ofstream f2("/tmp/1.html");
	f2 << "<img src='data:image/jpeg;base64,";
	f2 << base64_encode(v);
	f2 << "'><br>\n";
	f2 << "<iframe src='data:text/html;base64,";
	ifstream f3("edit.html");
	v.clear();
	while(f3 >> noskipws >> c) v.push_back(c);
	f2 << base64_encode(v) << "'></iframe>";
}

TEST_CASE("pem test") {
	ifstream f("server-cert.pem");
	cout << pem2json(f) << endl;//first
	cout << pem2json(f) << endl;//second that sponsor first
}

TEST_CASE("mpz2bnd") {
	unsigned char c[] = {3, 3, 3};
	mpz2bnd(0x100, c, c+3);
	REQUIRE(c[0] == 0);
	REQUIRE(c[1] == 1);
	REQUIRE(c[2] == 0);
}
TEST_CASE("c++17 []") {
	array<int, 3> ar{0,1,2};
	auto [a, b, c] = ar;
	REQUIRE((a == 0 && b == 1 && c == 2));
}
//TEST_CASE("www.dndd.com.???") {
//	const char* file[] = {"www.dndd.com.key", "www.dndd.com.pub", 
//						  "www.dndd.com.cert", "www.dndd.com.mod"};
//	mpz_class z[4];
//	for(int i=0; i<3; i++) {
//		unsigned char c; string s;
//		ifstream f(file[i]);
//		while(f >> noskipws >> c) s += c;
//		auto a = base64_decode(s);
//		z[i] = bnd2mpz(a.begin(), a.end());
//	}
//	ifstream f(file[3]);
//	vector<unsigned char> v;
//	for(string s; f >> setw(2) >> hex >> s;) v.push_back(stoi(s, nullptr,16));
//	z[3] = bnd2mpz(v.begin(), v.end());
//	for(auto a : z) cout << hex << a << endl;
//	cout << powm(z[2], z[1], z[3]) << endl;
//}

array<mpz_class, 3> get_pubkeys(istream& is);
TEST_CASE("get_pubkey") {
	ifstream f("pu.pem");
	auto [a,b,c] = get_pubkeys(f);
	cout << "pubkey : "  << hex << a << endl << b << endl << c << endl;
	cout << hex << powm(c, b, a);
}
