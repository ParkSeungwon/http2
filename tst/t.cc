#include<catch.hpp>
#include<fstream>
#include<iostream>
#include<regex>
#include<iomanip>
#include<gmpxx.h>
#include"tls/crypt.h"
#include"framework/server.h"
#include"tls/tls.h"
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
	pem2json(f);//first
	pem2json(f);//second that sponsor first
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

TEST_CASE("regex") {
	string s = "Last-Modified: Sat, 23 Sep 2017 01:42:37 GMT\n"
				"Content-Type: text/html\n"
				"Content-Length: 30\n"
				"Date: Thu, 12 Oct 2017 17:42:56 GMT\r\n\r\n"
				"123456789012345678901234567890";

	smatch m;
	regex_search(s, m, 	regex{R"(Content-Length:\s*(\d+))"});
	REQUIRE(m[1].str() == "30");
	REQUIRE(s.find("\r\n\r\n") != string::npos);
	REQUIRE(stoi(m[1].str()) + s.find("\r\n\r\n") + 4 == s.size());
	REQUIRE(s.substr(0, s.size()) == s);
}
	
TEST_CASE("array init") {
	array<int, 10> a{};
	array<int, 10> b;
	for(int i=0; i<10; i++) REQUIRE(a[i] == 0);
	for(auto c : array<int, 10>{}) REQUIRE(c == 0);
//	for(int i=0; i<10; i++) REQUIRE(b[i] == 0);//this is not true
	string s = "abcde";
	REQUIRE("ab" == s.substr(0, 2));
	REQUIRE("de" == s.substr(3));
}

TEST_CASE("certificate func") {
	stringstream ss; unsigned char c = 25, d = 2;
	ss << c; ss << d;
	ss >> c; ss >> d;
	REQUIRE(c == 25);
	REQUIRE(d == 2);
}

string func() {
	string k;
	return k+="cc";
}
TEST_CASE("return =") {
	REQUIRE(func() == "cc");
}
TEST_CASE("bool []") {
	char c[2] = {'a', 'c'};
	REQUIRE(c[true] == 'c');
}

TEST_CASE("substr index") {
	string s = "data:text/html;base,";
	REQUIRE(s.substr(0, 15) == "data:text/html;");
}

int f() {
	cout << 1 << ' ';
	return 1;
}
int g() {
	cout << 2 << ' ';
	return 2;
}
TEST_CASE("which is front") {
	f() + g();
	cout << __LINE__ << ' ' << __FILE__ << __func__ << endl;
}

TEST_CASE("startwiwth") {
	string s = "Content-Type: multipart/form-data; boundary=----WebKitFormBoundary1feen4q1pjqBCnWz";
	REQUIRE(s.find("Content-Type: multipart/form-data;") == 0);
	REQUIRE(s.substr(s.find("boundary=") + 9) == "----WebKitFormBoundary1feen4q1pjqBCnWz");

	s = "Content-Disposition: form-data; name=\"file\"; filename=\"IMG_0315.JPG\"";
	regex e1{R"raw(name="(\w+)")raw"}, e2{R"raw(filename="(\S+)")raw"};
	smatch m; string name, filename, val;
	if(regex_search(s, m, e1)) name = m[1].str();
	s = m.suffix().str();
	if(regex_search(s, m, e2)) filename = m[1].str();

	REQUIRE(name == "file");
	REQUIRE(filename == "IMG_0315.JPG");
}

TEST_CASE("aes overflow test") {
#pragma pack(1)
	Aes aes;
	unsigned char over[32], key[32], iv[16], result[32], msg[32];
#pragma pack()
	for(int i=0; i<32; i++) over[i] = 1;
	wc_AesSetKey(&aes, key, 16, iv, AES_DECRYPTION);
	wc_AesCbcEncrypt(&aes, result, msg, 32);
	cout << "overflow : ";
	for(int i=0; i<32; i++) cout << +over[i];
	for(int i=0; i<32; i++) cout << +result[i];
	for(int i=0; i<32; i++) cout << +msg[i];
}

void f(char* p) {
	for(int i=0; i<10; i++) p[i] = '1';
}
TEST_CASE("const array") {
	const char c[] = "abcdefghijklmn";
//	f(c);
}
