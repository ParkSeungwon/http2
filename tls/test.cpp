#include<iostream>
#include<fstream>
#include<sstream>
#include"crypt.h"
#include"ber.h"
#include"hash.h"
using namespace std;

mpz_class str2mpz(string s);
int main()
{
	ifstream f("server-cert.pem");
	string s = get_certificate_core(f);
	auto v = base64_decode(s);
	stringstream ss;
	for(uint8_t c : v) ss << c;	
	auto jv = der2json(ss);
	auto pub = str2mpz(jv[0][0][6][1].asString());
	uint8_t ar[256];
	cout << jv << endl;
	auto [K,e,sign] = get_pubkeys(jv);
	mpz2bnd(pub, ar, ar + 256);
	SHA2 sha;
	auto a = sha.hash(ar, ar + 256);

	s = get_certificate_core(f);
	v = base64_decode(s);
	stringstream ss2;
	for(uint8_t c : v) ss2 << c;	
	jv = der2json(ss2);
	auto [K2,e2,sign2] = get_pubkeys(jv);

	cout << hex << K2 << endl << hex << e2 << endl << hex << sign2 << endl << hex << powm(sign, e, K2) << endl;
	cout << hex << bnd2mpz(a.begin(), a.end()) << endl;
}
