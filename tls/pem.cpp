#include<cassert>
#include<iomanip>
#include<iostream>
#include<sstream>
#include<fstream>
#include"crypt.h"
#include"tls.h"
using namespace std;

vector<unsigned char> base64_decode(string);
string get_certificate_core(istream& is) {
	string s, r;
	while(s.substr(0, 10) != "-----BEGIN") getline(is, s);
	while(getline(is, s)) 
		if(s.substr(0, 8) != "-----END") r += s;
		else return r;
}

mpz_class str2mpz(string s) {
	vector<unsigned char> v; stringstream ss; char c;
	ss << s; 
	while(ss >> setw(2) >> s >> c) v.push_back(stoi(s, nullptr, 16));
	return bnd2mpz(v.begin(), v.end());
}

Json::Value pem2json(istream& is) {
	auto v = base64_decode(get_certificate_core(is));
	stringstream ss;
	for(auto c : v) ss << c;
	return der2json(ss);
}

array<mpz_class, 2> process_bitstring(string s)
{//RSA bitstring should be reprocessed to get the modulus and exponent
	stringstream ss, ss2; char c;
	ss << s;
	ss >> setw(2) >> s >> c;//garbage
	while(ss >> setw(2) >> s >> c) {
		c = stoi(s, nullptr, 16);
		ss2 << c;
	}
	auto jv = der2json(ss2);
	return {str2mpz(jv[0][0].asString()), str2mpz(jv[0][1].asString())};
}

array<mpz_class, 3> get_pubkeys(istream& is)
{//array = {RSA modulus, RSA exponent, sha sign}
	auto jv = pem2json(is);
	auto [a, b] = process_bitstring(jv[0][0][6][1].asString());//asString remove " ";
	auto c = str2mpz(jv[0][2].asString());
	return {a, b, c};
}

mpz_class get_prvkey(istream& is)
{
	auto jv = pem2json(is);
	return str2mpz(jv[0][3].asString());
}

int main(int ac, char** av)
{//extract RSA keys from pem files and test it
	ifstream f("pu.pem");//openssl req -x509 -days 1000 -new -key p.pem -out pu.pem
	auto ar = get_pubkeys(f);
	for(auto a : ar) cout << "0x" << hex << a << endl;
	ifstream f2("p.pem");//generated with openssl genrsa 2048 > p.pem
	auto prv = get_prvkey(f2);
	cout << "0x" << prv << endl;
	mpz_class m = 125;
	auto c = powm(m, ar[1], ar[0]);//encrypt
	assert(m == powm(c, prv, ar[0]));//decrypt and compare with original
}
