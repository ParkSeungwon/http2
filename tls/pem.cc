#include<iostream>
#include<iomanip>
#include<sstream>
#include<fstream>
#include"crypt.h"
using namespace std;

string get_certificate_core(istream& is) {
	string s, r;
	while(s != "-----BEGIN") is >> s;
	getline(is, s);
	for(is >> s; s != "-----END"; is >> s) r += s;
	return r;
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

array<mpz_class, 3> get_keys(istream& is)
{//RSA mod, exp, prv key
	auto jv = pem2json(is);
	return {str2mpz(jv[0][1].asString()), str2mpz(jv[0][2].asString()), str2mpz(jv[0][3].asString())};
}

