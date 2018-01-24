#include<iostream>
#include<fstream>
#include<gmpxx.h>
#include"crypt.h"
using namespace std;

int main()
{
	ifstream f("server-cert.pem");
	string s;
	vector<unsigned char> K[2], C[2];
	string cert[2];
	mpz_class Kz[2], Cz[2];
	for(int i=0, k; i<2; i++) {
		while(s != "Modulus:") f >> s;
		for(char c = ':'; c == ':'; K[i].push_back(k)) f >> hex >> k >> c;
		while(s != "CERTIFICATE-----") f >> s;
		for(char c; c != '-'; cert[i] += c) f >> c; 
		cert[i].pop_back();

		for(auto& a : K[i]) cout << hex << +a << ' '; cout << endl;
		cout << cert[i] << endl;

		C[i] = base64_decode(cert[i]);
		Kz[i] = bnd2mpz(K[i].begin(), K[i].end());
		Cz[i] = bnd2mpz(C[i].begin(), C[i].end());
	}

	auto r = powm(Cz[0], 65537, Kz[1]);
	cout << hex << r << endl;
}



