#include<iostream>
#include"server.h"
#include"crypt.h"
#include"tls.h"
using namespace std;

mpz_class random_prime(unsigned byte);

int main(int ac, char** av)
{//middle.x 3000 2001
	AES aes;
	DiffieHellman d;
//	show(d.p, d.g, d.ya);
	unsigned char random[64];
	mpz2bnd(random_prime(64), random, random+64);
	auto master_secret = prf(random, random+32, "master secret", random, 48);
	auto keys = prf(master_secret.begin(), master_secret.end(), "key expansion", random, 120);

	cout << "master secret : ";
	for(auto& c : master_secret) cout << hex << +c;
	cout << endl;

	cout << "keys : ";
	for(auto& c : keys) cout << hex << +c;
	cout << endl;
	aes.key(d.yb(random_prime(32)));
	aes.iv(random_prime(16));
	unsigned char a[48] = "Hello this is monkey";
	auto v = aes.encrypt(a, a + 48);
	for(auto& c : v) cout << c;
	cout << endl;
	for(auto& c : aes.decrypt(v.begin(), v.end())) cout << c;
	cout << endl;

	SHA1 sha1;
	for(auto& c : sha1.hash(v.begin(), v.end())) cout << hex << +c;
	cout << endl;

}


