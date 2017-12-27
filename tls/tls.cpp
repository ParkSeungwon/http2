#include<iostream>
#include"server.h"
#include"crypt.h"
using namespace std;

mpz_class random_prime(unsigned byte);

int main(int ac, char** av)
{//middle.x 3000 2001
	AES aes;
	aes.key(random_prime(32));
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


