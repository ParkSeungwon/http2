#include<iostream>
#include<vector>
#include"aes.h"
#include"crypt.h"//base64, mpz2bnd, random_prime
#include"hash.h"
#include"options/option.h"//CMDoption
using namespace std;

int main(int ac, char **av) 
{//i will upload my passwords to dropbox, so I need to encrypt it
	const mpz_class key{"0x471289aecb4389affde2d2d67892a"};
	CMDoption co{
		{"decrypt", "decrypt, input from cin", false }
	};
	if(!co.args(ac, av)) return 0;

	SHA1 sha;//IV + {msg + sha1 hash + 1-000 padding}, {} : aes128 encrypted
	if(string s; co.get<bool>("decrypt")) {
		AES<Decryption> aes;
		aes.key(key);
		for(char c; cin >> c;) s += c;
		auto v = base64_decode(move(s));
		aes.iv(&v[0]);
		v = aes.decrypt(v.begin() + 16, v.end());
		while(!v.back()) v.pop_back();
		v.pop_back();
		auto ar = sha.hash(v.begin(), v.end() - 20);
		if(!equal(ar.rbegin(), ar.rend(), v.rbegin())) cerr << "hash not match\n";
		v.resize(v.size() - 20);//remove sha1 hash output size 20
		for(char c : v) s += c;
		cout << s;
	} else {
		AES<Encryption> aes;
		aes.key(key);
		unsigned char ar[16];
		mpz2bnd(random_prime(16), ar, ar+16);
		aes.iv(ar);
		for(char c; cin >> noskipws >> c;) s += c;
		auto h = sha.hash(s.begin(), s.end());
		s.insert(s.end(), h.begin(), h.end());
		s += (char)1;//1+00000.. 패딩
		while(s.size() % 16) s += (char)0;
		auto v = aes.encrypt(s.begin(), s.end());
		v.insert(v.begin(), ar, ar+16);//add iv
		cout << base64_encode(v);
	}
}


