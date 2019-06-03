#include<iostream>
#include<vector>
#include"block_cipher.h"
#include"crypt.h"//base64, mpz2bnd, random_prime
#include"hash.h"
#include"options/option.h"//CMDoption
using namespace std;

int main(int ac, char **av) 
{//i will upload my passwords to dropbox, so I need to encrypt it
	const mpz_class key2{"0x471289aecb4389affde2d2d67892a"};
	uint8_t key[16];
	mpz2bnd(key2, key, key + 16);
	CMDoption co{
		{"decrypt", "decrypt, input from cin", false }
	};
	if(!co.args(ac, av)) return 0;

	SHA1 sha;//IV + {msg + sha1 hash + 1-000 padding}, {} : aes128 encrypted
	CBC<AES<128>> aes;
	if(string s; co.get<bool>("decrypt")) {
		aes.dec_key(key);
		for(char c; cin >> c;) s += c;
		auto v = base64_decode(move(s));
		aes.dec_iv(&v[0]);
		v = aes.decrypt(&*(v.begin() + 16), v.size()-16);
		while(!v.back()) v.pop_back();
		v.pop_back();
		auto ar = sha.hash(v.begin(), v.end() - 20);
		if(!equal(ar.rbegin(), ar.rend(), v.rbegin())) cerr << "hash not match\n";
		v.resize(v.size() - 20);//remove sha1 hash output size 20
		for(char c : v) s += c;
		cout << s;
	} else {
		aes.enc_key(key);
		unsigned char ar[16];
		mpz2bnd(random_prime(16), ar, ar+16);
		aes.enc_iv(ar);
		for(char c; cin >> noskipws >> c;) s += c;
		auto h = sha.hash(s.begin(), s.end());
		s.insert(s.end(), h.begin(), h.end());
		s += (char)1;//1+00000.. 패딩
		while(s.size() % 16) s += (char)0;
		auto v = aes.encrypt((uint8_t*)&*s.begin(), s.size());
		v.insert(v.begin(), ar, ar+16);//add iv
		cout << base64_encode(v);
	}
}


