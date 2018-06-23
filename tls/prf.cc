#include<cassert>
#include<iomanip>
#include<iostream>
#include"crypt.h"
using namespace std;

void print(unsigned char* r, const char* c)
{
	cout << c << endl;
	for(int i=0; i<256; i++) {
		cout << setw(2) << setfill('0') << hex << +r[i] << ' ';
		if(i%16 == 15) cout << endl;
	}
	cout << endl;
}

template<typename It> vector<unsigned char> prf(const It begin, const It end, 
		const char* label, unsigned char* seed, int n)
{//seed is always 64byte long, expand to n byte
	unsigned char aseed[128]={}, r[256]={};//((n-1)/32+1)*32];
	int i = 0;
	const int hash_sz = 20;
	while(aseed[hash_sz + i++] = *label++);//copy until null
	int sz = hash_sz + i - 1 + 64;
	assert(sz <= 128 && n <= 256);
	memcpy(aseed + hash_sz + i - 1, seed, 64);//buf = label + seed

	vector<array<unsigned char, hash_sz>> A;
	HMAC h;
	h.key(aseed + hash_sz, aseed + sz);//seed
	A.push_back(h.hash(begin, end));//A(1)
	for(int j=0; j<n; j+=hash_sz) {
		memcpy(aseed, A.back().data(), hash_sz);//aseed = A(i) + seed
		h.key(aseed, aseed + sz);
		auto t = h.hash(begin, end);
		memcpy(r + j, t.data(), hash_sz);//HMAC(secret, A(1) + seed) + ...
		h.key(A.back().begin(), A.back().end());//A(i) = HMAC(secret, A(i-1))
		A.push_back(h.hash(begin, end));
	}
	return {r, r+n};
}

template vector<unsigned char> prf(vector<unsigned char>::iterator a, vector<unsigned char>::iterator b, const char*, unsigned char*, int);
template vector<unsigned char> prf(unsigned char* a, unsigned char* b,
		const char*, unsigned char*, int);


