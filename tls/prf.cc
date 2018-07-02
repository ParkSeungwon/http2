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
{//seed is always 64byte long, expand seed to n byte pseudo random 
	unsigned char aseed[128]={}, r[256]={};//((n-1)/32+1)*32];
	int i = 0;
	const int hash_sz = 32;//sha256
	while(aseed[hash_sz + i++] = *label++);//copy until null
	int sz = hash_sz + i - 1 + 64;//hash + label + seed length
	assert(sz <= 128 && n <= 256);
	memcpy(aseed + hash_sz + i - 1, seed, 64);//aseed = hash_placehold + label + seed

	vector<array<unsigned char, hash_sz>> A;
	HMAC<SHA2> h;
	h.key(aseed + hash_sz, aseed + sz);//seed
	A.push_back(h.hash(begin, end));//A(1)
	for(int j=0; j<n; j+=hash_sz) {
		memcpy(aseed, A.back().data(), hash_sz);//aseed = A(i):placehold + seed
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
/*******************************
P_hash(secret, seed) = HMAC_hash(secret, A(1) + seed) +
					   HMAC_hash(secret, A(2) + seed) +
					   HMAC_hash(secret, A(3) + seed) + ...
where + indicates concatenation.
A() is defined as:
A(0) = seed
A(i) = HMAC_hash(secret, A(i-1))
P_hash can be iterated as many times as necessary to produce the
required quantity of data. For example, if P_SHA256 is being used to
create 80 bytes of data, it will have to be iterated three times
(through A(3)), creating 96 bytes of output data; the last 16 bytes
of the final iteration will then be discarded, leaving 80 bytes of
output data.
TLS’s PRF is created by applying P_hash to the secret as:
PRF(secret, label, seed) = P_<hash>(secret, label + seed)
The label is an ASCII string. It should be included in the exact
form it is given without a length byte or trailing null character.
For example, the label "slithy toves" would be processed by hashing
the following bytes:
73 6C 69 74 68 79 20 74 6F 76 65 73
*******************************/
