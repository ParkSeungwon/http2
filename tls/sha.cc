#include<iostream>
#include"crypt.h"
using namespace std;

SHA1::SHA1()
{
	if(wc_InitSha(&sha_)) cerr << "wc_init_sha_failed" << endl;
}

template<typename It> array<unsigned char, 20> SHA1::hash(const It begin, const It end) {
	array<unsigned char, 20> r;
	wc_ShaUpdate(&sha_, &*begin, end - begin);
	wc_ShaFinal(&sha_, r.data());
	return r;
}

template array<unsigned char, 20> SHA1::hash(vector<unsigned char>::iterator a,
		vector<unsigned char>::iterator b);
template array<unsigned char, 20> SHA1::hash(unsigned char* a, unsigned char* b);

