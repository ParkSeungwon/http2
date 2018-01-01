#include<iostream>
#include"crypt.h"
using namespace std;

template<typename It> void HMAC::key(const It begin, const It end) {
	if(wc_HmacSetKey(&hmac_, SHA256, &*begin, end - begin))
		cerr << "set key error" << endl;
}

template<typename It> array<unsigned char,32> HMAC::hash(const It begin, const It end) 
{
	array<unsigned char, 32> r;
	wc_HmacUpdate(&hmac_, &*begin, end - begin);
	wc_HmacFinal(&hmac_, r.data());
	return r;
}


template void HMAC::key(vector<unsigned char>::iterator a, vector<unsigned char>::iterator b);
template void HMAC::key(unsigned char* a, unsigned char* b);
template array<unsigned char,32> HMAC::hash(vector<unsigned char>::iterator a, vector<unsigned char>::iterator b);
template array<unsigned char,32> HMAC::hash(unsigned char* a, unsigned char* b);

