#include<cassert>
#include<random>
#include<iostream>
#include<iomanip>
#include<sstream>
#include"crypt.h"
using namespace std;

template<typename It> mpz_class bnd2mpz(It begin, It end)
{//big endian to mpz
	stringstream ss; ss << "0x";
	for(It i=begin; i!=end; i++) ss << setw(2) << setfill('0') << hex << +*i;
	return mpz_class{ss.str()};
}

template<typename It> void mpz2bnd(mpz_class n, It begin, It end)
{//mpz to big endian
	for(It i=end; i!=begin; n /= 0x100) *--i = mpz_class{n % 0x100}.get_ui();
}

static void show() {}
template<typename... Args> void show(mpz_class a, Args... b)
{//print args
	std::cout <<  "0x" << std::hex << a << std::endl;
	show(b...);
}

mpz_class nextprime(mpz_class n) 
{//chance of composite passing will be extremely small
	mpz_class r;
	mpz_nextprime(r.get_mpz_t(), n.get_mpz_t());
	return r;
}

mpz_class random_prime(unsigned byte)
{//return byte length prime number
	unsigned char arr[byte];
	uniform_int_distribution<> di(0, 0xff);
	random_device rd;
	for(int i=0; i<byte; i++) arr[i] = di(rd);
	auto z = nextprime(bnd2mpz(arr, arr+byte));//a little hole : over 0xffffffffffff
	stringstream ss; ss << "0x";
	for(int i=0; i<byte; i++) ss << "ff";
	if(z > mpz_class{ss.str()}) return random_prime(byte);
	else return z;
}

mpz_class powm(mpz_class base, mpz_class exp, mpz_class mod) 
{
	mpz_class r;
	assert(mod);
	mpz_powm(r.get_mpz_t(), base.get_mpz_t(), exp.get_mpz_t(), mod.get_mpz_t());
	return r;
}

template mpz_class bnd2mpz(vector<unsigned char>::iterator a, vector<unsigned char>::iterator b);
template mpz_class bnd2mpz(unsigned char* a, unsigned char* b);
template void mpz2bnd(mpz_class n, vector<unsigned char>::iterator a, vector<unsigned char>::iterator b);
template void mpz2bnd(mpz_class n, unsigned char* a, unsigned char* b);
template void show<>(mpz_class, mpz_class, mpz_class, mpz_class, mpz_class);
