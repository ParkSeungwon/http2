#include<cstring>
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

void show() {}
template<typename... Args> void show(mpz_class a, Args... b)
{//print args
	std::cout <<  "0x" << std::hex << a << std::endl;
	show(b...);
}
template void show<>(mpz_class, mpz_class, mpz_class, mpz_class, mpz_class);

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
	return nextprime(bnd2mpz(arr, arr+byte));//a little hole : over 0xffffffffffff
}

mpz_class powm(mpz_class base, mpz_class exp, mpz_class mod) 
{
	mpz_class r;
	mpz_powm(r.get_mpz_t(), base.get_mpz_t(), exp.get_mpz_t(), mod.get_mpz_t());
	return r;
}

AES::AES(unsigned short bit) : key_size_{bit / 8} 
{
	assert(key_size_ == 16 || key_size_ == 24 || key_size_ == 32);
}

void AES::key(const mpz_class key)
{
	mpz2bnd(key, key_, key_+32);
}

void AES::key(const unsigned char* key)
{
	memcpy(key_, key, 32);
}

void AES::iv(const mpz_class iv)
{
	mpz2bnd(iv, iv_, iv_+16);
}

void AES::iv(const unsigned char* iv)
{
	memcpy(iv_, iv, 16);
}

SHA1::SHA1()
{
	if(wc_InitSha(&sha_)) cerr << "wc_init_sha_failed" << endl;
}

DiffieHellman::DiffieHellman()
{
	p = random_prime(32), q = random_prime(16), h = random_prime(16);
	g = powm(h, (p-1)/q, p);
	ya = random_prime(32);
	xa = powm(g, xa, p);
}

mpz_class DiffieHellman::yb(mpz_class pub_key)
{
	return K = powm(yb_ = pub_key, xa, p);
}
