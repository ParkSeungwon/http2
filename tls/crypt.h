#pragma once
#include<array>
#include<iomanip>
#include<iostream>
#include<sstream>
#include<cassert>
#include<gmpxx.h>
#include<cstdio>
#include<json/json.h>

Json::Value pem2json(std::istream& is);
Json::Value der2json(std::istream& is);
std::array<mpz_class, 3> get_pubkeys(std::istream& is);
std::array<mpz_class, 3> get_pubkeys(const Json::Value& jv);
std::string base64_encode(std::vector<unsigned char> v);
std::vector<unsigned char> base64_decode(std::string s);
template<typename... Args> void show(mpz_class a, Args... b);
mpz_class random_prime(unsigned byte);
mpz_class nextprime(mpz_class n);
mpz_class powm(mpz_class base, mpz_class exp, mpz_class mod);
template<typename It> void mpz2bnd(mpz_class n, It begin, It end)
{//mpz to big endian
	for(It i=end; i!=begin; n /= 0x100) *--i = mpz_class{n % 0x100}.get_ui();
}
template<typename It> mpz_class bnd2mpz(It begin, It end)
{//big endian to mpz
	std::stringstream ss; ss << "0x";
	for(It i=begin; i!=end; i++)
		ss << std::hex << std::setfill('0') << std::setw(2) << +*i;
	return mpz_class{ss.str()};
}
void print(unsigned char* r, const char* c);
std::string get_certificate_core(std::istream& is);

template<class C> std::string hexprint(const char *p, const C &c)
{//log container specialization
	std::stringstream ss;
	ss << p << " : 0x";
	for(unsigned char a : c) ss << std::hex << std::setw(2) << std::setfill('0')<< +a;
	return ss.str();
}

class DHE
{//256 byte = 2048 bit, update ffdhe tls1.3 version
public:
	DHE(int bit = 2048);
	DHE(mpz_class p, mpz_class g, mpz_class ya);
	mpz_class set_yb(mpz_class pub_key);
	mpz_class p{"0xFFFFFFFFFFFFFFADF85458A2BB4A9AAFDC5620273D3CF1D8B9C583CE2D3695A9E13641146433FBCC939DCE249B3EF97D2FE363630C75D8F681B202AEC4617AD3DF1ED5D5FD65612433F51F5F066ED0856365553DED1AF3B557135E7F57C935984F0C70E0E68B77E2A689DAF3EFE8721DF158A136ADE73530ACCA4F483A797ABC0AB182B324FB61D108A94BB2C8E3FBB96ADAB760D7F4681D4F42A3DE394DF4AE56EDE76372BB190B07A7C8EE0A6D709E02FCE1CDF7E2ECC03404CD28342F619172FE9CE98583FF8E4F1232EEF28183C3FE3B1B4C6FAD733BB5FCBC2EC22005C58EF1837D1683B2C6F34A26C1B2EFFA886B423861285C97FFFFFFFFFFFFFFFF"};
	mpz_class g = 2;
	mpz_class ya, yb, K;

protected:
	mpz_class xa, xb;
};

class RSA
{
public:
	RSA(int key_size);//generate key
	RSA(mpz_class e, mpz_class d, mpz_class K);//read frem certificate or memory
	mpz_class sign(mpz_class m), decode(mpz_class m), encode(mpz_class m);
	mpz_class K, e;
protected:
	mpz_class p, q, d, phi;
};

class ECDHE
{//curve25519 nettle library
public:
	ECDHE();
//	void set_P(mpz_class P);
	mpz_class set_Q(mpz_class Q);
	mpz_class Q, N, K;
private:
	uint8_t q[32], n[32], k[32];//little endian
};
