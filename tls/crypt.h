#pragma once
#include<array>
#include<gmpxx.h>
#include<wolfssl/wolfcrypt/aes.h>
#include<wolfssl/wolfcrypt/sha.h>
#include<wolfssl/wolfcrypt/hmac.h>
#include<json/json.h>

Json::Value der2json(std::istream& is);
std::string base64_encode(std::vector<unsigned char> v);
std::vector<unsigned char> base64_decode(std::string s);
template<typename... Args> void show(mpz_class a, Args... b);
mpz_class random_prime(unsigned byte);
mpz_class nextprime(mpz_class n);
mpz_class powm(mpz_class base, mpz_class exp, mpz_class mod);
template<typename It> void mpz2bnd(mpz_class n, It begin, It end);
template<typename It> mpz_class bnd2mpz(It begin, It end);
void print(unsigned char* r, const char* c);
template<typename It> std::vector<unsigned char> prf(const It begin, const It end, 
		const char* label, unsigned char* seed, int n); //seed is always 64byte long

class AES
{
public:
	AES(unsigned short bit = 256);
	void key(const mpz_class key);
	void key(const unsigned char* key);
	void iv(const mpz_class iv);
	void iv(const unsigned char* iv);
	template<typename It>
		std::vector<unsigned char> encrypt(const It begin, const It end);
	template<typename It>
		std::vector<unsigned char> decrypt(const It begin, const It end);
protected:
	unsigned char key_[32], iv_[16];
	Aes aes_;
	unsigned char key_size_;
};

class SHA1
{
public:
	SHA1();
	template<typename It> std::array<unsigned char, 20> hash(const It begin, const It end);
protected:
	Sha sha_;
};

class SHA256
{
public:
	SHA256();
	template<typename It> std::array<unsigned char, 32> hash(const It begin, const It end);
protected:
	Sha256 sha_;
};


class HMAC
{//hmac using sha1
public:
	template<typename It> void key(const It begin, const It end);
	template<typename It> std::array<unsigned char, 20> hash(const It begin, const It end);
protected:
	const int block_size_ = 64;
	SHA1 sha_;
	std::array<unsigned char, 64> o_key_pad_, i_key_pad_;
};

class DiffieHellman
{
public:
	DiffieHellman();
	mpz_class yb(mpz_class pub_key);
	mpz_class p, g, ya, yb_;
protected:
	mpz_class q, h, K, xa;
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

