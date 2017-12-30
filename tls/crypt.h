#pragma once
#include<cassert>
#include<gmpxx.h>
#include<wolfssl/wolfcrypt/aes.h>
#include<wolfssl/wolfcrypt/sha.h>
#include<wolfssl/wolfcrypt/hmac.h>

void show();
template<typename... Args> void show(mpz_class a, Args... b);
mpz_class random_prime(unsigned byte);
template<typename It> void mpz2bnd(mpz_class n, It begin, It end);
template<typename It> mpz_class bnd2mpz(It begin, It end);

class AES
{
public:
	AES(unsigned short bit = 256);
	void key(const mpz_class key);
	void key(const unsigned char* key);
	void iv(const mpz_class iv);
	void iv(const unsigned char* iv);
	template<typename It> std::vector<unsigned char> encrypt(It begin, It end) {
		int sz = end - begin;
		assert(sz % 16 == 0);
		std::vector<unsigned char> result(sz);
		wc_AesSetKey(&aes_, key_, key_size_, iv_, AES_ENCRYPTION);
		wc_AesCbcEncrypt(&aes_, result.data(), &*begin, sz);//&* for iterator
		return result;
	}
	template<typename It> std::vector<unsigned char> decrypt(It begin, It end) {
		int sz = end - begin;
		assert(sz % 16 == 0);
		std::vector<unsigned char> result(sz);
		wc_AesSetKey(&aes_, key_, key_size_, iv_, AES_DECRYPTION);
		wc_AesCbcDecrypt(&aes_, result.data(), &*begin, sz);
		return result;
	}

protected:
	unsigned char key_[32], iv_[16];
	Aes aes_;
	unsigned char key_size_;
};

class SHA1
{
public:
	SHA1();
	template<typename It> std::array<unsigned char, 20> hash(It begin, It end) {
		std::array<unsigned char, 20> r;
		wc_ShaUpdate(&sha_, &*begin, end - begin);
		wc_ShaFinal(&sha_, r.data());
		return r;
	}

protected:
	Sha sha_;
};

class HMAC
{//hmac using sha256
public:
	template<typename It> void key(It begin, It end) {
		if(wc_HmacSetKey(&hmac_, SHA256, &*begin, end - begin))
			std::cerr << "set key error" << std::endl;
	}
		
	template<typename It> std::array<unsigned char, 32> hash(It begin, It end) {
		std::array<unsigned char, 32> r;
		wc_HmacUpdate(&hmac_, &*begin, end - begin);
		wc_HmacFinal(&hmac_, r.data());
		return r;
	}

protected:
	Hmac hmac_;
};

template<typename It> std::vector<unsigned char> prf(It begin, It end, 
		const char* label, unsigned char* seed, int n) {
	unsigned char buf[100];
	int i = 0;
	while(buf[i++] = *label++);//cpy until null
	int sz = i - 1 + 64;
	assert(sz < 100);
	memcpy(buf + i - 1, seed, 64);

	HMAC h;
	std::vector<std::array<unsigned char, 32>> A;
	h.key(buf, buf + sz);
	A.push_back(h.hash(begin, end));//A(1)

	std::vector<unsigned char> r;
	for(int i=0; i<n; i+=32) {
		auto a = A.back();
		std::vector<unsigned char> v(a.begin(), a.end());
		v.insert(v.end(), buf, buf+sz);//A(1) + seed
		h.key(v.begin(), v.end());
		auto ha = h.hash(begin, end);
		r.insert(r.end(), ha.begin(), ha.end());//HMAC(secret, A(1) + seed) + ...
		h.key(A.back().begin(), A.back().end());//A(i) = HMAC(secret, A(i-1))
		A.push_back(h.hash(begin, end));
	}
	return {r.begin(), r.begin()+n};
}

class DiffieHellman
{
public:
	DiffieHellman();
	mpz_class yb(mpz_class pub_key);
	mpz_class p, g, ya, yb_;

protected:
	mpz_class q, h, K, xa;
};

