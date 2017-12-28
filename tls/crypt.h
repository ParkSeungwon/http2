#pragma once
#include<cassert>
#include<gmpxx.h>
#include<wolfssl/wolfcrypt/aes.h>
#include<wolfssl/wolfcrypt/sha.h>

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
		int sz = end - begin;
		wc_ShaUpdate(&sha_, &*begin, sz);
		wc_ShaFinal(&sha_, r.data());
		return r;
	}

protected:
	Sha sha_;
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

