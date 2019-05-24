#pragma once
#include<cassert>
#include<gmpxx.h>
#include<nettle/aes.h>
#include<nettle/cbc.h>
#include<nettle/gcm.h>
#include<type_traits>
#define Encryption true
#define Decryption false

template<int B = 128> class AES
{
public:
	void enc_key(const unsigned char* key);
	void dec_key(const unsigned char* key);
	static constexpr nettle_cipher_func *enc_func_ = B == 128 ? 
		(nettle_cipher_func*)aes128_encrypt : (nettle_cipher_func*)aes256_encrypt;
	static constexpr nettle_cipher_func *dec_func_ = B == 128 ? 
		(nettle_cipher_func*)aes128_decrypt : (nettle_cipher_func*)aes256_decrypt;
	typename std::conditional<B == 128, aes128_ctx, aes256_ctx>::type
		enc_ctx_, dec_ctx_;
protected:
	unsigned char enc_key_[32], dec_key_[32];
};

template<class Cipher> class CBC
{
public:
	void enc_iv(const unsigned char* iv);
	void dec_iv(const unsigned char* iv);
	void enc_key(const unsigned char *key);
	void dec_key(const unsigned char *key);
	template<class It> std::vector<uint8_t> encrypt(const It begin, const It end)
	{
		const int sz = end - begin;
		assert(sz % 16 == 0);
		std::vector<unsigned char> result(sz);
		cbc_encrypt(&cipher_.enc_ctx_, Cipher::enc_func_, 16, enc_iv_, sz,
				(uint8_t*)&result[0], (const unsigned char*)&*begin);
		return result;
	}
	template<class It> std::vector<uint8_t> decrypt(const It begin, const It end)
	{
		const int sz = end - begin;
		assert(sz % 16 == 0);
		std::vector<unsigned char> result(sz);
		cbc_decrypt(&cipher_.dec_ctx_, Cipher::dec_func_, 16, dec_iv_, sz,
				(uint8_t*)&result[0], (const unsigned char*)&*begin);
		return result;
	}
protected:
	Cipher cipher_;
	unsigned char enc_iv_[16], dec_iv_[16];
};

template<class Cipher> class GCM
{
public:
	void enc_key(const unsigned char *k);
	void dec_key(const unsigned char *k);
	void enc_iv(const unsigned char *iv);
	void dec_iv(const unsigned char *iv);
	template<class It> std::vector<uint8_t> encrypt(const It begin, const It end)
	{
		int sz = end - begin;
		assert(sz % 16 == 0);
		std::vector<uint8_t> result(sz + 16);//for digest at the end 16
		gcm_update(&enc_ctx_, &enc_key_, sz, &*begin);
		gcm_encrypt(&enc_ctx_, &enc_key_, &cipher_.enc_ctx_, Cipher::enc_func_,
				sz, &result[0], &*begin);
		gcm_digest(&enc_ctx_, &enc_key_, &cipher_.enc_ctx_, Cipher::enc_func_,
				16, &result[sz]);
		return result;
	}
	template<class It> std::vector<uint8_t> decrypt(const It begin, const It end)
	{
		int sz = end - begin;
		assert(sz % 16 == 0);
		std::vector<uint8_t> result(sz + 16);//for digest at the end 16
		gcm_update(&dec_ctx_, &dec_key_, sz, &*begin);
		gcm_encrypt(&dec_ctx_, &dec_key_, &cipher_.dec_ctx_, Cipher::dec_func_,
				sz, &result[0], &*begin);
		gcm_digest(&dec_ctx_, &dec_key_, &cipher_.dec_ctx_, Cipher::dec_func_,
				16, &result[sz]);
		return result;
	}
protected:
	gcm_key enc_key_, dec_key_;
	gcm_ctx enc_ctx_, dec_ctx_;
	Cipher cipher_;
};
