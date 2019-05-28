#pragma once
#include<cassert>
#include<nettle/aes.h>
#include<nettle/camellia.h>
#include<nettle/des.h>
#include<nettle/cbc.h>
#include<nettle/gcm.h>
#include<type_traits>

struct BlockCipher
{
	nettle_cipher_func *enc_func_, *dec_func_;
	nettle_set_key_func *set_enc_key_, *set_dec_key_;
};

template<int B = 128> struct AES : BlockCipher
{
	AES();
	typename std::conditional<B == 128, aes128_ctx, aes256_ctx>::type
		enc_ctx_, dec_ctx_;
};

template<int B = 128> struct Camellia : BlockCipher
{
	Camellia();
	typename std::conditional<B == 128, camellia128_ctx, camellia256_ctx>::type
		enc_ctx_, dec_ctx_;
};

struct DES3 : BlockCipher
{//24 key size
	DES3();
	des3_ctx enc_ctx_, dec_ctx_;
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
		cbc_encrypt(&cipher_.enc_ctx_, cipher_.enc_func_, 16, enc_iv_, sz,
				(uint8_t*)&result[0], (const unsigned char*)&*begin);
		return result;
	}
	template<class It> std::vector<uint8_t> decrypt(const It begin, const It end)
	{
		const int sz = end - begin;
		assert(sz % 16 == 0);
		std::vector<unsigned char> result(sz);
		cbc_decrypt(&cipher_.dec_ctx_, cipher_.dec_func_, 16, dec_iv_, sz,
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
		assert(sz % GCM_BLOCK_SIZE == 0);//16
		std::vector<uint8_t> result(sz + GCM_DIGEST_SIZE);//16
		gcm_update(&enc_ctx_, &enc_key_, 8, enc_sequence_num_);
		increase_seq_num(enc_sequence_num_);
		gcm_encrypt(&enc_ctx_, &enc_key_, &cipher_.enc_ctx_, cipher_.enc_func_,
				sz, &result[0], &*begin);
		gcm_digest(&enc_ctx_, &enc_key_, &cipher_.enc_ctx_, cipher_.enc_func_,
				GCM_DIGEST_SIZE, &result[sz]);//16
		return result;
	}
	template<class It> std::vector<uint8_t> decrypt(const It begin, const It end)
	{
		int sz = end - begin;
		assert(sz % GCM_BLOCK_SIZE == 0);//16
		std::vector<uint8_t> result(sz + GCM_DIGEST_SIZE);//16
		gcm_update(&dec_ctx_, &dec_key_, 8, dec_sequence_num_);
		increase_seq_num(dec_sequence_num_);
		gcm_decrypt(&dec_ctx_, &dec_key_, &cipher_.dec_ctx_, cipher_.enc_func_,
				sz, &result[0], &*begin);
		gcm_digest(&dec_ctx_, &dec_key_, &cipher_.dec_ctx_, cipher_.enc_func_,
				GCM_DIGEST_SIZE, &result[sz]);
		return result;
	}
protected:
	gcm_key enc_key_, dec_key_;
	gcm_ctx enc_ctx_, dec_ctx_;
	Cipher cipher_;
	uint8_t enc_sequence_num_[8] = {0,}, dec_sequence_num_[8] = {0,};
private:
	void increase_seq_num(uint8_t *p);
};
