#pragma once
#include<cassert>
#include<cstring>
#include<nettle/aes.h>
#include<nettle/camellia.h>
#include<nettle/des.h>
#include<nettle/cbc.h>
#include<nettle/gcm.h>
#include<type_traits>
#include"chacha.h"

template<int B = 128> struct AES
{
	using cf = nettle_cipher_func;
	using kf = nettle_set_key_func;
	static constexpr cf *ncf[6] = {
		(cf*)aes128_encrypt, (cf*)aes192_encrypt, (cf*)aes256_encrypt,
		(cf*)aes128_decrypt, (cf*)aes192_decrypt, (cf*)aes256_decrypt
	};
	static constexpr kf *nskf[6] = {
		(kf*)aes128_set_encrypt_key, (kf*)aes192_set_encrypt_key,
		(kf*)aes256_set_encrypt_key, (kf*)aes128_set_decrypt_key, 
		(kf*)aes192_set_decrypt_key, (kf*)aes256_set_decrypt_key
	};
	static constexpr cf *enc_func_ = (cf*)ncf[B/64 - 2],
						*dec_func_ = (cf*)ncf[B/64 + 1];
	static constexpr kf *set_enc_key_ = (kf*)nskf[B/64 - 2],
						*set_dec_key_ = (kf*)nskf[B/64 + 1];
	typename std::conditional<B == 128, aes128_ctx, 
			 	typename std::conditional<B == 192, aes192_ctx, aes256_ctx>::type
			 >::type
		enc_ctx_, dec_ctx_;
};

template<int B = 128> struct Camellia
{
	using cf = nettle_cipher_func;
	using kf = nettle_set_key_func;
	static constexpr cf *ncf[3] = {
		(cf*)camellia128_crypt, (cf*)camellia192_crypt, (cf*)camellia256_crypt
	};
	static constexpr kf *nskf[6] = {
		(kf*)camellia128_set_encrypt_key, (kf*)camellia192_set_encrypt_key,
		(kf*)camellia256_set_encrypt_key, (kf*)camellia128_set_decrypt_key,
		(kf*)camellia192_set_decrypt_key, (kf*)camellia256_set_decrypt_key
	};
	static constexpr cf *enc_func_ = (cf*)ncf[B/128 - 1],
						*dec_func_ = (cf*)ncf[B/128 - 1];
	static constexpr kf *set_enc_key_ = (kf*)nskf[B/64 - 2],
						*set_dec_key_ = (kf*)nskf[B/64 + 1];
	typename std::conditional<B == 128, camellia128_ctx, camellia256_ctx>::type
		enc_ctx_, dec_ctx_;//camellia192_ctx is an alias for camellias256_ctx
};

template<int B = 0> struct DES3 
{//24 key size
	using cf = nettle_cipher_func;
	using kf = nettle_set_key_func;
	static constexpr kf *set_enc_key_ = (kf*)des3_set_key,
					 	*set_dec_key_ = (kf*)des3_set_key;
	static constexpr cf *dec_func_ = (cf*)des3_encrypt,
						*enc_func_ = (cf*)des3_encrypt;
	des3_ctx enc_ctx_, dec_ctx_;
};

struct CipherMode
{
	virtual void enc_iv(const unsigned char *) = 0;
	virtual void dec_iv(const unsigned char *) = 0;
	virtual void enc_key(const unsigned char *) = 0;
	virtual void dec_key(const unsigned char *) = 0;
	virtual std::vector<uint8_t> encrypt(const uint8_t *, int) = 0;
	virtual std::vector<uint8_t> decrypt(const uint8_t *, int) = 0;
};

template<class Cipher> class CBC : public CipherMode
{
public:
	void enc_iv(const unsigned char* iv) {
		memcpy(enc_iv_, iv, 16);
	}
	void dec_iv(const unsigned char* iv) {
		memcpy(dec_iv_, iv, 16);
	}
	void enc_key(const unsigned char *key) {
		Cipher::set_enc_key_(&cipher_.enc_ctx_, key);
	}
	void dec_key(const unsigned char *key) {
		Cipher::set_dec_key_(&cipher_.dec_ctx_, key);
	}
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
	std::vector<uint8_t> encrypt(const uint8_t *begin, int sz) {
		encrypt(begin, begin + sz);
	}
	std::vector<uint8_t> decrypt(const uint8_t *begin, int sz) {
		decrypt(begin, begin + sz);
	}
protected:
	Cipher cipher_;
	unsigned char enc_iv_[16], dec_iv_[16];
};

template<class Cipher> class GCM : public CipherMode
{
public:
	void enc_key(const unsigned char *k) {
		Cipher::set_enc_key_(&cipher_.enc_ctx_, k);
		gcm_set_key(&enc_key_, &cipher_.enc_ctx_, Cipher::enc_func_);
	}
	void dec_key(const unsigned char *k) {
		Cipher::set_enc_key_(&cipher_.dec_ctx_, k);//use enc key!!
		gcm_set_key(&dec_key_, &cipher_.dec_ctx_, Cipher::enc_func_);
	}
	void enc_iv(const unsigned char *iv) {
		gcm_set_iv(&enc_ctx_, &enc_key_, GCM_IV_SIZE, iv);//12
	}
	void dec_iv(const unsigned char *iv) {
		gcm_set_iv(&dec_ctx_, &dec_key_, GCM_IV_SIZE, iv);//12
	}
	template<class It> std::vector<uint8_t> encrypt(const It begin, const It end)
	{
		int sz = end - begin;
		assert(sz % GCM_BLOCK_SIZE == 0);//16
		std::vector<uint8_t> result(sz + GCM_DIGEST_SIZE);//16
		gcm_update(&enc_ctx_, &enc_key_, 8, enc_sequence_num_);
		increase_seq_num(enc_sequence_num_);
		gcm_encrypt(&enc_ctx_, &enc_key_, &cipher_.enc_ctx_, Cipher::enc_func_,
				sz, &result[0], &*begin);
		gcm_digest(&enc_ctx_, &enc_key_, &cipher_.enc_ctx_, Cipher::enc_func_,
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
		gcm_decrypt(&dec_ctx_, &dec_key_, &cipher_.dec_ctx_, Cipher::enc_func_,
				sz, &result[0], &*begin);
		gcm_digest(&dec_ctx_, &dec_key_, &cipher_.dec_ctx_, Cipher::enc_func_,
				GCM_DIGEST_SIZE, &result[sz]);
		return result;
	}
	std::vector<uint8_t> encrypt(const uint8_t *begin, int sz) {
		encrypt(begin, begin + sz);
	}
	std::vector<uint8_t> decrypt(const uint8_t *begin, int sz) {
		decrypt(begin, begin + sz);
	}
protected:
	gcm_key enc_key_, dec_key_;
	gcm_ctx enc_ctx_, dec_ctx_;
	Cipher cipher_;
	uint8_t enc_sequence_num_[8] = {0,}, dec_sequence_num_[8] = {0,};
private:
	void increase_seq_num(uint8_t *p) {
		for(int i=7; !++p[i] && i; i--); 
	}
};

template<class C = DES3<0>> class CHACHA : public CipherMode, public ChaCha
{//template B is just for compatibility with other block ciphers
public:
	void enc_key(const uint8_t *k) {
		ChaCha::enc_key(k);
	}
	void dec_key(const uint8_t *k) {
		ChaCha::dec_key(k);
	}
	void enc_iv(const uint8_t *iv) {
		enc_nonce(iv);
	}
	void dec_iv(const uint8_t *iv) {
		dec_nonce(iv);
	}
	std::vector<uint8_t> encrypt(const uint8_t *begin, int sz) {
		return ChaCha::encrypt(begin, begin + sz);
	}
	std::vector<uint8_t> decrypt(const uint8_t *begin, int sz) {
		return ChaCha::decrypt(begin, begin + sz);
	}
};
