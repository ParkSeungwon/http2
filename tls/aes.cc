#include"crypt.h"
#include"aes.h"
#include"options/log.h"
using namespace std;

template class AES<128>;
template class AES<256>;

template<int B> void AES<B>::set_enc_key(const mpz_class key)
{
	mpz2bnd(key, key_, key_+ B / 8);
	set_enc_key();
}

template<int B> void AES<B>::set_dec_key(const mpz_class key)
{
	mpz2bnd(key, key_, key_+ B / 8);
	set_dec_key();
}

template<int B> void AES<B>::set_enc_key(const unsigned char* key)
{
	memcpy(key_, key, B / 8);
	set_enc_key();
	LOGT << hexprint("setting key", vector<unsigned char>{key_, key_ + 16}) << endl;
}

template<int B> void AES<B>::set_dec_key(const unsigned char* key)
{
	memcpy(key_, key, B / 8);
	set_dec_key();
	LOGT << hexprint("setting key", vector<unsigned char>{key_, key_ + 16}) << endl;
}
template<int B> void AES<B>::set_enc_key()
{
	if constexpr(B == 128) aes128_set_encrypt_key(&aes_, key_);
	else aes256_set_encrypt_key(&aes_, key_);
}

template<int B> void AES<B>::set_dec_key()
{
	if constexpr(B == 128) aes128_set_decrypt_key(&aes_, key_);
	else aes256_set_decrypt_key(&aes_, key_);
}

template<int B> void AES<B>::iv(const mpz_class iv)
{
	mpz2bnd(iv, iv_, iv_+16);
}

template<int B> void AES<B>::iv(const unsigned char* iv)
{
	memcpy(iv_, iv, 16);
	LOGT << hexprint("setting iv", vector<unsigned char>{iv_, iv_ + 16}) << endl;
}

