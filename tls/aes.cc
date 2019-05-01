#include"crypt.h"
#include"aes.h"
using namespace std;

template class AES<Encryption, 128>;
template class AES<Encryption, 256>;
template class AES<Decryption, 128>;
template class AES<Decryption, 256>;

template<bool Enc, int B> void AES<Enc, B>::key(const mpz_class keyy)
{
	mpz2bnd(keyy, key_, key_+ B / 8);
	key();
}

template<bool Enc, int B> void AES<Enc, B>::key(const unsigned char* keyy)
{
	memcpy(key_, keyy, B / 8);
	key();
}

template<bool Enc, int B> void AES<Enc, B>::key()
{
	if constexpr(Enc) {
		if constexpr(B == 128) aes128_set_encrypt_key(&aes_, key_);
		else aes256_set_encrypt_key(&aes_, key_);
	} else {
		if constexpr(B == 128) aes128_set_decrypt_key(&aes_, key_);
		else aes256_set_decrypt_key(&aes_, key_);
	}
}

template<bool Enc, int B> void AES<Enc, B>::iv(const mpz_class iv)
{
	mpz2bnd(iv, iv_, iv_+16);
}

template<bool Enc, int B> void AES<Enc, B>::iv(const unsigned char* iv)
{
	memcpy(iv_, iv, 16);
}

