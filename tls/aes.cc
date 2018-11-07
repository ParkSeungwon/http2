#include"crypt.h"
#include"options/log.h"
using namespace std;

AES::AES()
	: enc_{Botan::get_cipher_mode("AES-128/CBC/PKCS7", Botan::ENCRYPTION)}
	, dec_{Botan::get_cipher_mode("AES-128/CBC/PKCS7", Botan::DECRYPTION)}
	, key_(16, 0), iv_(16, 0)
{ }

void AES::key(const mpz_class key)
{
	mpz2bnd(key, key_.data(), key_.data() + 16);
	enc_->clear();
	dec_->clear();
	enc_->set_key(key_);
	dec_->set_key(key_);
}

void AES::key(const unsigned char* key)
{
	LOGT << hexprint("setting key", vector<unsigned char>{key, key + 16}) << endl;
	memcpy(key_.data(), key, 16);
	enc_->clear();
	dec_->clear();
	enc_->set_key(key_);
	dec_->set_key(key_);
}

void AES::iv(const mpz_class iv)
{
	mpz2bnd(iv, iv_.data(), iv_.data() + 16);
	enc_->start(iv_);
	dec_->start(iv_);
}

void AES::iv(const unsigned char* iv)
{
	LOGT << hexprint("setting iv", vector<unsigned char>{iv, iv + 16}) << endl;
	memcpy(iv_.data(), iv, 16);
	enc_->start(iv_);
	dec_->start(iv_);
}

