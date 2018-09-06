#include"crypt.h"
using namespace std;

AES::AES(unsigned short bit) : key_size_{bit / 8} 
{
	assert(key_size_ == 16 || key_size_ == 24 || key_size_ == 32);
}

void AES::key(const mpz_class key)
{
	mpz2bnd(key, key_, key_+ key_size_);
}

void AES::key(const unsigned char* key)
{
	memcpy(key_, key, key_size_);
}

void AES::iv(const mpz_class iv)
{
	mpz2bnd(iv, iv_, iv_+16);
}

void AES::iv(const unsigned char* iv)
{
	memcpy(iv_, iv, 16);
}

