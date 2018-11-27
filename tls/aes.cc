#include"crypt.h"
#include"options/log.h"
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
	LOGT << hexprint("setting key", vector<unsigned char>{key, key + 16}) << endl;
	memcpy(key_, key, key_size_);
	LOGT << hexprint("setting key", vector<unsigned char>{key_, key_ + 16}) << endl;
}

void AES::iv(const mpz_class iv)
{
	mpz2bnd(iv, iv_, iv_+16);
}

void AES::iv(const unsigned char* iv)
{
	LOGT << hexprint("setting iv", vector<unsigned char>{iv, iv + 16}) << endl;
	memcpy(iv_, iv, 16);
	LOGT << hexprint("setting iv", vector<unsigned char>{iv_, iv_ + 16}) << endl;
}

void AES::save_key()
{
	memcpy(key_save_, key_, 32);
}

void AES::restore_key()
{
	memcpy(key_, key_save_, 32);
}
