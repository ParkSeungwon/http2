#include"crypt.h"
#include"options/log.h"
using namespace std;

void AES::key(const mpz_class key)
{
	mpz2bnd(key, key_, key_+ key_size_);
}

void AES::key(const unsigned char* key)
{
	LOGT << hexprint("setting key", vector<unsigned char>{key, key + 16}) << endl;
	memcpy(key_, key, key_size_);
}

void AES::iv(const mpz_class iv)
{
	mpz2bnd(iv, iv_, iv_+16);
}

void AES::iv(const unsigned char* iv)
{
	LOGT << hexprint("setting iv", vector<unsigned char>{iv, iv + 16}) << endl;
	memcpy(iv_, iv, 16);
}

