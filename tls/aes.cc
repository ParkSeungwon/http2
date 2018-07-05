#include<cassert>
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

template<typename It> vector<unsigned char> AES::encrypt(const It begin, const It end) {
	int sz = end - begin;
	assert(sz % 16 == 0);
	vector<unsigned char> result(sz);
	wc_AesSetKey(&aes_, key_, key_size_, iv_, AES_ENCRYPTION);
	wc_AesCbcEncrypt(&aes_, result.data(), &*begin, sz);//&* for iterator
	return result;
}

template<typename It> vector<unsigned char> AES::decrypt(const It begin, const It end) {
	int sz = end - begin;
	assert(sz % 16 == 0);
	std::vector<unsigned char> result(sz);
	wc_AesSetKey(&aes_, key_, key_size_, iv_, AES_DECRYPTION);
	wc_AesCbcDecrypt(&aes_, result.data(), &*begin, sz);
	return result;
}

template vector<unsigned char> AES::encrypt(vector<unsigned char>::iterator a,
		vector<unsigned char>::iterator b);
template vector<unsigned char> AES::encrypt(unsigned char* a, unsigned char* b);
template vector<unsigned char> AES::decrypt(vector<unsigned char>::iterator a,
		vector<unsigned char>::iterator b);
template vector<unsigned char> AES::decrypt(unsigned char* a, unsigned char* b);

