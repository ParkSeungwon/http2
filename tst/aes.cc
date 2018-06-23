#include<catch.hpp>
#include<fstream>
#include<iostream>
#include<iomanip>
#include<gmpxx.h>
#include"crypt.h"
using namespace std;

unsigned char c[] = "hello this is a test case this is a test case this is a test";

TEST_CASE("AES TEST") {
	AES aes;
	mpz_class key = random_prime(32);
	mpz_class iv = random_prime(16);
	aes.key(key);
	aes.iv(iv);
	auto v = aes.encrypt(c, c+16);//should be multiple of 16
	auto v2 = aes.decrypt(v.begin(), v.end());
	for(int i=0; i<16; i++) REQUIRE(c[i] == v2[i]);
}

TEST_CASE("Diffie hellman test") {
	DiffieHellman dh;//send dh.ya, dh.p, dh.g and get yb
	auto K = dh.yb(random_prime(32));//Bob's pub key
}

TEST_CASE("sha1") {
	SHA1 sha;
	unsigned char c[] = "hello this is a test case";
	array<unsigned char, 20> ar = sha.hash(c, c+10);
	REQUIRE(ar == sha.hash(c, c+10));
	c[1] = '0';
	REQUIRE(ar != sha.hash(c, c+10));
}

TEST_CASE("rsa") {
	RSA rsa{32};
	RSA rsa2{
		mpz_class{"42342423423"},//e
		mpz_class{"423423423423"},//d
		mpz_class{"634654636"}//K
	};
	mpz_class z{"31312333424"};
	auto a = rsa.encode(z);
	auto b = rsa.decode(a);
	REQUIRE(b == z);
}

TEST_CASE("hmac") {
	HMAC hmac;
	hmac.key(c, c);
	auto a = hmac.hash(c, c);
	mpz_class z{"0xfbdb1d1b18aa6c08324b7d64b71fb76370690e1d"};
	REQUIRE(z == bnd2mpz(a.begin(), a.end()));
}
/********************
Here are some empty HMAC values:

HMAC_MD5("", "")    = 74e6f7298a9c2d168935f58c001bad88
HMAC_SHA1("", "")   = fbdb1d1b18aa6c08324b7d64b71fb76370690e1d
HMAC_SHA256("", "") = b613679a0814d9ec772f95d778c35fc5ff1697c493715653c6c712144292c5ad

Here are some non-empty HMAC values, assuming 8-bit ASCII or UTF-8 encoding:

HMAC_MD5("key", "The quick brown fox jumps over the lazy dog")    = 80070713463e7749b90c2dc24911e275
HMAC_SHA1("key", "The quick brown fox jumps over the lazy dog")   = de7c9b85b8b78aa6bc8a7a36f70a90701c9db4d9
HMAC_SHA256("key", "The quick brown fox jumps over the lazy dog") = f7bc83f430538424b13298e6aa6fb143ef4d59a14946175997479dbc2d1a3cd8
****************************/
