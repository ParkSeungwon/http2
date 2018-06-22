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
//	hmac.key(c, c+32); //error
}
