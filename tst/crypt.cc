#include<catch.hpp>
#include<fstream>
#include<iostream>
#include<iomanip>
#include<gmpxx.h>
#include"tls/crypt.h"
using namespace std;

unsigned char c[] = "hello this is a test case this is a test case this is a test";

TEST_CASE("AES TEST") {
	AES aes;
	unsigned char iv[16], key[32], text[32];
	mpz2bnd(mpz_class{"0x2b7e151628aed2a6abf7158809cf4f3c"}, key, key+16);
	mpz2bnd(mpz_class{"0x6bc1bee22e409f96e93d7e117393172a"}, text, text+16);
	for(int i=0; i<16; i++) iv[i] = i;

	aes.key(key);
	aes.iv(iv);
	auto v = aes.encrypt(text, text+16);//should be multiple of 16
	REQUIRE(bnd2mpz(v.begin(), v.end()) == mpz_class{"0x7649abac8119b246cee98e9b12e9197d"});
	v = aes.decrypt(v.begin(), v.end());
	for(int i=0; i<16; i++) REQUIRE(v[i] == text[i]);

	AES aes2{256};
	mpz2bnd(mpz_class{"0x603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4"}, key, key+32);
	aes2.key(key);
	aes2.iv(iv);
	v = aes2.encrypt(text, text+16);
	REQUIRE(bnd2mpz(v.begin(), v.end()) == mpz_class{"0xf58c4c04d6e5f1ba779eabfb5f7bfbd6"});
	v = aes2.decrypt(v.begin(), v.end());
	for(int i=0; i<16; i++) REQUIRE(v[i] == text[i]);
}
/***********
AES CBC 128-bit encryption mode
 Encryption key: 2b7e151628aed2a6abf7158809cf4f3c
Initialization vector 				Test vector Cipher 					text 
000102030405060708090A0B0C0D0E0F 	6bc1bee22e409f96e93d7e117393172a 	7649abac8119b246cee98e9b12e9197d
Encryption key: 603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4
256 : f58c4c04d6e5f1ba779eabfb5f7bfbd6
7649ABAC8119B246CEE98E9B12E9197D 	ae2d8a571e03ac9c9eb76fac45af8e51 	5086cb9b507219ee95db113a917678b2
5086CB9B507219EE95DB113A917678B2 	30c81c46a35ce411e5fbc1191a0a52ef 	73bed6b8e3c1743b7116e69e22229516
73BED6B8E3C1743B7116E69E22229516 	f69f2445df4f9b17ad2b417be66c3710 	3ff1caa1681fac09120eca307586e1a7

******************/

TEST_CASE("Diffie hellman test") {
	DiffieHellman dh;//send dh.ya, dh.p, dh.g and get yb
	auto K = dh.yb(random_prime(32));//Bob's pub key
}

TEST_CASE("sha1") {
	SHA1 sha;
	unsigned char c[] = "The quick brown fox jumps over the lazy dog";
	int i = 0;
	for(auto* p = c; *p; p++) i++;//find null position
	array<unsigned char, 20> ar = sha.hash(c, c+i);
	vector<unsigned char> v{ar.begin(), ar.end()};
	REQUIRE(base64_encode(v) == "L9ThxnotKPzthJ7hu3bnORuT6xI=");
	/************************
	SHA1("The quick brown fox jumps over the lazy dog")
	gives hexadecimal: 2fd4e1c67a2d28fced849ee1bb76e7391b93eb12
	gives Base64 binary to ASCII text encoding: L9ThxnotKPzthJ7hu3bnORuT6xI=
	**************/
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

TEST_CASE("hmac-sha1") {
	HMAC<SHA1> hmac;
	hmac.key(c, c);
	auto a = hmac.hash(c, c);
	REQUIRE(bnd2mpz(a.begin(), a.end()) == mpz_class{"0xfbdb1d1b18aa6c08324b7d64b71fb76370690e1d"});

}

TEST_CASE("hmac_sha256") {
	HMAC<SHA2> hmac;
	hmac.key(c, c);
	auto a  = hmac.hash(c, c);
	REQUIRE(bnd2mpz(a.begin(), a.end()) == mpz_class{"0xb613679a0814d9ec772f95d778c35fc5ff1697c493715653c6c712144292c5ad"});
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

TEST_CASE("hmac-sha256-2") {
	unsigned char key[] = "Jefe";
	unsigned char data[] = "what do ya want for nothing?";
	HMAC<SHA2> hmac;
	hmac.key(key, key+4);
	auto ar = hmac.hash(data, data+28);
	REQUIRE(bnd2mpz(ar.begin(), ar.end()) == mpz_class{"0x5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843"});
}
/***********************
Key =          4a656665                          ("Jefe")

   Data =         7768617420646f2079612077616e7420  ("what do ya want ")
                  666f72206e6f7468696e673f          ("for nothing?")

   PRF-HMAC-SHA-256 = 5bdcc146bf60754e6a042426089575c7
                      5a003f089d2739839dec58b964ec3843
**********************/

TEST_CASE("base64") {
	vector<unsigned char> v{c, c+20};
	string s = base64_encode(v);
	auto v2 = base64_decode(s);
	REQUIRE(v == v2);
}

TEST_CASE("prf") {
	unsigned char secret[] = {0x9b, 0xbe, 0x43, 0x6b, 0xa9, 0x40, 0xf0, 0x17,
							  0xb1, 0x76, 0x52, 0x84, 0x9a, 0x71, 0xdb, 0x35};
	unsigned char seed[] = {0xa0, 0xba, 0x9f, 0x93, 0x6c, 0xda, 0x31, 0x18,
							0x27, 0xa6, 0xf7, 0x96, 0xff, 0xd5, 0x19, 0x8c};
	PRF<SHA2> prf;
	prf.label("test label");
	prf.seed(seed, seed + 16);
	prf.secret(secret, secret + 16);
	auto v = prf.get_n_byte(100);
	REQUIRE(bnd2mpz(v.begin(), v.end()) == mpz_class{"0xe3f229ba727be17b8d122620557cd453c2aab21d07c3d495329b52d4e61edb5a6b301791e90d35c9c9a46b4e14baf9af0fa022f7077def17abfd3797c0564bab4fbc91666e9def9b97fce34f796789baa48082d122ee42c5a72e5a5110fff70187347b66"});
}
/***********************
# Generating 100 bytes of pseudo-randomness using TLS1.2PRF-SHA256
Secret (16 bytes):
0000    9b be 43 6b a9 40 f0 17    ..Ck....
0008    b1 76 52 84 9a 71 db 35    .vR..q.5

Seed (16 bytes):
0000    a0 ba 9f 93 6c da 31 18    ....l.1.
0008    27 a6 f7 96 ff d5 19 8c    ........

Label (10 bytes):
0000    74 65 73 74 20 6c 61 62    test lab
0008    65 6c                      el

Output (100 bytes):
0000    e3 f2 29 ba 72 7b e1 7b    ....r...
0008    8d 12 26 20 55 7c d4 53    ... U..S
0010    c2 aa b2 1d 07 c3 d4 95    ........
0018    32 9b 52 d4 e6 1e db 5a    2.R....Z
0020    6b 30 17 91 e9 0d 35 c9    k0....5.
0028    c9 a4 6b 4e 14 ba f9 af    ..kN....
0030    0f a0 22 f7 07 7d ef 17    ........
0038    ab fd 37 97 c0 56 4b ab    ..7..VK.
0040    4f bc 91 66 6e 9d ef 9b    O..fn...
0048    97 fc e3 4f 79 67 89 ba    ...Oyg..
0050    a4 80 82 d1 22 ee 42 c5    ......B.
0058    a7 2e 5a 51 10 ff f7 01    ..ZQ....
0060    87 34 7b 66                .4.f




[TLS-12-PRF(HMAC(SHA-256))]

Secret = 9bbe436ba940f017b17652849a71db35
Salt = a0ba9f936cda311827a6f796ffd5198c
Label = 74657374206c6162656c
Output = e3f229ba727be17b8d122620557cd453c2aab21d07c3d495329b52d4e61edb5a6b301791e90d35c9c9a46b4e14baf9af0fa022f7077def17abfd3797c0564bab4fbc91666e9def9b97fce34f796789baa48082d122ee42c5a72e5a5110fff70187347b66
***************************/
