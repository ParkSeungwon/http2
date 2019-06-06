#include<algorithm>
#include<catch.hpp>
#include<nettle/aes.h>
#include<nettle/gcm.h>
#include"tls/crypt.h"
#include"tls/block_cipher.h"
#include"tls/chacha.h"
#include"options/log.h"
#include"tls/hash.h"
using namespace std;

TEST_CASE("ecdhe") {
	ECDHE A, B;
	A.set_Q(B.Q);
	B.set_Q(A.Q);
	REQUIRE(A.K == B.K);
}
unsigned char key[] = "123456789012345678901234567890123456";
unsigned char iv[] = "1234567890123456";
unsigned char src[64] = "12345678901234567890123456789012";
unsigned char encoded[32], digest[16], datum[8] = {0,}, decoded[32];
TEST_CASE("gcm nettle test") {
	struct gcm_key gk, gk2;
	struct gcm_ctx gc, gc2;
	struct aes128_ctx ac, ac2;
	aes128_set_encrypt_key(&ac, key);
	gcm_set_key(&gk, &ac, (nettle_cipher_func*)aes128_encrypt);
	gcm_set_iv(&gc, &gk, 12, iv);
	gcm_update(&gc, &gk, 8, datum);
	gcm_encrypt(&gc, &gk, &ac, (nettle_cipher_func*)aes128_encrypt, 32, encoded, src);
	gcm_digest(&gc, &gk, &ac, (nettle_cipher_func*)aes128_encrypt, 16, digest);

	aes128_set_encrypt_key(&ac2, key);
	gcm_set_key(&gk2, &ac2, (nettle_cipher_func*)aes128_encrypt);
	gcm_set_iv(&gc2, &gk2, 12, iv);
	gcm_update(&gc2, &gk2, 8, datum);
	gcm_decrypt(&gc2, &gk2, &ac2, (nettle_cipher_func*)aes128_encrypt, 32, decoded, encoded);
	gcm_digest(&gc2, &gk2, &ac2, (nettle_cipher_func*)aes128_encrypt, 16, digest);
	REQUIRE(equal(src, src+32, decoded));
}

TEST_CASE("aes cbc new") {
	GCM<AES<192>> aes;
	aes.enc_key(key);
	aes.dec_key(key);
	aes.enc_iv(iv);
	aes.dec_iv(iv);
	auto v = aes.encrypt(src, src + 32);
	auto v2 = aes.decrypt(v.begin(), v.end() - 16);
	REQUIRE(equal(src, src+32, v2.begin()));
	REQUIRE(std::equal(v.end() - 16, v.end(), v2.end()-16));
}

TEST_CASE("CBC AES") {
	CBC<AES<256>> ca;
	ca.enc_key(key);
	ca.dec_key(key);
	ca.enc_iv(iv);
	ca.dec_iv(iv);
	auto v = ca.encrypt(src, src + 32);
	auto v2 = ca.decrypt(v.begin(), v.end());
	REQUIRE(equal(src, src + 32, v2.begin()));
}
TEST_CASE("camellia") {
	GCM<Camellia<256>> ca;
	ca.enc_key(key);
	ca.dec_key(key);
	ca.enc_iv(iv);
	ca.dec_iv(iv);
	auto v = ca.encrypt(src, src + 32);
	auto v2 = ca.decrypt(v.begin(), v.end()-16);
	REQUIRE(equal(src, src + 32, v2.begin()));
	REQUIRE(std::equal(v.end() - 16, v.end(), v2.end()-16));
}
TEST_CASE("camellia192") {
	GCM<Camellia<192>> ca;
	ca.enc_key(key);
	ca.dec_key(key);
	ca.enc_iv(iv);
	ca.dec_iv(iv);
	auto v = ca.encrypt(src, src + 32);
	auto v2 = ca.decrypt(v.begin(), v.end()-16);
	REQUIRE(equal(src, src + 32, v2.begin()));
	REQUIRE(std::equal(v.end() - 16, v.end(), v2.end()-16));
}

TEST_CASE("des3 gcm") {
	GCM<DES3<>> ca;
	ca.enc_key(key);
	ca.dec_key(key);
	ca.enc_iv(iv);
	ca.dec_iv(iv);
	auto v = ca.encrypt(src, src + 32);
	auto v2 = ca.decrypt(v.begin(), v.end()-16);
	REQUIRE(equal(src, src + 32, v2.begin()));
	REQUIRE(std::equal(v.end() - 16, v.end(), v2.end()-16));
}

TEST_CASE("chacha") {
	ChaCha cha;
	cha.enc_key(key);
	cha.dec_key(key);
	cha.enc_nonce(iv);
	cha.dec_nonce(iv);
	auto v = cha.encrypt(src, src+64);
	auto v2 = cha.decrypt(v.begin(), v.end()-16);
	REQUIRE(equal(src, src+64, v2.begin()));
	REQUIRE(equal(v.end()-16, v.end(), v2.end()-16));
}

TEST_CASE("HKDF") {
	mpz_class salt{"0x000102030405060708090a0b0c"};// (13 octets);  v (32 octets)
	mpz_class PRK{"0x077709362c2e32df0ddc3f0dc47bba6390b6c73bb50f9c3122ec844ad7c2b3e5"};
	mpz_class info{"0xf0f1f2f3f4f5f6f7f8f9"};// (10 octets)
	mpz_class OKM{"0x3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865"};// (42 octets)
	uint8_t s[13], ikm[22], prk[32], inf[10], okm[42];
	for(int i=0; i<22; i++) ikm[i] = 0x0b;
	mpz2bnd(salt, s, s+13);
	mpz2bnd(PRK, prk, prk + 32);
	mpz2bnd(info, inf, inf+10);
	mpz2bnd(OKM, okm, okm+42);
	HKDF<SHA256> h;
	h.key(s, s+13);
	auto a = h.hash(ikm, ikm + 22);
	REQUIRE(equal(a.begin(), a.end(), prk));
	h.key(prk, prk + 32);
	auto b = h.expand(string{inf, inf+10}, 42);
	REQUIRE(equal(b.begin(), b.end(), okm));
}
/*
Basic test case with SHA-256
Hash = SHA-256
IKM = 0x0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b (22 octets)
L = 42
*/
