#include<algorithm>
#include<catch.hpp>
#include<nettle/aes.h>
#include<nettle/gcm.h>
#include<nettle/curve25519.h>
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

TEST_CASE("x25519 nettle mul_g mul key exchange") {
 	mpz_class a{"0x77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a"},
			  b{"0x5dab087e624a8a4b79e17f8b83800ee66f3bb1292618b6fd1c2f8b27ff88e0eb"},
			  pa{"0x8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a"},
			  pb{"0xde9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f"},
			  k{"0x4a5d9d5ba4ce2de1728e3bf480350f25e07e21c947d19e3376f09b3c1e161742"};
	uint8_t A[32], B[32], PA[32], PB[32], KA[32], KB[32];
	mpz2bnd(a, A, A+32); 				mpz2bnd(b, B, B+32);
	curve25519_mul_g(PA, A); 			curve25519_mul_g(PB, B);
	REQUIRE(pa == bnd2mpz(PA, PA+32)); 	REQUIRE(pb == bnd2mpz(PB, PB+32));
	curve25519_mul(KA, A, PB); 			curve25519_mul(KB, B, PA);
	REQUIRE(k == bnd2mpz(KA, KA+32)); 	REQUIRE(k == bnd2mpz(KB, KB+32));
//Alice's private key, a:
//     77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a
//Alice's public key, X25519(a, 9):
//     8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a
//Bob's private key, b:
//     5dab087e624a8a4b79e17f8b83800ee66f3bb1292618b6fd1c2f8b27ff88e0eb
//Bob's public key, X25519(b, 9):
//     de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f
//Their shared secret, K:
//     4a5d9d5ba4ce2de1728e3bf480350f25e07e21c947d19e3376f09b3c1e161742
}

TEST_CASE("nettle curve 25519 multiply") {
	mpz_class k, p, kp;
	SECTION("first test") {
	k = mpz_class{"0xa546e36bf0527c9d3b16154b82465edd62144c0ac1fc5a18506a2244ba449ac4"};
	p = mpz_class{"0xe6db6867583030db3594c1a424b15f7c726624ec26b3353b10a903a6d0ab1c4c"};
	kp =mpz_class{"0xc3da55379de9c6908e94ea4df28d084f32eccf03491c71f754b4075577a28552"};
	}
	SECTION("second test") {
	k = mpz_class{"0x4b66e9d4d1b4673c5ad22691957d6af5c11b6421e0ea01d42ca4169e7918ba0d"};
	p = mpz_class{"0xe5210f12786811d3f4b7959d0538ae2c31dbe7106fc03c3efc4cd549c715a493"};
	kp =mpz_class{"0x95cbde9476e8907d7aade45cb4b873f88b595a68799fa152e6f8f7647aac7957"};
	}
	uint8_t K[32], P[32], KP[32], R[32];
	mpz2bnd(k, K, K+32);
	mpz2bnd(p, P, P+32);
	mpz2bnd(kp, KP, KP+32);
	curve25519_mul(R, K, P);
	REQUIRE(equal(KP, KP+32, R));
	kp = k * p;
	REQUIRE(kp = bnd2mpz(KP, KP+32));
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
	ca.enc_key(key);						ca.dec_key(key);
	ca.enc_iv(iv);							ca.dec_iv(iv);
	auto v = ca.encrypt(src, src + 32); 	auto v2 = ca.decrypt(v.begin(), v.end());
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
