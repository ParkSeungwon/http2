#include<catch.hpp>
#include<nettle/aes.h>
#include<nettle/gcm.h>
#include"tls/crypt.h"
#include"tls/block_cipher.h"
#include"options/log.h"
using namespace std;

TEST_CASE("ecdhe") {
	ECDH A, B;
	A.set_Q(B.Q);
	B.set_Q(A.Q);
	REQUIRE(A.K == B.K);
}
unsigned char key[] = "1234567890123456";
unsigned char iv[] = "123456789012";
unsigned char src[33] = "12345678901234567890123456789012";
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
	stringstream ss; ss << "\nGCM test digest: ";
	for(unsigned char c : digest) ss << hex << +c;
	INFO(ss.str());
	cout << ss.str() << endl;

	aes128_set_decrypt_key(&ac2, key);
	gcm_set_key(&gk2, &ac2, (nettle_cipher_func*)aes128_decrypt);
	gcm_set_iv(&gc2, &gk2, 12, iv);
	gcm_update(&gc2, &gk2, 8, datum);
	gcm_decrypt(&gc2, &gk2, &ac2, (nettle_cipher_func*)aes128_decrypt, 32, decoded, encoded);
	gcm_digest(&gc2, &gk2, &ac2, (nettle_cipher_func*)aes128_decrypt, 16, digest);
	stringstream ss2; ss2 << "\nGCM test digest : ";
	for(unsigned char c : digest) ss2 << hex << +c;
	LOGT << ss2.str() << endl;
	for(uint8_t c : encoded) cerr << hex << +c;
	cout << endl;
	for(uint8_t c : decoded) cerr << hex << +c;
	cout << endl;

}

	template<int I> struct A {
		static constexpr int i = I == 0 ? 3 : 2;
	};
	template<class A> struct B {
		B() {
			LOGT << "A::i " << A::i << endl;
		}
	};
TEST_CASE("constexpr init") {

	B<A<0>> b;
}

TEST_CASE("aes cbc new") {
	GCM<AES<128>> aes;
	aes.enc_key(key);
	aes.dec_key(key);
	aes.enc_iv(iv);
	aes.dec_iv(iv);
	auto v = aes.encrypt(src, src + 32);
	auto v2 = aes.decrypt(v.begin(), v.end() - 16);
	cerr << "GCM src : ";
	for(int i=0; i<32; i++) cerr << hex << +src[i];
	cout << endl << "GCM decode : ";
	for(int i=0; i<32; i++) cerr << hex << +v2[i];
	//for(int i=0; i<32; i++) REQUIRE(src[i] == v2[i]);
}

TEST_CASE("camellia") {
	CBC<Camellia<256>> ca;
	ca.enc_key(key);
	ca.dec_key(key);
	ca.enc_iv(iv);
	ca.dec_iv(iv);
	auto v = ca.encrypt(src, src + 32);
	auto v2 = ca.decrypt(v.begin(), v.end());
	for(int i=0; i<32; i++) REQUIRE(src[i] == v2[i]);
}
