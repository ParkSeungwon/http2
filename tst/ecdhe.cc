#include<catch.hpp>
#include<nettle/aes.h>
#include<nettle/gcm.h>
#include"tls/crypt.h"
#include"options/log.h"
using namespace std;

TEST_CASE("ecdhe") {
	ECDH A, B;
	A.set_Q(B.Q);
	B.set_Q(A.Q);
	REQUIRE(A.K == B.K);
}
TEST_CASE("gcm nettle test") {
	unsigned char key[] = "1234567890123456";
	unsigned char iv[] = "123456789012";
	unsigned char src[33] = "12345678901234567890123456789012";
	unsigned char dest[32], digest[16];
	struct gcm_key gk, gk2;
	struct gcm_ctx gc, gc2;
	struct aes128_ctx ac, ac2;
	aes128_set_encrypt_key(&ac, key);
	gcm_set_key(&gk, &ac, (nettle_cipher_func*)aes128_encrypt);
	gcm_set_iv(&gc, &gk, 12, iv);
	gcm_update(&gc, &gk, 16, key);
	gcm_encrypt(&gc, &gk, &ac, (nettle_cipher_func*)aes128_encrypt, 32, dest, src);
	gcm_digest(&gc, &gk, &ac, (nettle_cipher_func*)aes128_encrypt, 16, digest);
	stringstream ss; ss << "\nGCM test dest: ";
	for(unsigned char c : dest) ss << hex << +c;
	LOGT << ss.str() << endl;

	aes128_set_decrypt_key(&ac2, key);
	gcm_set_key(&gk, &ac2, (nettle_cipher_func*)aes128_decrypt);
	gcm_set_iv(&gc2, &gk2, 12, iv);
	gcm_update(&gc2, &gk2, 16, key);
	gcm_decrypt(&gc2, &gk2, &ac2, (nettle_cipher_func*)aes128_decrypt, 32, src, dest);
	gcm_digest(&gc2, &gk2, &ac2, (nettle_cipher_func*)aes128_decrypt, 16, digest);
	stringstream ss2; ss2 << "\nGCM test src : ";
	for(unsigned char c : src) ss2 << hex << +c;
	LOGT << ss2.str() << endl;
}
