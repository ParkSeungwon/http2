#include<iostream>
#include<nettle/gcm.h>
#include<nettle/aes.h>
#include<nettle/chacha-poly1305.h>
using namespace std;
using cf = nettle_cipher_func;


int main()
{
	unsigned char key[] = "1234567890123456";
	unsigned char iv[] = "123456789012";
	unsigned char src[33] = "12345678901234567890123456789012";
	unsigned char encoded[32], digest[16], datum[8] = {0,}, decoded[32];
	struct gcm_key gk, gk2;
	struct gcm_ctx gc, gc2;
	struct aes128_ctx ac, ac2;

	aes128_set_encrypt_key(&ac, key);
	gcm_set_key(&gk, &ac, (cf*)aes128_encrypt);
	gcm_set_iv(&gc, &gk, 12, iv);
	gcm_update(&gc, &gk, 8, datum);
	gcm_encrypt(&gc, &gk, &ac, (cf*)aes128_encrypt, 32, encoded, src);
	gcm_digest(&gc, &gk, &ac, (cf*)aes128_encrypt, 16, digest);

	aes128_set_encrypt_key(&ac, key);
	gcm_set_key(&gk, &ac, (cf*)aes128_encrypt);
	gcm_set_iv(&gc, &gk, 12, iv);
	gcm_update(&gc, &gk, 8, datum);
	gcm_decrypt(&gc, &gk, &ac, (cf*)aes128_encrypt, 32, decoded, encoded);
	gcm_digest(&gc, &gk, &ac, (cf*)aes128_encrypt, 16, digest);
//	aes128_set_encrypt_key(&ac, key);
//	gcm_set_key(&gk, &ac, (cf*)aes128_encrypt);
//	gcm_set_iv(&gc, &gk, 12, iv);
//	gcm_update(&gc, &gk, 8, datum);
//	gcm_decrypt(&gc, &gk, &ac, (cf*)aes128_encrypt, 32, decoded, encoded);
//	gcm_digest(&gc, &gk, &ac, (cf*)aes128_encrypt, 16, digest);
	
	for(unsigned char c : src) cerr << hex << +c;
	cout << endl;
	for(uint8_t c : encoded) cerr << hex << +c;
	cout << endl;
	for(uint8_t c : decoded) cerr << hex << +c;
	cout << endl;

	struct G { 
		struct gcm_key key; struct gcm_ctx gcm; struct aes128_ctx cipher;
	} a, b;

	gcm_aes128_ctx *ctx = (gcm_aes128_ctx*)&a, *ctx2 = (gcm_aes128_ctx*)&b;
	gcm_aes128_set_key(ctx, key);
	gcm_aes128_set_iv(ctx, 12, iv);
	gcm_aes128_update(ctx, 8, datum);
	gcm_aes128_encrypt(ctx, 32, decoded, encoded);
	gcm_aes128_digest(ctx, 16, digest);
	cout << "digest ";
	for(unsigned char c : digest) cerr << hex << +c;
	cout << endl;

//	gcm_aes128_set_key(ctx2, key);
	aes128_set_encrypt_key(&ctx2->cipher, key);
	gcm_set_key(&ctx2->key, &ctx2->cipher, (cf*)aes128_encrypt);
	gcm_aes128_set_iv(ctx2, 12, iv);
	gcm_aes128_update(ctx2, 8, datum);
	gcm_aes128_decrypt(ctx2, 32, decoded, encoded);
	gcm_aes128_digest(ctx2, 16, digest);
	for(unsigned char c : digest) cerr << hex << +c;
	cout << endl;

	for(unsigned char c : src) cerr << hex << +c;
	cout << endl;
	for(uint8_t c : encoded) cerr << hex << +c;
	cout << endl;
	for(uint8_t c : decoded) cerr << hex << +c;
	cout << endl;

	chacha_poly1305_ctx cctx;
	chacha_poly1305_set_key(&cctx, key);
	chacha_poly1305_set_nonce(&cctx, iv);
	chacha_poly1305_update(&cctx, 8, datum);
	chacha_poly1305_encrypt(&cctx, 32, encoded, src);
	chacha_poly1305_digest(&cctx, 16, digest);

	for(unsigned char c : src) cerr << hex << +c;
	cout << endl;
	for(uint8_t c : encoded) cerr << hex << +c;
	cout << endl;
	for(uint8_t c : decoded) cerr << hex << +c;
	cout << endl;

	chacha_poly1305_ctx cctx2;
	chacha_poly1305_set_key(&cctx2, key);
	chacha_poly1305_set_nonce(&cctx2, iv);
	chacha_poly1305_update(&cctx2, 8, datum);
	chacha_poly1305_decrypt(&cctx2, 32, decoded, encoded);
	chacha_poly1305_digest(&cctx2, 16, digest);

	for(unsigned char c : src) cerr << hex << +c;
	cout << endl;
	for(uint8_t c : encoded) cerr << hex << +c;
	cout << endl;
	for(uint8_t c : decoded) cerr << hex << +c;
	cout << endl;
}
