#include<iostream>
#include<nettle/gcm.h>
#include<nettle/aes.h>
using namespace std;

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
	gcm_set_key(&gk, &ac, (nettle_cipher_func*)aes128_encrypt);
	gcm_set_iv(&gc, &gk, 12, iv);
	gcm_update(&gc, &gk, 8, datum);
	gcm_encrypt(&gc, &gk, &ac, (nettle_cipher_func*)aes128_encrypt, 32, encoded, src);
	gcm_digest(&gc, &gk, &ac, (nettle_cipher_func*)aes128_encrypt, 16, digest);

	aes128_set_decrypt_key(&ac2, key);
	gcm_set_key(&gk2, &ac2, (nettle_cipher_func*)aes128_decrypt);
	gcm_set_iv(&gc2, &gk2, 12, iv);
	gcm_update(&gc2, &gk2, 8, datum);
	gcm_decrypt(&gc2, &gk2, &ac2, (nettle_cipher_func*)aes128_decrypt, 32, decoded, encoded);
	gcm_digest(&gc2, &gk2, &ac2, (nettle_cipher_func*)aes128_decrypt, 16, digest);
	
	for(unsigned char c : src) cerr << hex << +c;
	cout << endl;
	for(uint8_t c : encoded) cerr << hex << +c;
	cout << endl;
	for(uint8_t c : decoded) cerr << hex << +c;
	cout << endl;
}
