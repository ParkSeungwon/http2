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

	struct gctx GCM_CTX(aes128_ctx) ctx;
	GCM_SET_KEY(&ctx, aes128_set_encrypt_key, aes128_encrypt, key);
	GCM_SET_IV(&ctx, 12, iv);
	GCM_UPDATE(&ctx, 16, datum);
	GCM_ENCRYPT(&ctx, aes128_encrypt, 32, encoded, src);
	GCM_DIGEST(&ctx, aes128_encrypt, 16, digest);

	GCM_SET_KEY(&ctx, aes128_set_decrypt_key, aes128_decrypt, key);
	GCM_SET_IV(&ctx, 12, iv);
	GCM_UPDATE(&ctx, 16, datum);
	GCM_ENCRYPT(&ctx, aes128_decrypt, 32, decoded, encoded);
	GCM_DIGEST(&ctx, aes128_decrypt, 16, digest);

	for(unsigned char c : src) cerr << hex << +c;
	cout << endl;
	for(uint8_t c : encoded) cerr << hex << +c;
	cout << endl;
	for(uint8_t c : decoded) cerr << hex << +c;
	cout << endl;
}

