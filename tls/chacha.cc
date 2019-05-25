#include"chacha.h"
using namespace std;

void ChaCha::enc_key(const uint8_t *k)
{
	chacha_poly1305_set_key(&enc_ctx_, k);
}
void ChaCha::dec_key(const uint8_t *k)
{
	chacha_poly1305_set_key(&dec_ctx_, k);
}
void ChaCha::enc_nonce(const uint8_t *n)
{
	chacha_poly1305_set_nonce(&enc_ctx_, n);
}
void ChaCha::dec_nonce(const uint8_t *n)
{
	chacha_poly1305_set_nonce(&dec_ctx_, n);
}
void ChaCha::increase_seq_num(unsigned char *p)
{
	for(int i=7; !++p[i] && i; i--); 
}
