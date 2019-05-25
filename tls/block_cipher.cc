#include"crypt.h"
#include"block_cipher.h"
using namespace std;

template class CBC<AES<128>>;
template class CBC<AES<256>>;
template class GCM<AES<128>>;
template class GCM<AES<256>>;
template class CBC<Camellia<128>>;
template class CBC<Camellia<256>>;
template class GCM<Camellia<128>>;
template class GCM<Camellia<256>>;

//AES
template<int B> void AES<B>::enc_key(const unsigned char* k)
{
	if constexpr(B == 128) aes128_set_encrypt_key(&enc_ctx_, k);
	else aes256_set_encrypt_key(&enc_ctx_, k);
}
template<int B> void AES<B>::dec_key(const unsigned char* k)
{
	if constexpr(B == 128) aes128_set_decrypt_key(&dec_ctx_, k);
	else aes256_set_decrypt_key(&dec_ctx_, k);
}

//Camellia
template<int B> void Camellia<B>::enc_key(const unsigned char *k)
{
	if constexpr(B == 128) camellia128_set_encrypt_key(&enc_ctx_, k);
	else camellia256_set_encrypt_key(&enc_ctx_, k);
}
template<int B> void Camellia<B>::dec_key(const unsigned char *k)
{
	if constexpr(B == 128) camellia128_set_decrypt_key(&dec_ctx_, k);
	else camellia256_set_decrypt_key(&dec_ctx_, k);
}

//CBC
template<class C> void CBC<C>::enc_key(const unsigned char *k)
{
	cipher_.enc_key(k);
}
template<class C> void CBC<C>::dec_key(const unsigned char *k)
{
	cipher_.dec_key(k);
}
template<class C> void CBC<C>::enc_iv(const unsigned char *iv)
{
	memcpy(enc_iv_, iv, 16);
}
template<class C> void CBC<C>::dec_iv(const unsigned char *iv)
{
	memcpy(dec_iv_, iv, 16);
}

//GCM
template<class C> void GCM<C>::enc_key(const unsigned char *k)
{
	cipher_.enc_key(k);
	gcm_set_key(&enc_key_, &cipher_.enc_ctx_, C::enc_func_);
}
template<class C> void GCM<C>::dec_key(const unsigned char *k)
{
	cipher_.dec_key(k);
	gcm_set_key(&dec_key_, &cipher_.dec_ctx_, C::dec_func_);
}
template<class C> void GCM<C>::enc_iv(const unsigned char *iv)
{
	gcm_set_iv(&enc_ctx_, &enc_key_, 12, iv);
}
template<class C> void GCM<C>::dec_iv(const unsigned char *iv)
{
	gcm_set_iv(&dec_ctx_, &dec_key_, 12, iv);
}
template<class C> void GCM<C>::increase_seq_num(unsigned char *p)
{
	for(int i=7; !++p[i] && i; i--); 
}
