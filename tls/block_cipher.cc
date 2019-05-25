#include"crypt.h"
#include"block_cipher.h"
using namespace std;

template class AES<128>;
template class AES<256>;
template class Camellia<128>;
template class Camellia<256>;
template class CBC<AES<128>>;
template class CBC<AES<256>>;
template class CBC<Camellia<128>>;
template class CBC<Camellia<256>>;
template class CBC<DES3>;
template class GCM<AES<128>>;
template class GCM<AES<256>>;
template class GCM<Camellia<128>>;
template class GCM<Camellia<256>>;
template class GCM<DES3>;

using ncf = nettle_cipher_func;
using kf = nettle_set_key_func;

//AES
template<int B> AES<B>::AES()
{
	set_enc_key_ = B == 128 ? (kf*)aes128_set_encrypt_key : (kf*)aes256_set_encrypt_key;
	set_dec_key_ = B == 128 ? (kf*)aes128_set_decrypt_key : (kf*)aes256_set_decrypt_key;
	enc_func_ = B == 128 ? (ncf*)aes128_encrypt : (ncf*)aes256_encrypt;
	dec_func_ = B == 128 ? (ncf*)aes128_decrypt : (ncf*)aes256_decrypt;
}

//Camellia
template<int B> Camellia<B>::Camellia()
{
	set_enc_key_ = B == 128 ?
		(kf*)camellia128_set_encrypt_key : (kf*)camellia256_set_encrypt_key;
	set_dec_key_ = B == 128 ?
		(kf*)camellia128_set_decrypt_key : (kf*)camellia256_set_decrypt_key;
	dec_func_ = enc_func_ = B == 128 ? (ncf*)camellia128_crypt:(ncf*)camellia256_crypt;
}

//DES3
DES3::DES3()
{
	set_enc_key_ = (kf*)des3_set_key;
	set_dec_key_ = (kf*)des3_set_key;
	dec_func_ = enc_func_ = (ncf*)des3_encrypt;
}

//CBC
template<class C> void CBC<C>::enc_key(const unsigned char *k)
{
	cipher_.set_enc_key_(&cipher_.enc_ctx_, k);
}
template<class C> void CBC<C>::dec_key(const unsigned char *k)
{
	cipher_.set_dec_key_(&cipher_.dec_ctx_, k);
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
	cipher_.set_enc_key_(&cipher_.enc_ctx_, k);
	gcm_set_key(&enc_key_, &cipher_.enc_ctx_, cipher_.enc_func_);
}
template<class C> void GCM<C>::dec_key(const unsigned char *k)
{
	cipher_.set_enc_key_(&cipher_.dec_ctx_, k);//use enc key!!
	gcm_set_key(&dec_key_, &cipher_.dec_ctx_, cipher_.enc_func_);
}
template<class C> void GCM<C>::enc_iv(const unsigned char *iv)
{
	gcm_set_iv(&enc_ctx_, &enc_key_, GCM_IV_SIZE, iv);//12
}
template<class C> void GCM<C>::dec_iv(const unsigned char *iv)
{
	gcm_set_iv(&dec_ctx_, &dec_key_, GCM_IV_SIZE, iv);//12
}
template<class C> void GCM<C>::increase_seq_num(unsigned char *p)
{
	for(int i=7; !++p[i] && i; i--); 
}
