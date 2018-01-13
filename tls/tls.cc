#include<cstring>
#include<iostream>
#include<unistd.h>
#include<arpa/inet.h>//htons
#include<cassert>
#include"tls.h"
using namespace std;

TLS::TLS(unsigned char* buffer, unsigned char* buffer2)
{//buffer = read buffer, buffer2 = write buffer
	rec_received_ = reinterpret_cast<TLS_header*>(buffer);
	if(buffer2) rec_to_send_ = reinterpret_cast<TLS_header*>(buffer2);
	else rec_to_send_ = rec_received_;
}

array<unsigned char, 32> TLS::client_hello()
{//return desired id
	Handshake_header* ph = (Handshake_header*)rec_received_->data;
	assert(rec_received_->content_type == 0x16);//handshake
	assert(ph->handshake_type == 1);//client hello
	Hello_header* p = (Hello_header*)ph->data;
	memcpy(client_random_.data(), p->unix_time, 32);//unix time + 28 random
	memcpy(server_random_.data(), p->unix_time, 4);
	mpz2bnd(random_prime(28), server_random_.data() + 4, server_random_.end());
	if(id_length_ = p->session_id_length) {
		memcpy(session_id_.data(), p->session_id, id_length_);
		return session_id_;
	} else return {};
}

int TLS::server_hello(array<unsigned char, 32> id)
{//return data size
	Handshake_header* ph = (Handshake_header*)rec_to_send_->data;
	Hello_header* p = (Hello_header*)ph->data;
	int sz = &p->end - (uint8_t*)rec_to_send_;
	init(sz);

	ph->handshake_type = 2;
	mpz2bnd(sz - 9, ph->length, ph->length+3);

	p->version[0] = 3, p->version[1] = 3;
	memcpy(p->unix_time, server_random_.data(), 32);
	p->session_id_length = 32;
	session_id_ = id;
	memcpy(p->session_id, id.data(), 32);
	p->cipher_suite[1] = 0x35;//0035 DHE RSA SHA1
	p->compression = 0;//no compression
	return sz;
}

void TLS::init(int sz)
{//initialize buffer to send
	memset(rec_to_send_, 0, sz);
	rec_to_send_->content_type = 0x16;
	rec_to_send_->version = 0x0303;//no need htons 03 = 03
	rec_to_send_->length = htons(sz - 5);
}

int TLS::server_certificate()
{//return data_size
	rec_to_send_->handshake_type = 11;
	
	return 2;
}
/* Static x509 buffer */
typedef struct x509_buffer {
    int  length;                  /* actual size */
    byte buffer[MAX_X509_SIZE];   /* max static cert size */
} x509_buffer;


/* wolfSSL X509_CHAIN, for no dynamic memory SESSION_CACHE */
struct WOLFSSL_X509_CHAIN {
    int         count;                    /* total number in chain */
    x509_buffer certs[MAX_CHAIN_DEPTH];   /* only allow max depth 4 for now */
};


int TLS::server_key_exchange()
{
	Handshake_header* ph = (Handshake_header*)rec_to_send_->data;
	ph->handshake_type = 12;
	ph->length;
	mpz2bnd(diffie_.p, ph->data, ph->data+32);
	mpz2bnd(diffie_.g, ph->data+32, ph->data+64);
	mpz2bnd(diffie_.ya, ph->data+64, ph->data+96);

	return 3;
}

int TLS::server_hello_done()
{
	Handshake_header* ph = (Handshake_header*)rec_to_send_->data;
	int sz = ph->data - (uint8_t*)rec_to_send_;
	init(sz);
	ph->handshake_type = 14;
	return sz;
}

int TLS::client_key_exchange()//16
{
	Handshake_header* ph = (Handshake_header*)rec_received_->data;
	assert(ph->handshake_type == 16);

	unsigned char rand[64], pre[32];
	auto pre_master_secret = diffie_.yb(bnd2mpz(ph->data, ph->data+32));
	mpz2bnd(pre_master_secret, pre, pre+32);
	memcpy(rand, client_random_.data(), 32);
	memcpy(rand + 32, server_random_.data(), 32);
	auto master_secret = prf(pre, pre+32, "master secret", rand, 48);
	memcpy(rand + 32, client_random_.data(), 32);
	memcpy(rand, server_random_.data(), 32);
	auto keys = prf(master_secret.begin(), master_secret.end(), "key expansion", rand, 136);

	unsigned char* p = keys.data();
	hmac_dec_.key(p); p += 28;
	hmac_enc_.key(p); p += 28;
	aes_dec_.key(p); p += 32;
	aes_enc_.key(p); p += 32;
	aes_dec_.iv(p); p += 16;
	aes_enc_.iv(p);
	return -6;
}

string TLS::decode()
{
	assert(rec_received_->content_type == 0x17);
	auto v = aes_dec_.decrypt(rec_received_->data, rec_received_->data + rec_received_->length);
	return {v.data(), v.size()};
}

int TLS::encode(string s)
{
	auto v = aes_enc_.encrypt(s.data(), s.data() + s.size());
	int sz = v.size() + 5;
	init(sz);
	rec_to_send_->content_type = 0x17;
	memcpy(rec_to_send_->data, v.data(), sz - 5);
	return sz;
}

int TLS::client_finished()
{
	Handshake_header* ph = (Handshake_header*)rec_received_->data;
	assert(ph->handshake_type == 20);
	return 7;
}

int TLS::server_finished()//16
{
	return 0;
}

