#include<fstream>
#include<cstring>
#include<iostream>
#include<unistd.h>
#include<arpa/inet.h>//htons
#include<cassert>
#include"tls.h"
using namespace std;

static mpz_class ze, zd, zK;//used in TLS constructor
static vector<unsigned char> init_certificate()
{
	ifstream f("server-cert.pem"); 
	vector<unsigned char> v; unsigned char c;
	while(f >> noskipws >> c) v.push_back(c);
//	ze = get keys from files
	return v;
}
vector<unsigned char> TLS::certificate_ = init_certificate();
RSA TLS::rsa_{ze, zd, zK};

TLS::TLS(unsigned char* buffer, unsigned char* buffer2)
{//buffer = read buffer, buffer2 = write buffer
	rec_received_ = reinterpret_cast<TLS_header*>(buffer);
	if(buffer2) rec_to_send_ = reinterpret_cast<TLS_header*>(buffer2);
	else rec_to_send_ = rec_received_;//use same buffer for read and write
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
	int sz = sizeof(Hello_header);
	Hello_header* p = (Hello_header*)init(2, sz);

	p->version[0] = 3, p->version[1] = 3;
	memcpy(p->unix_time, server_random_.data(), 32);
	p->session_id_length = 32;
	session_id_ = id;
	memcpy(p->session_id, id.data(), 32);
	p->cipher_suite[1] = 0x35;//0035 DHE RSA SHA1
	p->compression = 0;//no compression
	return sz + 10;
}

unsigned char* TLS::init(int handshake_type, int sz)
{//initialize buffer to send, sz = body size 
	memset(rec_to_send_, 0, sz + 6 + 4);
	rec_to_send_->content_type = 0x16;
	rec_to_send_->version = 0x0303;//no need htons 03 = 03
	rec_to_send_->length = htons(sz + 4);
	Handshake_header* ph = (Handshake_header*)rec_to_send_->data;
	ph->handshake_type = handshake_type;
	mpz2bnd(sz, ph->length, ph->length+3);
	return ph->data;
}

int TLS::server_certificate()
{//return data_size
	int sz = certificate_.size();
	unsigned char* p = init(11, sz);
	for(int i=0; i<sz; i++) p[i] = certificate_[i];
	return sz + 10;
}

int TLS::server_key_exchange()
{
	unsigned char* p = init(12, 96 + 256);
	mpz2bnd(diffie_.p, p, p+32);
	mpz2bnd(diffie_.g, p+32, p+64);
	mpz2bnd(diffie_.ya, p+64, p+96);

	unsigned char a[160];
	memcpy(a, client_random_.data(), 32);
	memcpy(a + 32, server_random_.data(), 32);
	memcpy(a + 64, p, 96);
	auto b = server_mac_.hash(a, a + 160);
	auto z = rsa_.sign(bnd2mpz(b.begin(), b.end()));
	mpz2bnd(z, p + 96, p + 256 + 96);
	return 10 + 96 + 256;
}

int TLS::server_hello_done()
{
	init(14, 0);
	return 10;
}

array<unsigned char, 64> TLS::use_key(array<unsigned char, 64> keys)
{
	client_aes_.key(keys.data());
	server_aes_.key(keys.data() + 32);
	return keys;
}
array<unsigned char, 64> TLS::use_key(vector<unsigned char> keys)
{
	array<unsigned char, 64> r;
	for(int i=0; i<64; i++) r[i] = keys[i];
	return use_key(r);
}

array<unsigned char, 64> TLS::client_key_exchange()//16
{//return client_aes_key + server_aes_key
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
	return use_key(prf(master_secret.begin(), master_secret.end(), "key expansion", rand, 64));
}

string TLS::decode()
{
	assert(rec_received_->content_type == 0x17);
	client_aes_.iv(rec_received_->data);
	auto v = client_aes_.decrypt(rec_received_->data + 16, 
			rec_received_->data + rec_received_->length);
	return {v.data(), v.data() + v.size() - 20 - v.back()};//v.back() == padding length
}

int TLS::encode(string s)
{//encrypt source s according to tls -> prepare rec_to_send_ buffer, return buffer size
	rec_to_send_->content_type = 0x17;
	rec_to_send_->version = 0x0303;
	mpz2bnd(random_prime(16), rec_to_send_->data, rec_to_send_->data+16);
	server_aes_.iv(rec_to_send_->data);
	int padding_length = 16 - (s.size() + 20) % 16;//20 = sha1 digest size, 16 block sz

	s = string{0x01} + string{(char*)rec_to_send_, 5} + s;
	auto verify = server_mac_.hash((uint8_t*)s.data(), (uint8_t*)s.data() + s.size());
	
	s += string{verify.begin(), verify.end()} + string(padding_length, padding_length);
	auto v = server_aes_.encrypt((uint8_t*)s.data()+6, (uint8_t*)s.data() + s.size());
	
	memcpy(rec_to_send_->data+16, v.data(), v.size());
	rec_to_send_->length = v.size() + 16;
	return v.size() + 16 + 5;
}

int TLS::client_finished()
{
	Handshake_header* ph = (Handshake_header*)rec_received_->data;
	assert(ph->handshake_type == 20);
	return 7;
}

int TLS::server_finished()//16
{
	init(16, 0);
	return 10;
}
