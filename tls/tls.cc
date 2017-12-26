#include<cassert>
#include<cstring>
#include<unistd.h>
#include<iostream>
#include<iomanip>
#include<sstream>
#include"server.h"
#include"tls.h"
using namespace std;

template<typename It> mpz_class bnd2mpz(It begin, It end)
{//big endian to mpz
	stringstream ss; ss << "0x";
	for(It i=begin; i!=end; i++) ss << setw(2) << setfill('0') << hex << +*i;
	return mpz_class{ss.str()};
}

template<typename It> void mpz2bnd(mpz_class n, It begin, It end)
{//mpz to big endian
	for(It i=end; i!=begin; n /= 0x100) *--i = mpz_class{n % 0x100}.get_ui();
}

void show() {}
template<typename... Args> void show(mpz_class a, Args... b)
{//print args
	cout <<  "0x" << hex << a << endl;
	show(b...);
}

mpz_class nextprime(mpz_class n) 
{//chance of composite passing will be extremely small
	mpz_class r;
	mpz_nextprime(r.get_mpz_t(), n.get_mpz_t());
	return r;
}

mpz_class random_prime(unsigned byte)
{//return byte length prime number
	unsigned char arr[byte];
	uniform_int_distribution<> di(0, 0xff);
	random_device rd;
	for(int i=0; i<byte; i++) arr[i] = di(rd);
	return nextprime(bnd2mpz(arr, arr+byte));//a little hole : over 0xffffffffffff
}

mpz_class powm(mpz_class base, mpz_class exp, mpz_class mod) 
{
	mpz_class r;
	mpz_powm(r.get_mpz_t(), base.get_mpz_t(), exp.get_mpz_t(), mod.get_mpz_t());
	return r;
}

AES256::AES256(mpz_class key, mpz_class iv)
{
	mpz2bnd(key, key_, key_+32);
	mpz2bnd(iv, iv_, iv_+16);
	wc_AesSetKey(&enc_, key_, 32, iv_, AES_ENCRYPTION);
	wc_AesSetKey(&dec_, key_, 32, iv_, AES_DECRYPTION);
}

template vector<uint8_t> AES256::encrypt<>(uint8_t* begin, uint8_t* end);
template vector<uint8_t> AES256::decrypt<>(uint8_t* begin, uint8_t* end);
template array<uint8_t, 20> SHA1::hash<>(uint8_t* begin, uint8_t* end);
template vector<uint8_t> AES256::encrypt<>(
		vector<uint8_t>::iterator begin, vector<uint8_t>::iterator end); 
template vector<uint8_t> AES256::decrypt<>(
		vector<uint8_t>::iterator begin, vector<uint8_t>::iterator end); 
template array<uint8_t, 20> SHA1::hash<>(
		vector<uint8_t>::iterator begin, vector<uint8_t>::iterator end);

template<typename It> vector<unsigned char> AES256::encrypt(It begin, It end)
{
	int sz = end - begin;
	assert(sz % 16 == 0);
	vector<unsigned char> result(sz);
	wc_AesCbcEncrypt(&enc_, result.data(), &*begin, sz);//&* for iterator
	return result;
}

template<typename It> vector<unsigned char> AES256::decrypt(It begin, It end)
{
	int sz = end - begin;
	assert(sz % 16 == 0);
	vector<unsigned char> result(sz);
	wc_AesCbcDecrypt(&dec_, result.data(), &*begin, sz);
	return result;
}

SHA1::SHA1()
{
	if(wc_InitSha(&sha_)) cerr << "wc_init_sha_failed" << endl;
}

template<typename It> array<unsigned char, 20> SHA1::hash(It begin, It end)
{
	array<unsigned char, 20> r;
	int sz = end - begin;
	wc_ShaUpdate(&sha_, &*begin, sz);
	wc_ShaFinal(&sha_, r.data());
	return r;
}

bool TLS::Less::operator()(const unsigned char* a, const unsigned char* b) const 
{
	return memcmp(a, b, 32) < 0;
}

void TLS::start()
{
	int cl_size = sizeof(client_addr);
	while(1) {
		cout << "0" << endl;
		client_fd = accept(server_fd, (sockaddr*)&client_addr, (socklen_t*)&cl_size);
		if(client_fd == -1) cout << "accept() error" << endl;
		else if(!fork()) {
//			gnutls_session_t session;
//			gnutls_datum_t session_id;
//			gnutls_init(&session, GNUTLS_SERVER);
//			gnutls_priority_set_direct(session, "NORMAL:+ANON-ECDH:+ANON-DH", NULL);
//			gnutls_credentials_set(session, GNUTLS_CRD_ANON, anoncred);
//			gnutls_session_get_id2(session, &session_id);
//			gnutls_transport_set_int(session, client_fd);
//			int ret;
//			do {
//				ret = gnutls_handshake(session);
//			} while (ret < 0 && gnutls_error_is_fatal(ret) == 0);
//
//			for(int n; (n = gnutls_record_recv(session, buffer, 40960000)) > 0;) {
//				if(idNchannel_.find(session_id.data) == idNchannel_.end()) 
//					idNchannel_[session_id.data] = new Channel(inport_);
//				idNchannel_[session_id.data]->send(string{buffer, n});
//				string s = idNchannel_[session_id.data]->recv();
//				cout << s << endl;
//				gnutls_record_send(session, s.data(), s.size());
//			}
//			gnutls_bye(session, GNUTLS_SHUT_WR);
//			gnutls_deinit(session);
			break;
		}
	}
}
