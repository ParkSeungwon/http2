//http://blog.fourthbit.com/2014/12/23/traffic-analysis-of-an-ssl-slash-tls-session
#include<fstream>
#include<cstring>
#include<iostream>
#include<unistd.h>
#include<arpa/inet.h>//htons
#include<cassert>
#include<initializer_list>
#include"tls.h"
using namespace std;

array<mpz_class, 3> get_keys(istream& is);
mpz_class get_prvkey(istream& is);
string get_certificate_core(istream& is);

//static member initialization
static mpz_class ze, zd, zK;//used in TLS constructor
static int init_certificate()
{
	ifstream f2("p.pem");//openssl req -x509 -days 1000 -new -key p.pem -out pu.pem
	ifstream f("pu.pem"); //generated with openssl genrsa 2048 > p.pem
	auto [K, e, d] = get_keys(f2);
	zK = K; ze = e; zd = d;
}
static int k = init_certificate();
RSA TLS::rsa_{ze, zd, zK};

TLS::TLS(unsigned char* buffer)
{//buffer = read buffer, buffer2 = write buffer
	rec_received_ = reinterpret_cast<TLS_header*>(buffer);
}

void TLS::set_buf(void* p)
{
	rec_received_ = (TLS_header*)p;
}

array<unsigned char, 32> TLS::client_hello()
{//return desired id
	Handshake_header* ph = (Handshake_header*)(rec_received_ + 1);
	assert(rec_received_->content_type == 0x16);//handshake
	assert(ph->handshake_type == 1);//client hello
	Hello_header* p = (Hello_header*)(ph + 1);
	memcpy(client_random_.data(), p->unix_time, 32);//unix time + 28 random
	memcpy(server_random_.data(), p->unix_time, 4);
	mpz2bnd(random_prime(28), server_random_.data() + 4, server_random_.end());
	if(id_length_ = p->session_id_length) {
		memcpy(session_id_.data(), p->session_id, id_length_);
		return session_id_;
	} else return {};
}
/*****************
ClientHello: This message typically begins a TLS handshake negotiation. It is sent with a list of client-supported cipher suites, for the server to pick the best suiting one (preferably the strongest), a list of compression methods, and a list of extensions. It gives also the possibility to the client of restarting a previous session, through the inclusion of a SessionId field.

     |
     |
     |
     |  Handshake Layer
     |
     |
- ---+----+----+----+----+----+----+------+----+----------+--------+-----------+----------+
     |  1 |    |    |    |    |    |32-bit|    |max 32-bit| Cipher |Compression|Extensions|
     |0x01|    |    |    |  3 |  1 |random|    |session Id| Suites |  methods  |          |
- ---+----+----+----+----+----+----+------+----+----------+--------+-----------+----------+
  /  |  \    \---------\    \----\             \       \
 /       \        \            \                \   SessionId
record    \     length        SSL/TLS            \
length     \                  version         SessionId
            type: 1       (TLS 1.0 here)       length



CipherSuites

+----+----+----+----+----+----+
|    |    |    |    |    |    |
|    |    |    |    |    |    |
+----+----+----+----+----+----+
  \-----\   \-----\    \----\
     \         \          \
      length    cipher Id  cipherId


Compression methods (no practical implementation uses compression)

+----+----+----+
|    |    |    |
|  0 |  1 |  0 |
+----+----+----+
  \-----\    \
     \        \
 length: 1    cmp Id: 0


Extensions

+----+----+----+----+----+----+----- - -
|    |    |    |    |    |    |
|    |    |    |    |    |    |...extension data
+----+----+----+----+----+----+----- - -
  \-----\   \-----\    \----\
     \         \          \
    length    Extension  Extension data
                 Id          length

***************************/




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
	Handshake_header* ph = (Handshake_header*)(rec_received_+1);
	assert(ph->handshake_type == 16);

	unsigned char rand[64], pre[32];
	auto pre_master_secret = diffie_.yb(bnd2mpz((unsigned char*)ph+1, (unsigned char*)(ph+1)+32));
	mpz2bnd(pre_master_secret, pre, pre+32);
	memcpy(rand, client_random_.data(), 32);
	memcpy(rand + 32, server_random_.data(), 32);
	PRF<SHA1> prf;
	prf.secret(pre, pre+32);
	prf.seed(rand, rand + 64);
	prf.label("master secret");
	auto master_secret = prf.get_n_byte(48);
	memcpy(rand + 32, client_random_.data(), 32);
	memcpy(rand, server_random_.data(), 32);
	prf.secret(master_secret.begin(), master_secret.end());
	prf.label("key expansion");
	prf.seed(rand, rand+64);
	return use_key(prf.get_n_byte(64));
}
/*****************************
ClientKeyExchange: It provides the server with the necessary data to generate the keys for the symmetric encryption. The message format is very similar to ServerKeyExchange, since it depends mostly on the key exchange algorithm picked by the server.

     |
     |
     |
     |  Handshake Layer
     |
     |
- ---+----+----+----+----+----------------+
     | 16 |    |    |    |   algorithm    |
     |0x10|    |    |    |   parameters   |
- ---+----+----+----+----+----------------+
  /  |  \    \---------\
 /       \        \
record    \     length
length     \
            type: 16
**********************/

string TLS::decode()
{
	assert(rec_received_->content_type == 0x17);
	unsigned char* p = reinterpret_cast<unsigned char*>(rec_received_ + 1);
	client_aes_.iv(p);
	auto v = client_aes_.decrypt(p + 16, p + rec_received_->length[0] * 0x100 + rec_received_->length[1]);
	return {v.data(), v.data() + v.size() - 20 - v.back()};//v.back() == padding length
}
/***********************
ApplicationData Protocol format

The mission of this protocol is to properly encapsulate the data coming from the Application Layer of the network stack, so it can seamlessly be handled by the underlying protocol (TCP) without forcing changes in any of those layers. The format of the messages in this protocols follows the same structure as the previous ones.

                           |
                           |
                           |
         Record Layer      |  ApplicationData Layer (encrypted)
                           |
                           |
  +----+----+----+----+----+----+----+--- - - - - - - --+---------+
  | 23 |    |    |    |       length-delimited data     |         |
  |0x17|    |    |    |    |    |    |                  |   MAC   |
  +----+----+----+----+----+----+----+--- - - - - - - --+---------+
    /               /      |
   /               /       |
  type: 23        /        |
                 /
                /
           length: arbitrary (up to 16k)
******************/

vector<string> TLS::encode(string s) {
	struct {
		TLS_header h1;
		uint8_t random[16];
	}__attribute__((packed)) r;
	r.h1.content_type = 0x17;
	vector<string> vs;

	const int chunk_size = (2 << 14) - 1024 - 20;//cut string into 2^14
	for(int sq = 1; chunk_size * (sq - 1) < s.size(); sq++) {
		auto z = random_prime(16);
		mpz2bnd(z, r.random, r.random + 16);
		server_aes_.iv(z);

		int len = sq * chunk_size > s.size() ? s.size() % chunk_size : chunk_size;
		int padding_length = 16 - (len + 20) % 16;//20 = sha1 digest, 16 block sz
		mpz2bnd(len + 20 + 16 + 1, r.h1.length, r.h1.length + 2);
		std::string s2 = string{sq} + string{(const char*)&r.h1, 5} + 
			s.substr((sq-1) * chunk_size, min((int)s.size(), sq*chunk_size));
		auto verify = server_mac_.hash((uint8_t*)s2.data(),
				(uint8_t*)s2.data() + s.size());
		s2 += string{verify.begin(), verify.end()};
		s2 += string(padding_length, padding_length);
		auto v = server_aes_.encrypt((uint8_t*)s2.data()+6,//exclude first 6 bytes
				(uint8_t*)s2.data() + s2.size());
		string s3 = s2.substr(0, 6) + string{(const char*)r.random, 16} +
			string{v.begin(), v.end()};
		vs.push_back(s3);
	}
	return vs;
}
/***************
The MAC is generated as:
MAC(MAC_write_key, seq_num + TLSCompressed.type + TLSCompressed.version +
	TLSCompressed.length + TLSCompressed.fragment);
where "+" denotes concatenation.

struct {
	opaque IV[SecurityParameters.record_iv_length];//16
	block-ciphered struct {
		opaque content[TLSCompressed.length];//len
		opaque MAC[SecurityParameters.mac_length];//20
		uint8 padding[GenericBlockCipher.padding_length];//pad
		uint8 padding_length;//1
	};
} GenericBlockCipher;
*********************/
int TLS::client_finished()
{
	Handshake_header* ph = (Handshake_header*)(rec_received_ + 1);
	assert(ph->handshake_type == 20);
	return 7;
}
/***********************
Finished: This message signals that the TLS negotiation is complete and the CipherSuite is activated. It should be sent already encrypted, since the negotiation is successfully done, so a ChangeCipherSpec protocol message must be sent before this one to activate the encryption. The Finished message contains a hash of all previous handshake messages combined, followed by a special number identifying server/client role, the master secret and padding. The resulting hash is different from the CertificateVerify hash, since there have been more handshake messages.

     |
     |
     |
     |  Handshake Layer
     |
     |
- ---+----+----+----+----+----------+
     | 20 |    |    |    |  signed  |
     |0x14|    |    |    |   hash   |
- ---+----+----+----+----+----------+
  /  |  \    \---------\
 /       \        \
record    \     length
length     \
            type: 20
*********************/

