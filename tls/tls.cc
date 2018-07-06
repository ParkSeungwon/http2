//http://blog.fourthbit.com/2014/12/23/traffic-analysis-of-an-ssl-slash-tls-session
#include<fstream>
#include<cstring>
#include<iostream>
#include<unistd.h>
#include<arpa/inet.h>//htons
#include<cassert>
#include"tls.h"
using namespace std;

array<mpz_class, 3> get_keys(istream& is);
mpz_class get_prvkey(istream& is);
string get_certificate_core(istream& is);

static mpz_class ze, zd, zK;//used in TLS constructor
static vector<unsigned char> init_certificate()
{
	ifstream f2("p.pem");//openssl req -x509 -days 1000 -new -key p.pem -out pu.pem
	ifstream f("pu.pem"); //generated with openssl genrsa 2048 > p.pem
	auto [K, e, d] = get_keys(f2);
	zK = K; ze = e; zd = d;
	vector<unsigned char> v;
	for(int i=0; i<4; i++) v.push_back(0x0b);//certificate type + 3 byte size placehold
	for(string s; (s = get_certificate_core(f)) != "";) {
		for(int i=0; i<3; i++) v.push_back(0);
		mpz2bnd(s.size(), v.end() - 3, v.end());
		v.insert(v.end(), s.begin(), s.end());
	}
	mpz2bnd(v.size() - 4, v.begin() + 1, v.begin() + 4);
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


int TLS::server_hello(array<unsigned char, 32> id)
{//return data size
	int sz = sizeof(Hello_header);
	Hello_header* p = (Hello_header*)init(2, sz);

	p->version[0] = 3, p->version[1] = 3;
	memcpy(p->unix_time, server_random_.data(), 32);
	p->session_id_length = 32;
	session_id_ = id;
	memcpy(p->session_id, id.data(), 32);
	p->cipher_suite[1] = 0x33;//0033 DHE RSA SHA1
	p->compression = 0;//no compression
	return sz + 10;
}
/**************
(00,33)DHE-RSA-AES128-SHA : 128 Bit Key exchange: DH, encryption: AES, MAC: SHA1.
(00,67)DHE-RSA-AES128-SHA256 : 128 Bit Key exchange: DH, encryption: AES, MAC: SHA256.
(00,39)DHE-RSA-AES256-SHA : 256 Bit Key exchange: DH, encryption: AES, MAC: SHA1.
(00,6b)DHE-RSA-AES256-SHA256 : 256 Bit Key exchange: DH, encryption: AES, MAC: SHA256.

ServerHello: The ServerHello message is very similar to the ClientHello message, with the exception that it only includes one CipherSuite and one Compression method. If it includes a SessionId (i.e. SessionId Length is > 0), it signals the client to attempt to reuse it in the future.

     |
     |
     |
     |  Handshake Layer
     |
     |
- ---+----+----+----+----+----+----+----------+----+----------+----+----+----+----------+
     |  2 |    |    |    |    |    |  32byte  |    |max 32byte|    |    |    |Extensions|
     |0x02|    |    |    |  3 |  1 |  random  |    |session Id|    |    |    |          |
- ---+----+----+----+----+----+----+----------+----+----------+--------------+----------+
  /  |  \    \---------\    \----\               \       \       \----\    \
 /       \        \            \                  \   SessionId      \  Compression
record    \     length        SSL/TLS              \ (if length > 0)  \   method
length     \                  version           SessionId              \
            type: 2       (TLS 1.0 here)         length            CipherSuite
****************/


unsigned char* TLS::init(int handshake_type, int sz)
{//initialize head of buffer to send, sz = body size 
	memset(rec_to_send_, 0, sz + 5 + 4);
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
/************************
Certificate: The body of this message contains a chain of public key certificates. Certificate chains allows TLS to support certificate hierarchies and PKIs (Public Key Infrastructures).

     |
     |
     |
     |  Handshake Layer
     |
     |
- ---+----+----+----+----+----+----+----+----+----+----+-----------+---- - -
     | 11 |    |    |    |    |    |    |    |    |    |           |
     |0x0b|    |    |    |    |    |    |    |    |    |certificate| ...more certificate
- ---+----+----+----+----+----+----+----+----+----+----+-----------+---- - -
  /  |  \    \---------\    \---------\    \---------\
 /       \        \              \              \
record    \     length      Certificate    Certificate
length     \                   chain         length
            type: 11           length
***************************/

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
	auto z = rsa_.sign(bnd2mpz(b.begin(), b.end()));//SIGPE
	mpz2bnd(z, p + 96, p + 256 + 96);
	return 10 + 96 + 256;
}
/************************
ServerKeyExchange: This message carries the keys exchange algorithm parameters that the client needs from the server in order to get the symmetric encryption working thereafter. It is optional, since not all key exchanges require the server explicitly sending this message. Actually, in most cases, the Certificate message is enough for the client to securely communicate a premaster key with the server. The format of those parameters depends exclusively on the selected CipherSuite, which has been previously set by the server via the ServerHello message.

     |
     |
     |
     |  Handshake Layer
     |
     |
- ---+----+----+----+----+----------------+
     | 12 |    |    |    |   algorithm    |
     |0x0c|    |    |    |   parameters   |
- ---+----+----+----+----+----------------+
  /  |  \    \---------\
 /       \        \
record    \     length
length     \
            type: 12

struct {
select (KeyExchangeAlgorithm) {
	case dh_anon:
		ServerDHParams params;
	case dhe_dss:
	case dhe_rsa:
		ServerDHParams params;
		digitally-signed struct {
			opaque client_random[32];
			opaque server_random[32];
			ServerDHParams params;
		} signed_params;
	case rsa:
	case dh_dss:
	case dh_rsa:
	struct {} ;
		 message is omitted for rsa, dh_dss, and dh_rsa 
		 may be extended, e.g., for ECDH -- see [TLSECC] 
};
} ServerKeyExchange;
params
The server’s key exchange parameters.
signed_params
For non-anonymous key exchanges, a signature over the server’s
key exchange parameters.
*********************/

/************************
CertificateRequest: It is used when the server requires client identity authentication. Not commonly used in web servers, but very important in some cases. The message not only asks the client for the certificate, it also tells which certificate types are acceptable. In addition, it also indicates which Certificate Authorities are considered trustworthy.

     |
     |
     |
     |  Handshake Layer
     |
     |
- ---+----+----+----+----+----+----+---- - - --+----+----+----+----+-----------+-- -
     | 13 |    |    |    |    |    |           |    |    |    |    |    C.A.   |
     |0x0d|    |    |    |    |    |           |    |    |    |    |unique name|
- ---+----+----+----+----+----+----+---- - - --+----+----+----+----+-----------+-- -
  /  |  \    \---------\    \    \                \----\   \-----\
 /       \        \          \ Certificate           \        \
record    \     length        \ Type 1 Id        Certificate   \
length     \             Certificate         Authorities length \
            type: 13     Types length                         Certificate Authority
                                                                      length
*********************/

int TLS::server_hello_done()
{
	init(14, 0);
	return 10;
}
/*****************************
ServerHelloDone: This message finishes the server part of the handshake negotiation. It does not carry any additional information.

     |
     |
     |
     |  Handshake Layer
     |
     |
- ---+----+----+----+----+
     | 14 |    |    |    |
   4 |0x0e|  0 |  0 |  0 |
- ---+----+----+----+----+
  /  |  \    \---------\
 /       \        \
record    \     length: 0
length     \
            type: 14
*********************/

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
	client_aes_.iv(rec_received_->data);
	auto v = client_aes_.decrypt(rec_received_->data + 16, 
			rec_received_->data + rec_received_->length);
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

int TLS::server_finished()//16
{
	init(16, 0);
	return 10;
}
