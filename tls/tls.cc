//http://blog.fourthbit.com/2014/12/23/traffic-analysis-of-an-ssl-slash-tls-session
#include<cstring>
#include<iostream>
#include<unistd.h>
#include<arpa/inet.h>//htons
#include<cassert>
#include<initializer_list>
#include<fstream>
#include<deque>
#include"tls.h"
using namespace std;

array<mpz_class, 3> get_keys(istream& is);
mpz_class get_prvkey(istream& is);
std::string get_certificate_core(std::istream& is);

//static member initialization
static mpz_class ze, zd, zK;//used in TLS constructor
static vector<unsigned char> to_byte(int k, int sz)
{
	vector<unsigned char> v(sz);
	mpz2bnd(k, v.begin(), v.end());
	return v;
}
static vector<unsigned char> init_certificate()
{
	ifstream f2("key.pem");//generated with openssl genrsa 2048 > key.pem
	ifstream f("cert.pem");//openssl req -x509 -days 1000 -new -key key.pem -out cert.pem
	auto [K, e, d] = get_keys(f2);
	zK = K; ze = e; zd = d;
//	mpz_class m{"0x23232"};
//	auto z = powm(m, e, K);
//	assert(m == powm(z, d, K));
	vector<vector<unsigned char>> vv;

	for(string s; (s = get_certificate_core(f)) != "";) {
		vector<unsigned char> v;
		for(unsigned char c : base64_decode(s)) v.push_back(c);
		vv.push_back(v);
	}

	deque<unsigned char> r;
	for(const auto &v : vv) {
		for(unsigned char c : to_byte(v.size(), 3)) r.push_back(c);
		for(unsigned char c : v) r.push_back(c);
	}
	for(int i=0; i<2; i++) {
		auto v = to_byte(r.size(), 3);
		r.insert(r.begin(), v.begin(), v.end());
	}
	r.push_front(0x0b);
	auto v = to_byte(r.size(), 2);
	r.insert(r.begin(), v.begin(), v.end());
	r.push_front(3); r.push_front(3); r.push_front(0x16);

	v.clear();
	for(unsigned char c : r) v.push_back(c);
	return v;
}
vector<unsigned char> TLS::certificate_ = init_certificate();
RSA TLS::rsa_{ze, zd, zK};


TLS::TLS(unsigned char* buffer)
{//buffer = read buffer, buffer2 = write buffer
	rec_received_ = reinterpret_cast<TLS_header*>(buffer);
}

vector<unsigned char> TLS::server_certificate()
{
	return certificate_;
}

/************************
Structure of this message:

opaque ASN.1Cert<1..2^24-1>;

struct {
	ASN.1Cert certificate_list<0..2^24-1>;
} Certificate;

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




array<unsigned char, 32 * 4> TLS::use_key(array<unsigned char, 32 * 4> keys)
{
	unsigned char *p = keys.data();
	client_mac_.key(p, p + 32);
	server_mac_.key(p + 32, p + 64);
	client_aes_.key(p + 64);//AES128 key size 16
	server_aes_.key(p + 80);
	client_aes_.iv(p + 96);
	server_aes_.iv(p + 112);
	return keys;
}
array<unsigned char, 32 * 4> TLS::use_key(vector<unsigned char> keys)
{//just pass to upper function
	array<unsigned char, 32 * 4> r;
	for(int i=0; i < 32 * 4; i++) r[i] = keys[i];
	return use_key(r);
}
/******
 Then, the key_block is
partitioned as follows:
client_write_MAC_key[SecurityParameters.mac_key_length] 32?
server_write_MAC_key[SecurityParameters.mac_key_length]
client_write_key[SecurityParameters.enc_key_length] 32
server_write_key[SecurityParameters.enc_key_length]
client_write_IV[SecurityParameters.fixed_iv_length] 16
server_write_IV[SecurityParameters.fixed_iv_length]
Currently, the client_write_IV and server_write_IV are only generated
for implicit nonce techniques as described in Section 3.2.1 of
[AEAD].
Implementation note: The currently defined cipher suite which
requires the most material is AES_256_CBC_SHA256. It requires 2 x 32
byte keys and 2 x 32 byte MAC keys, for a total 128 bytes of key
material.

Immediately after sending a ChangeCipherSpec message, the client will send an encrypted Handshake Finished message to ensure the server is able to understand the agreed-upon encryption. The message will contain a hash of all previous handshake messages, along with the string “client finished”. This is very important because it verifies that no part of the handshake has been tampered with by an attacker. It also includes the random bytes that were sent by the client and server, protecting it from replay attacks where the attacker pretends to be one of the parties.

Once received by the server, the server will acknowledge with its own ChangeCipherSpec message, followed immediately by its own Finished message verifying the contents of the handshake.

Note: if you have been following along in Wireshark, there appears to be a bug with Client/Server Finish messages when using AES_GCM that mislabels them.
Application Data

Finally, we can begin to transmit encrypted data! It may seem like a lot of work, but that is soon to pay off. The only remaining step is to discuss how the data is encrypted with AES_GCM, an AEAD cipher.

First, we generate a MAC, key, and IV for both the client and the server using our master secret and the PRF definition from earlier.

key_data = PRF(master_secret, "key expansion", server_random + client_random);

Since we are using 128-bit AES with SHA-256, we’ll pull out the following key data:

// client_write_MAC_key = key_data[0..31]
// server_write_MAC_key = key_data[32..63]
client_write_key = key_data[64..79]
server_write_key = key_data[80..95]
client_write_IV = key_data[96..99]
server_write_IV = key_data[100..103]

For AEAD ciphers like GCM, we don’t need the MAC keys, but we offset them anyways. The client and server also get different keys to prevent a replay attack where a client message it looped back to it.

We also construct additional_data and an 8-byte nonce, both of which are sent with the encrypted data. In the past, it was thought that the nonce could be either random or just a simple session counter. However, recent research found many sites using random nonces for AES_GCM were vulnerable to nonce reuse attacks, so it’s best to just use an incrementing counter tied to the session.

additional_data = sequence_num + record_type + tls_version + length
nonce = <random_8_bytes>

Finally, we can encrypt our data with AES GCM!

encrypted = AES_GCM(client_write_key, client_write_IV+nonce, <DATA>, additional_data)

and the server can read it with

<DATA> = AES_GCM(client_write_key, client_write_IV+nonce, encrypted, additional_data)

******/

array<unsigned char, 32*4> TLS::client_key_exchange()//16
{//return client_aes_key + server_aes_key
	struct H {
		TLS_header h1;
		Handshake_header h2;
		uint8_t key_sz[2];
		uint8_t pub_key[];
	}__attribute__((packed));
	H* ph = (H*)rec_received_;;
	assert(ph->h2.handshake_type == 16);

	unsigned char rand[64], pre[DH_KEY_SZ];
	int key_size = ph->key_sz[0] * 0x100 + ph->key_sz[1];
	auto pre_master_secret = diffie_.yb(bnd2mpz(ph->pub_key, ph->pub_key + key_size));
	mpz2bnd(pre_master_secret, pre, pre + DH_KEY_SZ);
	memcpy(rand, client_random_.data(), 32);
	memcpy(rand + 32, server_random_.data(), 32);
	PRF<SHA1> prf;
	prf.secret(pre, pre + DH_KEY_SZ);
	prf.seed(rand, rand + 64);
	prf.label("master secret");
	auto master_secret = prf.get_n_byte(48);
	memcpy(rand + 32, client_random_.data(), 32);
	memcpy(rand, server_random_.data(), 32);
	prf.secret(master_secret.begin(), master_secret.end());
	prf.label("key expansion");
	prf.seed(rand, rand+64);
	return use_key(prf.get_n_byte(32 * 4));
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

until enough output has been generated.
**********************/

int TLS::get_content_type() {
	return rec_received_->content_type;
}

string TLS::decode()
{
//	assert(rec_received_->content_type == 0x17);
	unsigned char* p = reinterpret_cast<unsigned char*>(rec_received_ + 1);
//	client_aes_.iv(p);
	auto v = client_aes_.decrypt(p, p + rec_received_->length[0] * 0x100 + rec_received_->length[1]);
	for(int i=v.back(); i>0; i--) v.pop_back();
	auto a = client_mac_.hash(v.begin(), v.end() - 20);
	for(int i=0; i<20; i++) cout << +a[i] << ':' << v[v.size() - 20 + i];
	return {v.data(), v.data() + v.size() - 20};//v.back() == padding length
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
		//uint8_t random[16];
	}__attribute__((packed)) r;
	r.h1.content_type = 0x17;
	vector<string> vs;

	const int chunk_size = (2 << 14) - 1024 - 20;//cut string into 2^14
	for(int sq = 1; chunk_size * (sq - 1) < s.size(); sq++) {
//		auto z = random_prime(16);
//		mpz2bnd(z, r.random, r.random + 16);
//		server_aes_.iv(z);

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
		string s3 = s2.substr(0, 6) + //string{(const char*)r.random, 16} +
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

void TLS::change_cipher_spec(int) {}
int TLS::client_finished()
{
	string s = decode();
	for(unsigned char c : s) cout << noskipws << hex << +c << ' ';
	Handshake_header* ph = (Handshake_header*)(rec_received_ + 1);
//	assert(ph->handshake_type == 20);
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

void TLS::generate_signature(unsigned char *p_length, unsigned char *p) {
	unsigned char a[64 + 3 * DH_KEY_SZ + 6];
	memcpy(a, client_random_.data(), 32);
	memcpy(a + 32, server_random_.data(), 32);
	memcpy(a + 64, p_length, 6 + 3 * DH_KEY_SZ);
	//		auto b = server_mac_.hash(a, a + 70 + 3 * DH_KEY_SZ);
	SHA5 sha;
	auto b = sha.hash(a, a + 70 + 3 * DH_KEY_SZ);
	deque<unsigned char> dq{b.begin(), b.end()};
	unsigned char d[] = {0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01,
						 0x65, 0x03, 0x04, 0x02, 0x03, 0x05, 0x00, 0x04};
	dq.push_front(dq.size());
	dq.insert(dq.begin(), d, d + 16);
	dq.push_front(dq.size());
	dq.push_front(0x30);
	dq.push_front(0x00);
	while(dq.size() < 254) dq.push_front(0xff);
	dq.push_front(0x01);
	dq.push_front(0x00);
	//		3031300d060960864801650304020105000420
	//		3051300d060960864801650304020305000440		
	//		1ffff padding should be added in front of b;
	auto z = rsa_.sign(bnd2mpz(dq.begin(), dq.end()));//SIGPE
	mpz2bnd(z, p, p + 256);
}
