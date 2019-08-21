//http://blog.fourthbit.com/2014/12/23/traffic-analysis-of-an-ssl-slash-tls-session
#include<cstring>
#include<algorithm>
#include<fstream>
#include"options/log.h"
#include"hash.h"
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
static int int_2byte(const uint8_t *p)
{
	return 0x100 * *p + *(p+1);
}
template<class S> static std::string struct2str(const S &s)
{
	return std::string{(const char*)&s, sizeof(s)};
}
static string init_certificate()
{//this will run before main -> use for initialization
	ifstream f2("key.pem");//generated with openssl genrsa 2048 > key.pem
	ifstream f("cert.pem");//openssl req -x509 -days 1000 -new -key key.pem -out cert.pem
	auto [K, e, d] = get_keys(f2);
	zK = K; ze = e; zd = d;
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

	return {r.begin(), r.end()};
}
template<bool SV> string TLS<SV>::certificate_ = init_certificate();
template<bool SV> RSA TLS<SV>::rsa_{ze, zd, zK};
template class TLS<true>;//server
template class TLS<false>;//client

template<bool SV> TLS<SV>::TLS(unsigned char* buffer)
{//buffer = read buffer, buffer2 = write buffer
	rec_received_ = buffer;
	mpz2bnd(random_prime(32), session_id_.begin(), session_id_.end());
}
template<bool SV> bool TLS<SV>::support_dhe()
{
	return static_cast<bool>(dhe_);
}
template<bool SV> bool TLS<SV>::is_tls12()
{
	return tls12_;
}
template<bool SV>
pair<int, int> TLS<SV>::get_content_type(const string &s)
{
	if(s != "") rec_received_ = s.data();
	uint8_t *p = (uint8_t*)rec_received_;
	return {p[0], p[5]};
}
template<bool SV>
void TLS<SV>::generate_signature(unsigned char* p_length, unsigned char* sign)
{
	unsigned char a[64 + 3 * DH_KEY_SZ + 6];
	memcpy(a, client_random_.data(), 32);
	memcpy(a + 32, server_random_.data(), 32);
	if(dhe_) memcpy(a + 64, p_length, 6 + 3 * DH_KEY_SZ);
	else memcpy(a + 64, p_length, 36);
	//		auto b = server_mac_.hash(a, a + 70 + 3 * DH_KEY_SZ);
	SHA512 sha;
	array<uint8_t, 64> b;
	if(dhe_) b = sha.hash(a, a + 70 + 3 * DH_KEY_SZ);
	else b = sha.hash(a, a + 64 + 36);
	std::deque<unsigned char> dq{b.begin(), b.end()};
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
	mpz2bnd(z, sign, sign + 256);
}

template<bool SV>
array<unsigned char, KEY_SZ> TLS<SV>::derive_keys(mpz_class premaster_secret)
{
	unsigned char pre[DH_KEY_SZ * 2], rand[64];
	int sz = mpz_sizeinbase(premaster_secret.get_mpz_t(), 16);
	LOGD << "premaster : 0x" << hex << premaster_secret << endl;
	if(sz % 2) sz++;
	sz /= 2;
	assert(DH_KEY_SZ * 2 >= sz);
	mpz2bnd(premaster_secret, pre, pre + sz);
	PRF<SHA256> prf;
	prf.secret(pre, pre + sz);
	memcpy(rand, client_random_.data(), 32);
	memcpy(rand + 32, server_random_.data(), 32);
	prf.seed(rand, rand + 64);
	prf.label("master secret");
	master_secret_ = prf.get_n_byte(48);
	LOGD << hexprint("master secret", master_secret_) << endl;//ok
	prf.secret(master_secret_.begin(), master_secret_.end());
	memcpy(rand, server_random_.data(), 32);
	memcpy(rand + 32, client_random_.data(), 32);
	prf.seed(rand, rand + 64);
	LOGD << hexprint("server random", server_random_) << endl;
	LOGD << hexprint("client random", client_random_) << endl;
	prf.label("key expansion");
	std::array<unsigned char, KEY_SZ> r;
	auto v = prf.get_n_byte(KEY_SZ);
	for(int i=0; i<KEY_SZ; i++) r[i] = v[i];
	LOGD << hexprint("expanded keys", r) << endl;
	return r;
}
/*********
To generate the key material, compute
key_block = PRF(SecurityParameters.master_secret,
"key expansion",
SecurityParameters.server_random +
SecurityParameters.client_random);
until enough output has been generated.
 Then, the key_block is
partitioned as follows:
client_write_MAC_key[SecurityParameters.mac_key_length]
server_write_MAC_key[SecurityParameters.mac_key_length]
client_write_key[SecurityParameters.enc_key_length]
server_write_key[SecurityParameters.enc_key_length]
client_write_IV[SecurityParameters.fixed_iv_length]
server_write_IV[SecurityParameters.fixed_iv_length]
Currently, the client_write_IV and server_write_IV are only generated
for implicit nonce techniques as described in Section 3.2.1 of
[AEAD].
Implementation note: The currently defined cipher suite which
requires the most material is AES_256_CBC_SHA256. It requires 2 x 32
byte keys and 2 x 32 byte MAC keys, for a total 128 bytes of key
material.
************/
template<bool SV>
array<unsigned char, KEY_SZ> TLS<SV>::use_key(array<unsigned char, KEY_SZ> keys)
{
	unsigned char *p = keys.data();
	mac_[0]->key(p, 20);
	mac_[1]->key(p + 20, 20);
	if constexpr(SV) {
		cipher_->dec_key(p + 40);//AES128 key size 16
		cipher_->enc_key(p + 56);
	} else {
		cipher_->enc_key(p + 40);
		cipher_->dec_key(p + 56);
	}
	return keys;
}
/******
 Then, the key_block is
partitioned as follows:
client_write_MAC_key[SecurityParameters.mac_key_length] 20
server_write_MAC_key[SecurityParameters.mac_key_length]
client_write_key[SecurityParameters.enc_key_length] 16
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

#pragma pack(1)
struct TLS_header {
	uint8_t content_type = 0x16;  // 0x17 for Application Data, 0x16 handshake
	uint8_t version[2] = {0x03, 0x03};      // 0x0303 for TLS 1.2
	uint8_t length[2] = {0, 4};       //length of encrypted_data, 4 : handshake size
	void set_length(int k) { length[0] = k / 0x100; length[1] = k % 0x100; }
	int get_length() { return length[0] * 0x100 + length[1]; }
} ;
/*********************************
Record Protocol format

The TLS Record header comprises three fields, necessary to allow the higher layer to be built upon it:

    Byte 0: TLS record type

    Bytes 1-2: TLS version (major/minor)

    Bytes 3-4: Length of data in the record (excluding the header itself). The maximum supported is 16384 (16K).

             record type (1 byte)
            /
           /    version (1 byte major, 1 byte minor)
          /    /
         /    /         length (2 bytes)
        /    /         /
     +----+----+----+----+----+
     |    |    |    |    |    |
     |    |    |    |    |    | TLS Record header
     +----+----+----+----+----+


     Record Type Values       dec      hex
     -------------------------------------
     CHANGE_CIPHER_SPEC        20     0x14
     ALERT                     21     0x15
     HANDSHAKE                 22     0x16
     APPLICATION_DATA          23     0x17


     Version Values            dec     hex
     -------------------------------------
     SSL 3.0                   3,0  0x0300
     TLS 1.0                   3,1  0x0301
     TLS 1.1                   3,2  0x0302
     TLS 1.2                   3,3  0x0303
 *********************/
struct Handshake_header {
	uint8_t handshake_type;
	uint8_t length[3] = {0,0,0};
	void set_length(int k) {
		length[0] = k / 0x10000;
		length[1] = (k % 0x10000) / 0x100;
		length[2] = k % 0x100;
	}
	int get_length() { return length[0] * 0x10000 + length[1] * 0x100 + length[0]; }
} ;
/***********************
Handshake Protocol format

This is the most complex subprotocol within TLS. The specification focuses primarily on this, since it handles all the machinery necessary to establish a secure connection. The diagram below shows the general structure of Handshake Protocol messages. There are 10 handshake message types in the TLS specification (not counting extensions), so the specific format of each one will be described below.

                           |
                           |
                           |
         Record Layer      |  Handshake Layer
                           |                                  |
                           |                                  |  ...more messages
  +----+----+----+----+----+----+----+----+----+------ - - - -+--
  | 22 |    |    |    |    |    |    |    |    |              |
  |0x16|    |    |    |    |    |    |    |    |message       |
  +----+----+----+----+----+----+----+----+----+------ - - - -+--
    /               /      | \    \----\-----\                |
   /               /       |  \         \
  type: 22        /        |   \         handshake message length
                 /              type
                /
           length: arbitrary (up to 16k)


   Handshake Type Values    dec      hex
   -------------------------------------
   HELLO_REQUEST              0     0x00
   CLIENT_HELLO               1     0x01
   SERVER_HELLO               2     0x02
   CERTIFICATE               11     0x0b
   SERVER_KEY_EXCHANGE       12     0x0c
   CERTIFICATE_REQUEST       13     0x0d
   SERVER_DONE               14     0x0e
   CERTIFICATE_VERIFY        15     0x0f
   CLIENT_KEY_EXCHANGE       16     0x10
   FINISHED                  20     0x14
*******************/
struct Hello_header {
	uint8_t version[2] = {0x03, 0x03};//length is from here
	uint8_t random[32];
	uint8_t session_id_length = 32;
	uint8_t session_id[32];
};
template<bool SV> void TLS<SV>::set_buf(void* p)
{
	rec_received_ = p;
}
template<bool SV> string TLS<SV>::accumulate(string s)
{
	accumulated_handshakes_ += s.substr(sizeof(TLS_header));
	return s;
}
template<bool SV> void TLS<SV>::accumulate()
{//working with buffer version
	TLS_header *p = (TLS_header*)rec_received_;
	char *q = (char*)rec_received_;
	accumulated_handshakes_ += string{q + sizeof(TLS_header),
									q + sizeof(TLS_header) + p->get_length()};
}
template<bool SV>
template<class D,class A,template<int> class C,int B,template<class> class M,class H>
void TLS<SV>::set_cipher() {//Auth is not implemented yet
	if(std::is_same<DHE, D>::value) {
		dhe_ = std::make_unique<DHE>();
		ecdhe_ = nullptr;//v !ecdhe_:for client side server hello
	} else if(std::is_same<D, ECDHE>::value && !ecdhe_)
		ecdhe_ = std::make_unique<ECDHE>();
	cipher_ = std::make_unique<M<C<B>>>();
	mac_[0] = std::make_unique<HMAC<H>>();
	mac_[1] = std::make_unique<HMAC<H>>();
	hkdf_ = make_unique<HKDF<H>>();
	hash_code_ = typeid(H).hash_code();
	LOGI << "using " << typeid(D).name() << typeid(A).name() << typeid(C<B>).name()
		<< B << typeid(M<C<B>>).name() << typeid(H).name() << endl;
}
template<bool SV> void TLS<SV>::allocate_cipher(uint8_t a, uint8_t b) 
{//CHACHA case : CBC or GCM does not take effect
	selected_cipher_suite[0] = a;
	selected_cipher_suite[1] = b;
	switch(a*0x100 + b) {
		case 0x0016: set_cipher<DHE, RSA, DES3, 0, CBC, SHA1>(); break;
		case 0x002F: set_cipher<void, RSA, AES, 128, CBC, SHA1>(); break;
		case 0x0033: set_cipher<DHE, RSA, AES, 128, CBC, SHA1>(); break;
		case 0x0039: set_cipher<DHE, RSA, AES, 256, CBC, SHA1>(); break;
		case 0x0045: set_cipher<DHE, RSA, Camellia, 128, CBC, SHA1>(); break;
		case 0x0067: set_cipher<DHE, RSA, AES, 128, CBC, SHA256>(); break;
		case 0x006B: set_cipher<DHE, RSA, AES, 256, CBC, SHA256>(); break;
		case 0x0088: set_cipher<DHE, RSA, Camellia, 256, CBC, SHA1>(); break;
		case 0x009E: set_cipher<DHE, RSA, AES, 128, GCM, SHA256>(); break;
		case 0x009F: set_cipher<DHE, RSA, AES, 256, GCM, SHA384>(); break;
		case 0x00BE: set_cipher<DHE, RSA, Camellia, 128, CBC, SHA256>(); break;
		case 0x00C4: set_cipher<DHE, RSA, Camellia, 256, CBC, SHA256>(); break;
		case 0xC012: set_cipher<ECDHE, RSA, DES3, 0, CBC, SHA1>(); break;
		case 0xC013: set_cipher<ECDHE, RSA, AES, 128, CBC, SHA1>(); break;
		case 0xC014: set_cipher<ECDHE, RSA, AES, 256, CBC, SHA1>(); break;
		case 0xC027: set_cipher<ECDHE, RSA, AES, 128, CBC, SHA256>(); break;
		case 0xC028: set_cipher<ECDHE, RSA, AES, 256, CBC, SHA384>(); break;
		case 0xC02F: set_cipher<ECDHE, RSA, AES, 128, GCM, SHA256>(); break;
		case 0xC030: set_cipher<ECDHE, RSA, AES, 256, GCM, SHA384>(); break;
		case 0xC076: set_cipher<ECDHE, RSA, Camellia, 128, CBC, SHA256>(); break;
		case 0xC077: set_cipher<ECDHE, RSA, Camellia, 256, CBC, SHA384>(); break;
		case 0xC07C: set_cipher<DHE, RSA, Camellia, 128, GCM, SHA256>(); break;
		case 0xC07D: set_cipher<DHE, RSA, Camellia, 256, GCM, SHA384>(); break;
		case 0xC08A: set_cipher<ECDHE, RSA, Camellia, 128, GCM, SHA256>(); break;
		case 0xC08B: set_cipher<ECDHE, RSA, Camellia, 256, GCM, SHA384>(); break;
		case 0xCCA8: set_cipher<ECDHE, RSA, DES3, 0, CHACHA, SHA256>(); break;//DES no
		case 0xCCAA: set_cipher<DHE, RSA, DES3, 0, CHACHA, SHA256>(); break;//effect
	}
}
template<bool SV> bool TLS<SV>::process_extension(uint8_t *p)
{//only used in server, return true if tls1.3 agreed
	struct Ext {
		uint8_t type[2];
		uint8_t length[2];
		uint8_t list_length[2];
		uint8_t data[];
	} *q;
	int total_length = int_2byte(p), len;
	p += 2;
	uint8_t *start = p;
	bool check[4] = {false,};//x25519, no compress, hash, key
	while(p < start + total_length) {
		q = (Ext*)p;
		int ll = int_2byte(q->list_length);
		switch(int_2byte(q->type)) {
		case 10: //ffdh2048, curve x25519
			for(int i=0; i<ll; i+=2) {
				if(q->data[i] == 1 && q->data[i+1] == 0) {
					dhe_ = make_unique<DHE>();
					break;
				}
				if(q->data[i] == 0 && q->data[i+1] == 0x1d) {
					ecdhe_ = make_unique<ECDHE>();
					break;
				}
			}
			if(dhe_ || ecdhe_) check[0] = true;
			break;
		case 11: //format no compress
			if(!q->list_length[1]) check[1] = true;
			else for(int i=0; i<q->list_length[0]-1; i++)
					if(!q->data[i]) check[1] = true;
			break;
		case 13://signature algorithm sha512 rsa
			for(int i=0; i<ll; i+=2) 
				if(q->data[i] == 6 && q->data[i+1] == 1) check[2] = true;
		case 51: //key
			int to_find;
			if(ecdhe_) to_find = 0x1d;
			else to_find = 0x100;
			for(int i=0; i<ll;) {
				if(int_2byte(q->data + i) == to_find) {//x25519, ffdh2048
					if(ecdhe_) ecdhe_->set_Q(bnd2mpz(q->data + i + 4,
								q->data + i + 4 + int_2byte(q->data + 2)));
					else dhe_->set_yb(bnd2mpz(q->data + i + 4,
								q->data + i + 4 + int_2byte(q->data + 2)));
					check[3] = true;
					break;
				} else i += int_2byte(q->data + 2) + 4;//advance 
			}
			break;
		case 41://psk
			{
				uint8_t psk[32] = {0,};
				break;
			}
		default: break;
		}
		p += int_2byte(q->length) + 4;
	}
	for(int i=0; i<4; i++) if(!check[i]) return false;
	return true;
}

template<bool SV> string TLS<SV>::client_hello(string&& s)
{//return desired id
	struct H {
		TLS_header h1;
		Handshake_header h2;
		Hello_header h3;
		uint8_t cipher_suite_length[2] = {0, 12};
		uint8_t cipher_suite[12] = {
			0xC0,0x2F,//TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256                      
			0xC0,0x30,//TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384                      
			0x00,0x9E,//TLS_DHE_RSA_WITH_AES_128_GCM_SHA256                        
			0x00,0x9F,//TLS_DHE_RSA_WITH_AES_256_GCM_SHA384                        
			0xCC,0xA8,//TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256    
			0xCC,0xAA//TLS_DHE_RSA_WITH_CHACHA20_POLY1305_SHA256 
/*			0x00,0x33,//TLS_DHE_RSA_WITH_AES_128_CBC_SHA                           
//			0x00,0x39,//TLS_DHE_RSA_WITH_AES_256_CBC_SHA                           
//			0x00,0x67,//TLS_DHE_RSA_WITH_AES_128_CBC_SHA256                        
//			0x00,0x6B,//TLS_DHE_RSA_WITH_AES_256_CBC_SHA256                        
//			0x00,0x45,//TLS_DHE_RSA_WITH_CAMELLIA_128_CBC_SHA                      
//			0x00,0x88,//TLS_DHE_RSA_WITH_CAMELLIA_256_CBC_SHA                      
//			0x00,0xBE,//TLS_DHE_RSA_WITH_CAMELLIA_128_CBC_SHA256                   
//			0x00,0xC4,//TLS_DHE_RSA_WITH_CAMELLIA_256_CBC_SHA256                   
//			0xC0,0x7C,//TLS_DHE_RSA_WITH_CAMELLIA_128_GCM_SHA256                   
//			0xC0,0x7D,//TLS_DHE_RSA_WITH_CAMELLIA_256_GCM_SHA384                   
//			0x00,0x16,//TLS_DHE_RSA_WITH_3DES_EDE_CBC_SHA                          
//			0xC0,0x13,//TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA                         
//			0xC0,0x14,//TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA                         
//			0xC0,0x27,//TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256                      
//			0xC0,0x28,//TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384                      
//			0xC0,0x76,//TLS_ECDHE_RSA_WITH_CAMELLIA_128_CBC_SHA256                 
//			0xC0,0x77,//TLS_ECDHE_RSA_WITH_CAMELLIA_256_CBC_SHA384                 
//			0xC0,0x8A,//TLS_ECDHE_RSA_WITH_CAMELLIA_128_GCM_SHA256                 
//			0xC0,0x8B,//TLS_ECDHE_RSA_WITH_CAMELLIA_256_GCM_SHA384                 
//			0xC0,0x12,//TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA        
//			0x00,0x2F//TLS_RSA_AES_128_SHA */
		};
		uint8_t compression_length = 1;
		uint8_t compression_method = 0;//none

		uint8_t extension_length[2] = {1, 81};

		uint8_t supported_group[2] = {0, 10};//type
		uint8_t supported_group_length[2] = {0, 6};//length
		uint8_t support_group_list_length[2] = {0, 4};
		uint8_t ffdh2048_x25519[4] = {1, 0, 0, 0x1d};
		
		uint8_t ec_point_format[2] = {0, 11};//type
		uint8_t ec_point_format_length[2] = {0, 2};//length
		uint8_t ec_length = 1;
		uint8_t non_compressed = 0;

		uint8_t key_share[2] = {0, 51};//type
		uint8_t key_share_length[2] = {1, 42};//length
		uint8_t client_key_share_len[2] = {1, 40};
		uint8_t ffdhe[2] = {1, 0};
		uint8_t ffdhe_key_length[2] = {1, 0};
		uint8_t ffdhe_key[256];
		uint8_t x25519_key[2] = {0, 0x1d};
		uint8_t key_length[2] = {0, 32};
		uint8_t key[32];

		uint8_t supported_version[2] = {0, 0x2b};
		uint8_t supported_version_length[2] = {0, 5};
		uint8_t supported_version_list_length = 4;
		uint8_t supported_versions[4] = {3, 4, 3, 3};//TLS 1.3, TLS 1.2

		uint8_t psk_mode[2] = {0, 0x2d};
		uint8_t psk_mode_length[2] = {0, 2};
		uint8_t psk_mode_llength = 1;
		uint8_t psk_with_ecdhe = 1;
	} r;

	if constexpr(!SV) {//if client
		set_buf(&r);
		r.h2.handshake_type = 1;
		r.h1.set_length(sizeof(H) - sizeof(TLS_header));
		r.h2.set_length(sizeof(H) - sizeof(TLS_header) - sizeof(Hello_header));
		mpz2bnd(random_prime(32), r.h3.random, r.h3.random + 32);
		memcpy(client_random_.data(), r.h3.random, 32);//unix time + 28 random
		dhe_ = make_unique<DHE>();
		ecdhe_ = make_unique<ECDHE>();
		mpz2bnd(dhe_->ya, r.ffdhe_key, r.ffdhe_key + 256);
		mpz2bnd(ecdhe_->Q, r.key, r.key + 32);
	} else {//server
		if(s != "") set_buf(s.data());
		if(get_content_type() != pair{HANDSHAKE, CLIENT_HELLO}) return alert(2, 10);
		H *p = (H*)rec_received_;
		memcpy(client_random_.data(), p->h3.random, 32);//unix time + 28 random
		int len = int_2byte(p->cipher_suite_length);
		for(int i=0; i<int_2byte(r.cipher_suite_length); i+=2) {
			auto it = search(p->cipher_suite, p->cipher_suite + len,
					r.cipher_suite + i, r.cipher_suite + i + 1);
			if(it != p->cipher_suite + len && (it - p->cipher_suite) % 2 == 0) {
				allocate_cipher(r.cipher_suite[i], r.cipher_suite[i + 1]);
				break;
			}
		}

		uint8_t *up = p->cipher_suite;//v ext
		up += 2 + int_2byte(p->cipher_suite_length);
		if(!process_extension(up)) tls12_ = true;
			//return alert(2, 40);//ecdhe handshake failed
		else use_key(derive_keys(ecdhe_ ? ecdhe_->K : dhe_->K));
	}
	accumulate();

	uint8_t p[32] = {0,};
	hkdf_->no_salt();
	psk_key_schedule_["early secret"] = hkdf_->extract(p, 32);
	psk_key_schedule_["binder key"] = hkdf_->derive_secret("ext binderres binder", "");
	psk_key_schedule_["c e traffic"] = hkdf_->derive_secret("c e traffic",
			accumulated_handshakes_);
	psk_key_schedule_["e exp master"] = hkdf_->derive_secret( "e exp master",
			accumulated_handshakes_);
	
	if constexpr(SV) return struct2str(r);
	else return "";
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
template<bool SV> string TLS<SV>::server_hello(string &&s)
{
	struct H {
		TLS_header h1;
		Handshake_header h2;
		Hello_header h3;
		uint8_t cipher_suite[2] = {0x00, 0x2f};
		uint8_t compression = 0;
		uint8_t extension_length[2] = {0, 0};

		uint8_t supported_version[2] = {0, 0x2b};
		uint8_t supported_version_length[2] = {0, 4};
		uint8_t support[4] = {3, 4, 3, 3};

		uint8_t key_share[2] = {0, 0x33};
		uint8_t key_share_length[2] = {};
		uint8_t type[2];
		uint8_t key_value[];
	} r;
	if constexpr(SV) { 
		set_buf(&r);
		r.cipher_suite[0] = selected_cipher_suite[0];
		r.cipher_suite[1] = selected_cipher_suite[1];
		r.h1.length[1] = sizeof(Hello_header) + sizeof(Handshake_header) + 3;
		r.h2.length[2] = sizeof(Hello_header) + 3;
		r.h2.handshake_type = 2;
		mpz2bnd(random_prime(32), server_random_.begin(), server_random_.end());
		memcpy(r.h3.random, server_random_.data(), 32);
//		memcpy(r.h3.session_id, session_id_.data(), 32);
	} else {
		if(s != "") set_buf(s.data());
		if(get_content_type() != pair{HANDSHAKE, SERVER_HELLO}) 
			return alert(2, 10);
		H *p = (H*)rec_received_;
		memcpy(server_random_.data(), p->h3.random, 32);
		memcpy(session_id_.data(), p->h3.session_id, 32);
		allocate_cipher(p->cipher_suite[0], p->cipher_suite[1]);
	}
	accumulate();
	if(!is_tls12()) {
		auto v = psk_key_schedule_["early secret"];
		hkdf_->salt(&v[0], v.size());
		v = psk_key_schedule_["derived"] = hkdf_->derive_secret("derived", "");
		hkdf_->salt(&v[0], v.size());
		uint8_t key[256];
		if(dhe_) mpz2bnd(dhe_->K, key, key + 256);
		else mpz2bnd(ecdhe_->K, key, key + 32);
		v=psk_key_schedule_["handshake secret"]=hkdf_->extract(key, dhe_ ? 256 : 32);
		hkdf_->salt(&v[0], v.size());
		psk_key_schedule_["c hs traffic"] = hkdf_->derive_secret("c hs traffic",
				accumulated_handshakes_);
		psk_key_schedule_["s hs traffic"] = hkdf_->derive_secret("s hs traffic", 
				accumulated_handshakes_);

		v = psk_key_schedule_["derived"] = hkdf_->derive_secret("derived", "");
		hkdf_->salt(&v[0], v.size());
		for(int i=0; i<256; i++) key[i] = 0;
		v = psk_key_schedule_["master secret"] = hkdf_->extract(key, dhe_ ? 256 : 32);
	}
	if(SV) return struct2str(r);
	else return "";
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
template<bool SV> string TLS<SV>::server_certificate(string&& s)
{
	if constexpr(SV) return accumulate(certificate_);
	else {
		if(s != "") set_buf(s.data());
		if(get_content_type() != pair{HANDSHAKE, CERTIFICATE}) 
			return alert(2, 10);
		accumulate();
		struct H {
			TLS_header h1;
			Handshake_header h2;
			uint8_t certificate_length[2][3];
			unsigned char certificate[];
		} *p = (H*)rec_received_;
		std::stringstream ss;
		uint8_t *q = p->certificate_length[1];
		for(int i=0; i < *q * 0x10000 + *(q+1) * 0x100 + *(q+2); i++) 
			ss << std::noskipws << p->certificate[i];//first certificate
		auto jv = der2json(ss);
		auto [K, e, sign] = get_pubkeys(jv);

		LOGD << "K : " << K << endl;
		LOGD << "e : " << e << endl;
		LOGD << "sign : " << sign << endl;
//		*plog << jv << std::endl << std::hex << powm(sign, e, K) << std::endl;
		rsa_.K = K; rsa_.e = e;
		return "";
	}
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
template<bool SV> string TLS<SV>::ecdhe_server_key_exchange(string &&s)
{
	struct H {
		TLS_header h1;
		Handshake_header h2;
		uint8_t named_curve = 3, x25519[2] = {0, 0x1d};
		uint8_t pubkey_len = 32, key[32];
		uint8_t signature_hash = 6, signature_sign = 1;
		uint8_t signature_length[2] = {1, 0}, sign[256];
	} r;

	if constexpr(SV) {
		r.h1.set_length(sizeof(H) - sizeof(TLS_header));
		r.h2.set_length(sizeof(H)-sizeof(TLS_header)-sizeof(Handshake_header));
		r.h2.handshake_type = 12;
		mpz2bnd(ecdhe_->Q, r.key, r.key + 32);
		generate_signature(&r.named_curve, r.sign);
		return accumulate(struct2str(r));
	} else {
		if(s != "") set_buf(s.data());
		if(get_content_type() != pair{HANDSHAKE, SERVER_KEY_EXCHANGE})
			return alert(2, 10);
		accumulate();
		const uint8_t *ptr = static_cast<const H*>(rec_received_)->key;
		ecdhe_->set_Q(bnd2mpz(ptr, ptr + 32));
		use_key(derive_keys(ecdhe_->K));
		return "";
	}
}
template<bool SV> string TLS<SV>::server_key_exchange(string &&s)
{
	if(ecdhe_) return ecdhe_server_key_exchange(move(s));
	else return dhe_server_key_exchange(move(s));
}
template<bool SV> string TLS<SV>::dhe_server_key_exchange(string&& s)
{
	struct H {
		TLS_header h1;
		Handshake_header h2;
		uint8_t p_length[2] = {DH_KEY_SZ / 0x100, DH_KEY_SZ % 0x100}, p[DH_KEY_SZ],
		g_length[2] = {DH_KEY_SZ / 0x100, DH_KEY_SZ % 0x100}, g[DH_KEY_SZ],
		ya_length[2] = {DH_KEY_SZ / 0x100, DH_KEY_SZ % 256}, ya[DH_KEY_SZ];
		uint8_t signature_hash = 6, //SHA512
				signature_sign = 1, //rsa
				signature_length[2] = {1, 0}, sign[256];
//enum { none(0), md5(1), sha1(2), sha224(3), sha256(4), sha384(5), sha512(6), (255) } HashAlgorithm;
// enum { anonymous(0), rsa(1), dsa(2), ecdsa(3), (255) } SignatureAlgorithm;
	} r;

	if constexpr(SV) {
		r.h1.set_length(sizeof(H) - sizeof(TLS_header));
		r.h2.set_length(sizeof(H) - sizeof(TLS_header) - sizeof(Handshake_header));
		r.h2.handshake_type = 12;
		mpz2bnd(dhe_->p, r.p, r.p + DH_KEY_SZ);
		mpz2bnd(dhe_->g, r.g, r.g + DH_KEY_SZ);
		mpz2bnd(dhe_->ya, r.ya, r.ya + DH_KEY_SZ);
		generate_signature(r.p_length, r.sign);
		return accumulate(struct2str(r));
	} else {
		if(s != "") set_buf(s.data());
		if(get_content_type() != pair{HANDSHAKE, SERVER_KEY_EXCHANGE})
			return alert(2, 10);
		accumulate();
		const uint8_t *ptr_keys = static_cast<const H*>(rec_received_)->p_length;
		mpz_class pgya[3];
		for(int i=0, key_length; i<3; ptr_keys += key_length + 2, i++) {
			key_length = int_2byte(ptr_keys);
			pgya[i] = bnd2mpz(ptr_keys + 2, ptr_keys + 2 + key_length);
		}
		dhe_ = make_unique<DHE>(pgya[0], pgya[1], pgya[2]);
		use_key(derive_keys(dhe_->K));
		return "";
	}	
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
template<bool SV> string TLS<SV>::server_hello_done(string&& s)
{
	struct {
		TLS_header h1;
		Handshake_header h2;
	} r;
	if constexpr(SV) {
		r.h2.handshake_type = 14;
		return accumulate(struct2str(r));
	} else {
		if(s != "") set_buf(s.data());
		if(get_content_type() != pair{HANDSHAKE, SERVER_DONE}) return "error";
		accumulate();
		return "";
	}
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
template<bool SV> string TLS<SV>::change_cipher_spec(string &&s)
{
	struct {
		TLS_header h1;
		uint8_t spec = 1;
	} r;
	r.h1.content_type = 20;
	r.h1.length[1] = 1;
	return struct2str(r);
}

template<bool SV> string TLS<SV>::client_key_exchange(string&& s)//16
{//return client_aes_key + server_aes_key
	struct H {
		TLS_header h1;
		Handshake_header h2;
		uint8_t key_sz[2] = {1, 0};
		uint8_t pub_key[];
	} r;

	mpz_class premaster_secret;
	if constexpr(SV) {
		if(s != "") set_buf(s.data());
		if(get_content_type() != pair{HANDSHAKE, CLIENT_KEY_EXCHANGE}) 
			return alert(2, 10);
		accumulate();
		H* p = (H*)rec_received_;
		assert(p->h2.handshake_type == 16);
		if(dhe_) premaster_secret = 
			dhe_->set_yb(bnd2mpz(p->pub_key, p->pub_key + int_2byte(p->key_sz)));
		else premaster_secret =
			ecdhe_->set_Q(bnd2mpz(p->pub_key, p->pub_key + int_2byte(p->key_sz)));
		auto a = use_key(derive_keys(premaster_secret));
		return "";
	} else {
		r.h2.handshake_type = 16;
		string pub_key{dhe_ ? DH_KEY_SZ : 32};//init with size bug
		if(dhe_) mpz2bnd(dhe_->yb, pub_key.begin(), pub_key.end());
		else mpz2bnd(ecdhe_->Q, pub_key.begin(), pub_key.end());
		r.h1.set_length(sizeof(Handshake_header) + 2 + pub_key.size());
		r.h2.set_length(2 + pub_key.size());
		return accumulate(struct2str(r)) + pub_key; 
	}
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
template<bool SV> string TLS<SV>::decode(string &&s)
{
	if(s != "") rec_received_ = s.data();
	struct H {
		TLS_header h1;
		uint8_t iv[16];
		unsigned char m[];
	} *p = (H*)rec_received_;
	struct {
		uint8_t seq[8];
		TLS_header h1;
	} header_for_mac;
	cipher_->dec_iv(p->iv);
	auto decrypted = cipher_->decrypt(p->m, p->h1.get_length() - 16);//here key value is changed(the other key?)
	LOGD << hexprint("decrypted", decrypted) << endl;
	assert(decrypted.size() > decrypted.back());
	decrypted.resize(decrypted.size() - decrypted.back() - 1);//remove padding
	string content{decrypted.begin(), decrypted.end() - 20};

	mpz2bnd(dec_seq_num_++, header_for_mac.seq, header_for_mac.seq + 8);
	header_for_mac.h1 = p->h1;
	header_for_mac.h1.set_length(content.size());
	string t = struct2str(header_for_mac) + content;
	auto auth = mac_[!SV]->hash((const uint8_t*)&*t.begin(), t.size());//verify auth
	if(equal(auth.rbegin(), auth.rend(), decrypted.rbegin())) 
		LOGI << "mac verified" << endl;
	else LOGE << "mac verification failed" << endl;
	return content;
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
template<bool SV> string TLS<SV>::encode(string &&s, int type)
{
	struct {
		TLS_header h1;
		uint8_t iv[16];
	} header_to_send;
	struct {
		uint8_t seq[8];
		TLS_header h1;
	} header_for_mac;
	header_for_mac.h1.content_type = header_to_send.h1.content_type = type;

	mpz2bnd(enc_seq_num_++, header_for_mac.seq, header_for_mac.seq + 8);
	const size_t chunk_size = (1 << 14) - 64;//cut string into 2^14
	int len = min(s.size(), chunk_size);
	int block_len = ((len + 20) / 16 + 1) * 16;//20 = sha1 digest, 16 block sz
	header_for_mac.h1.set_length(len);
	string frag = s.substr(0, len);
	string s2 = struct2str(header_for_mac) + frag;
	auto verify = mac_[SV]->hash((const uint8_t*)&*s2.begin(), s2.size());
	LOGD << hexprint("mac verify", verify) << endl;
	frag += string{verify.begin(), verify.end()};//add authentication
	while(frag.size() != block_len) frag += (char)(block_len - len - 21);//padding

	mpz2bnd(random_prime(16), header_to_send.iv, header_to_send.iv + 16);
	cipher_->enc_iv(header_to_send.iv);
	auto encrypted = cipher_->encrypt((const uint8_t*)&*frag.begin(), frag.size());
	header_to_send.h1.set_length(sizeof(header_to_send.iv) + encrypted.size());
	s2 = struct2str(header_to_send) + string{encrypted.begin(), encrypted.end()};
	LOGT << hexprint("sending", s2) << endl;
	if(s.size() > chunk_size)//finished does not exceed chunk size, so no type needed
		s2 += encode(s.substr(chunk_size));
	return s2;
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
template<bool SV> string TLS<SV>::finished(string &&s)
{//finished message to send(s == "") and receive(s == recv())
	PRF<SHA256> prf; SHA256 sha;
	prf.secret(master_secret_.begin(), master_secret_.end());
	auto h = sha.hash(accumulated_handshakes_.cbegin(), accumulated_handshakes_.cend());
	prf.seed(h.begin(), h.end());
	const char *label[2] = {"client finished", "server finished"};
	prf.label(label[++finish_msg_count_]);
	auto v = prf.get_n_byte(12);
	LOGD << hexprint("finished", v) << endl;

	Handshake_header hh;
	hh.handshake_type = 0x14;//finished
	hh.set_length(12);
	
	string msg = struct2str(hh) + string{v.begin(), v.end()};
	accumulated_handshakes_ += msg;

	if(!is_tls12()) {
		v = psk_key_schedule_["master secret"];//reuse v
		hkdf_->salt(&v[0], v.size());
		psk_key_schedule_["c ap traffic"] = 
			hkdf_->derive_secret("c ap traffic", accumulated_handshakes_);
		psk_key_schedule_["s ap traffic"] = 
			hkdf_->derive_secret("s ap traffic", accumulated_handshakes_);
		psk_key_schedule_["exp master"] = 
			hkdf_->derive_secret("exp master", accumulated_handshakes_);
		psk_key_schedule_["res master"] = 
			hkdf_->derive_secret("res master", accumulated_handshakes_);
	}

	if(SV == finish_msg_count_) return encode(move(msg), 0x16);
	if(decode(move(s)) != msg) return alert(2, 51);
	else return "";
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

change cipher spec after
The Finished messages have contents which are computed with, again, the PRF.
The contents of the Finished message are 12 bytes obtained by invoking the PRF with, as "secret" input, the master secret; the "seed" is the hash of all previous handshake messages.
The "label" differs depending on who, between the client and the server, sends that specific Finished message.
Since the Finished messages are sent after the ChangeCipherSpec, they are encrypted and MACed, using the algorithms and keys which have just been negotiated.
In that sense, the keys and nonces (the client and server randoms) are involved multiple times.
 *********************/
template<bool SV> string TLS<SV>::alert(uint8_t level, uint8_t desc)
{//encrypted send => encode(alert(2, 20).substr(sizeof(TLS_header)), 0x15)
	struct {
		TLS_header h1;
		uint8_t alert_level;
		uint8_t alert_desc;
	} h;
	h.h1.content_type = 0x15;
	h.alert_level = level;
	h.alert_desc = desc;
	h.h1.set_length(2);
	return struct2str(h);
}
template<bool SV> int TLS<SV>::alert(string &&s)
{//alert received
	if(s != "") rec_received_ = s.data();
	struct H {
		TLS_header h1;
		uint8_t alert_level;
		uint8_t alert_desc;
	} *p = (H*)rec_received_;
	int level, desc;
	if(p->h1.get_length() == 2) {
		level = p->alert_level;
		desc = p->alert_desc;
	} else {//encrypted
		string s = decode();//already set data to buffer -> decode has no argument
		level = static_cast<uint8_t>(s[0]);
		desc = static_cast<uint8_t>(s[1]);
	}
	switch(desc) {//s reuse
		case 0: s = "close_notify(0)"; break;
		case 10: s = "unexpected_message(10)"; break;
		case 20: s = "bad_record_mac(20)"; break;
		case 21: s = "decryption_failed_RESERVED(21)"; break;
		case 22: s = "record_overflow(22)"; break;
		case 30: s = "decompression_failure(30)"; break;
		case 40: s = "handshake_failure(40)"; break;
		case 41: s = "no_certificate_RESERVED(41)"; break;
		case 42: s = "bad_certificate(42)"; break;
		case 43: s = "unsupported_certificate(43)"; break;
		case 44: s = "certificate_revoked(44)"; break;
		case 45: s = "certificate_expired(45)"; break;
		case 46: s = "certificate_unknown(46)"; break;
		case 47: s = "illegal_parameter(47)"; break;
		case 48: s = "unknown_ca(48)"; break;
		case 49: s = "access_denied(49)"; break;
		case 50: s = "decode_error(50)"; break;
		case 51: s = "decrypt_error(51)"; break;
		case 60: s = "export_restriction_RESERVED(60)"; break;
		case 70: s = "protocol_version(70)"; break;
		case 71: s = "insufficient_security(71)"; break;
		case 80: s = "internal_error(80)"; break;
		case 90: s = "user_canceled(90)"; break;
		case 100: s = "no_renegotiation(100)"; break;
		case 110: s = "unsupported_extension(110)"; break;
	}
	if(level == 1) LOGW << s << endl;
	else if(level == 2) LOGF << s << endl;
	return desc;
}

template<bool SV> void
TLS<SV>::handshake(function<string(void)> read_f, function<void(string)> write_f)
{
	string s;
	switch(CLIENT_HELLO) {
	case CLIENT_HELLO:
		if(s = client_hello(read_f()); s != "") {//error -> alert return
			write_f(s);					LOGE << "handshake failed" << endl;
			break;
		} else 								LOGI << "client hello" << endl;
	case SERVER_HELLO:
		s = server_hello(); 				LOGI << "server hello" << endl;
		s += is_tls12() ? //if tls13, encode starts here
			server_certificate() : encode(server_certificate(), HANDSHAKE);
											LOGI << "server certificate" << endl;
		if(is_tls12()) {
			s += server_key_exchange();	LOGI << "server key exchange" << endl;
			s += server_hello_done();		LOGI << "server hello done" << endl;
		} else s += finished();//finished is already encoded
		write_f(s);
	case CLIENT_KEY_EXCHANGE:
		if(is_tls12()) {
			if(s = client_key_exchange(read_f()); s != "") {
				write_f(s);				LOGE<<"client key exchange failed"<<endl;
				break;
			} else 							LOGI << "client key exchange" << endl;
			change_cipher_spec(read_f());LOGI << "change cipher spec" << endl;
		}
		if(s = finished(read_f()); s != "") {
			write_f(s); 					LOGE << "decrypt error" << endl;
			break;
		} else 								LOGI << "client finished" << endl;
	case CHANGE_CIPHER_SPEC:
		if(is_tls12()) {
			s = change_cipher_spec(); 	LOGI << "change cipher spec" << endl;
			s += finished(); 				LOGI << "server finished" << endl;
			write_f(s);
		}
	}
}
#pragma pack()
