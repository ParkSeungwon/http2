#pragma once
#include"crypt.h"
#pragma pack(1)
#define DH_KEY_SZ 128
#define KEY_SZ 72
/*********************
               TLS Handshake

               +-----+                              +-----+
               |     |                              |     |
               |     |        ClientHello           |     |
               |     o----------------------------> |     |
               |     |                              |     |
       CLIENT  |     |        ServerHello           |     |  SERVER
               |     |       [Certificate]          |     |
               |     |    [ServerKeyExchange]       |     |
               |     |    [CertificateRequest]      |     |
               |     |      ServerHelloDone         |     |
               |     | <----------------------------o     |
               |     |                              |     |
               |     |       [Certificate]          |     |
               |     |     ClientKeyExchange        |     |
               |     |    [CertificateVerify]       |     |
               |     |   ** ChangeCipherSpec **     |     |
               |     |         Finished             |     |
               |     o----------------------------> |     |
               |     |                              |     |
               |     |   ** ChangeCipherSpec **     |     |
               |     |         Finished             |     |
               |     | <----------------------------o     |
               |     |                              |     |
               +-----+                              +-----+



 Optional messages
 --------------------------------------------------------------------------------------------
 Certificate (server)     needed with all key exchange algorithms, except for anonymous ones.
 ServerKeyExchange        needed in some cases, like Diffie-Hellman key exchange algorithm.
 CertificateRequest       needed if Client authentication is required.
 Certificate (client)     needed in response to CertificateRequest by the server.
 CertificateVerify        needed if client Certificate message was sent.

ChangeCipherSpec Protocol: It makes the previously negotiated parameters effective, so communication becomes encrypted.

Alert Protocol: Used for communicating exceptions and indicate potential problems that may compromise security.

Application Data Protocol: It takes arbitrary data (application-layer data generally), and feeds it through the secure channel.
*******************/
struct TLS_header {
	uint8_t content_type = 0x16;  // 0x17 for Application Data, 0x16 handshake
	uint8_t version[2] = {0x03, 0x03};      // 0x0303 for TLS 1.2
	uint8_t length[2] = {0, 4};       //length of encrypted_data, 4 : handshake size
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

template<bool SV = true> class TLS
{//this class just deals with memory structure -> decoupled from underlying algorithm
public:
	TLS(unsigned char* buffer = nullptr)
	{//buffer = read buffer, buffer2 = write buffer
		rec_received_ = reinterpret_cast<TLS_header*>(buffer);
	}
	std::string decode();
	std::vector<std::string> encode(std::string s);

	int	client_finished();
	void change_cipher_spec(int);

	void set_buf(void* p) {
		rec_received_ = (TLS_header*)p;
	}

	auto client_hello()
	{//return desired id
		struct H {
			TLS_header h1;
			Handshake_header h2;
			Hello_header h3;
			uint8_t cipher_suite_length[2] = {0, 4};
			uint8_t cipher_suite[4] = {0x00, 0x33, 0x00, 0x2f};
			uint8_t compression = 0;
			uint8_t extension_length[2] = {0, 0};
		} r;
		if constexpr(!SV) {
			r.h2.handshake_type = 1;
			r.h1.length[1] = sizeof(Hello_header) + sizeof(Handshake_header) + 9;
			r.h2.length[2] = sizeof(Hello_header) + 9;
			mpz2bnd(random_prime(32), r.h3.random, r.h3.random + 32);
			memcpy(client_random_.data(), r.h3.random, 32);//unix time + 28 random
			return r;
		} else {
			H *p = (H*)rec_received_;
			memcpy(client_random_.data(), p->h3.random, 32);//unix time + 28 random
			int len = 0x100 * p->cipher_suite_length[0] + p->cipher_suite_length[1];
			for(int i=0; i<len; i++)
				if(p->cipher_suite[i] == 0x33) support_dhe_ = true;
			if(id_length_ = p->h3.session_id_length) {
				memcpy(session_id_.data(), p->h3.session_id, id_length_);
				return session_id_;
			} else return std::array<unsigned char, 32>{};
		}
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
	auto server_hello(std::array<unsigned char, 32> id = {0,}) {
		struct H {
			TLS_header h1;
			Handshake_header h2;
			Hello_header h3;
			uint8_t cipher_suite[2] = {0x00, 0x2f};
			uint8_t compression = 0;
			uint8_t extension_length[2] = {0, 0};
		} r;
		if constexpr(SV) {
			if(support_dhe_) r.cipher_suite[1] = 0x33;
			r.h1.length[1] = sizeof(Hello_header) + sizeof(Handshake_header) + 5;
			r.h2.length[2] = sizeof(Hello_header) + 5;
			r.h2.handshake_type = 2;
			mpz2bnd(random_prime(32), server_random_.begin(), server_random_.end());
			memcpy(r.h3.random, server_random_.data(), 32);
			memcpy(r.h3.session_id, id.data(), 32);
			return r;
		} else {
			H *p = (H*)rec_received_;
			memcpy(server_random_.data(), p->h3.random, 32);
			memcpy(session_id_.data(), p->h3.session_id, 32);
			if(p->cipher_suite[1] == 0x33) support_dhe_ = true;
		}
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
	auto server_certificate() {
		if constexpr(SV) return certificate_;
		else {
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
			auto [K, e, sign] = get_pubkeys(ss);
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
	auto server_key_exchange() {
		struct H {
			TLS_header h1;
			Handshake_header h2;
			uint8_t p_length[2] = {DH_KEY_SZ / 0x100, DH_KEY_SZ % 0x100}, p[DH_KEY_SZ],
					g_length[2] = {DH_KEY_SZ / 0x100, DH_KEY_SZ % 0x100}, g[DH_KEY_SZ],
					ya_length[2] = {DH_KEY_SZ / 0x100, DH_KEY_SZ % 256}, ya[DH_KEY_SZ];
			uint8_t signature_hash = 6, //SHA512
					signature_sign = 1, //rsa
					signature_length[2] = {1, 0}, sign[256];
/*enum { none(0), md5(1), sha1(2), sha224(3), sha256(4), sha384(5), sha512(6), (255) } HashAlgorithm;
enum { anonymous(0), rsa(1), dsa(2), ecdsa(3), (255) } SignatureAlgorithm;*/
		} r;

		if constexpr(SV) {
			const int k = 3 * DH_KEY_SZ + 266;
			r.h1.length[0] = (k + sizeof(Handshake_header)) / 0x100;
			r.h1.length[1] = (k + sizeof(Handshake_header)) % 0x100;
			r.h2.length[1] = k / 0x100; r.h2.length[2] = k % 0x100;
			r.h2.handshake_type = 12;
			mpz2bnd(diffie_.p, r.p, r.p + DH_KEY_SZ);
			mpz2bnd(diffie_.g, r.g, r.g + DH_KEY_SZ);
			mpz2bnd(diffie_.ya, r.ya, r.ya + DH_KEY_SZ);
			generate_signature(r.p_length, r.sign);
			return r;
		} else {
			H *q = (H*)rec_received_;
			mpz_class p = bnd2mpz(q->p, q->p + DH_KEY_SZ),
					  g = bnd2mpz(q->g, q->g + DH_KEY_SZ),
					  ya = bnd2mpz(q->ya, q->ya + DH_KEY_SZ);
			diffie_ = DiffieHellman{p, g, ya};
			use_key(derive_keys(diffie_.K));
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
	auto server_hello_done() {
		struct {
			TLS_header h1;
			Handshake_header h2;
		} r;
		if constexpr(SV) {
			r.h2.handshake_type = 14;
			return r;
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
	auto change_cipher_spec() {
		struct {
			TLS_header h1;
			uint8_t spec = 1;
		} r;
		r.h1.content_type = 20;
		r.h1.length[1] = 1;
		return r;
	}

	auto server_finished() {
		struct {
			TLS_header h1;
			Handshake_header h2;
		} r;

		r.h2.handshake_type = 20;
		char *p = (char*)&r;
		std::string s{p, p + sizeof(r)};
		std::string x = encode(s)[0];
		std::vector<unsigned char> v{0x16, 3, 3, 0};
		v.push_back(x.size());
		for(unsigned char c : x) v.push_back(c);
		return v;
	}

	auto client_key_exchange()//16
	{//return client_aes_key + server_aes_key
		struct H {
			TLS_header h1;
			Handshake_header h2;
			uint8_t key_sz[2] = {0, DH_KEY_SZ};
			uint8_t pub_key[DH_KEY_SZ];
		} r;

		if constexpr(SV) {
			H* ph = (H*)rec_received_;;
			assert(ph->h2.handshake_type == 16);
			int key_size = ph->key_sz[0] * 0x100 + ph->key_sz[1];
			auto premaster_secret = diffie_.set_yb(bnd2mpz(ph->pub_key, ph->pub_key + key_size));
			return use_key(derive_keys(premaster_secret));
		} else {
			r.h2.handshake_type = 16;
			mpz2bnd(diffie_.yb, r.pub_key, r.pub_key + DH_KEY_SZ);
			return r;
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
	std::array<unsigned char, KEY_SZ> use_key(std::array<unsigned char, KEY_SZ> keys)
	{
		unsigned char *p = keys.data();
		client_mac_.key(p, p + 20);
		server_mac_.key(p + 20, p + 40);
		client_aes_.key(p + 40);//AES128 key size 16
		server_aes_.key(p + 56);
	//	client_aes_.iv(p + 72);
	//	server_aes_.iv(p + 88);
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

	int get_content_type() {
		return rec_received_->content_type;
	}

protected:
	TLS_header *rec_received_;
	AES server_aes_, client_aes_;
	HMAC<SHA1> server_mac_, client_mac_;
	DiffieHellman diffie_;
	std::array<unsigned char, 32> session_id_, server_random_, client_random_;
	static std::vector<unsigned char> certificate_;
	int id_length_;

private:
	static RSA rsa_;
	bool support_dhe_ = false;

	void generate_signature(unsigned char* p_length, unsigned char* p) {
		unsigned char a[64 + 3 * DH_KEY_SZ + 6];
		memcpy(a, client_random_.data(), 32);
		memcpy(a + 32, server_random_.data(), 32);
		memcpy(a + 64, p_length, 6 + 3 * DH_KEY_SZ);
		//		auto b = server_mac_.hash(a, a + 70 + 3 * DH_KEY_SZ);
		SHA5 sha;
		auto b = sha.hash(a, a + 70 + 3 * DH_KEY_SZ);
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
		mpz2bnd(z, p, p + 256);
	}

	std::array<unsigned char, KEY_SZ> derive_keys(mpz_class premaster_secret) 
	{
		unsigned char pre[DH_KEY_SZ], rand[64];
		mpz2bnd(premaster_secret, pre, pre + DH_KEY_SZ);
		PRF<SHA2> prf;
		int i = 0;
		while(!pre[i]) i++;//strip preceding 0s
		prf.secret(pre + i, pre + DH_KEY_SZ);
		memcpy(rand, client_random_.data(), 32);
		memcpy(rand + 32, server_random_.data(), 32);
		prf.seed(rand, rand + 64);
		prf.label("master secret");
		auto master_secret = prf.get_n_byte(48);
		prf.secret(master_secret.begin(), master_secret.end());
		memcpy(rand, server_random_.data(), 32);
		memcpy(rand + 32, client_random_.data(), 32);
		prf.seed(rand, rand + 64);
		prf.label("key expansion");
		std::array<unsigned char, KEY_SZ> r;
		auto v = prf.get_n_byte(KEY_SZ);
		for(int i=0; i<KEY_SZ; i++) r[i] = v[i];
		return r;
	}
};
#pragma pack()
