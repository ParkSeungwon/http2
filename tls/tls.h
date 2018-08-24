#pragma once
#include"crypt.h"
#pragma pack(1)
#define DH_KEY_SZ 128
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
	uint8_t unix_time[4];
	uint8_t random[28];
	uint8_t session_id_length = 32;
	uint8_t session_id[32];
	uint8_t cipher_suite[2] = {0x00, 0x33};
	uint8_t compression = 0;
	uint8_t extension_length[2] = {0, 0};
} ;

class TLS
{//this class just deals with memory structure -> decoupled from underlying algorithm
public:
	TLS(unsigned char* buf_received = nullptr);
	std::string decode();
	std::vector<std::string> encode(std::string s);

	std::array<unsigned char, 32> client_hello();
	std::array<unsigned char, 64> client_key_exchange();
	int	client_finished();
	std::array<unsigned char, 64> use_key(std::array<unsigned char, 64> keys);
	void set_buf(void* p);
	std::vector<unsigned char> server_certificate();
	void change_cipher_spec();

	auto server_hello(std::array<unsigned char, 32> id) {
		struct {
			TLS_header h1;
			Handshake_header h2;
			Hello_header h3;
		} r;

		r.h1.length[1] = sizeof(Hello_header) + sizeof(Handshake_header);
		r.h2.length[2] = sizeof(Hello_header);
		r.h2.handshake_type = 2;
		memcpy(r.h3.unix_time, server_random_.data(), 32);
		memcpy(r.h3.session_id, id.data(), 32);
		return r;
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
	auto server_key_exchange() {
		struct {
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

		r.h2.handshake_type = 14;
		return r;
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
	auto server_finished() {
		struct {
			TLS_header h1;
			Handshake_header h2;
		} r;

		r.h2.handshake_type = 20;
		return r;
	}
protected:
	TLS_header *rec_received_;
	AES server_aes_, client_aes_;
	HMAC<SHA1> server_mac_, client_mac_;
	DiffieHellman<DH_KEY_SZ> diffie_;
	std::array<unsigned char, 32> session_id_, server_random_, client_random_;
	static std::vector<unsigned char> certificate_;
	int id_length_;
private:
	std::array<unsigned char, 64> use_key(std::vector<unsigned char> keys);
	static RSA rsa_;
	void generate_signature(unsigned char*, unsigned char*);
};
#pragma pack()
