#pragma once
#include"crypt.h"
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

template<bool SV = true> class TLS
{//just deals with memory structure -> decoupled from underlying file-descriptor
public:
	TLS(unsigned char* buffer = nullptr);
	bool support_dhe();
	int get_content_type(std::string &&s = "");//"" -> manual set
	void set_buf(void* p);
	void session_id(std::array<unsigned char, 32> id);
	std::array<unsigned char, KEY_SZ> use_key(std::array<unsigned char, KEY_SZ> keys);
	std::string decode(std::string &&s = "");//if not rvalue use set_buf
	std::string encode(std::string &&s = "");

	std::string client_hello(std::string &&s = "");//s != "" -> buffer is set to s
	std::string server_hello(std::string &&s = "");//s == "" -> manual buffer set
	std::string server_certificate(std::string &&s = "");
	std::string server_key_exchange(std::string &&s = "");
	std::string server_hello_done(std::string &&s = "");
	std::string client_key_exchange(std::string &&s = "");
	std::string change_cipher_spec(std::string &&s = "");//if s=="" send, else recv
	std::string finished(std::string &&s = "");//if s=="" send, else recv

protected:
	void *rec_received_;
	AES server_aes_, client_aes_;
	HMAC<SHA1> server_mac_, client_mac_;
	DiffieHellman diffie_;
	std::array<unsigned char, 32> session_id_, server_random_, client_random_;
	static std::string certificate_;
	int id_length_;

private:
	static RSA rsa_;
	bool support_dhe_ = false;

	void generate_signature(unsigned char* p_length, unsigned char* p);
	std::array<unsigned char, KEY_SZ> derive_keys(mpz_class premaster_secret);
};
