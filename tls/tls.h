#pragma once
#include"crypt.h"

struct TLS_header {
	uint8_t content_type;  // 0x17 for Application Data, 0x16 handshake
	uint16_t version;      // 0x0303 for TLS 1.2
	uint16_t length;       // length of encrypted_data
	uint8_t data[];
} __attribute__((packed));
struct Handshake_header {
	uint8_t handshake_type;
	uint8_t length[3];
	uint8_t data[];
} __attribute__((packed));
struct Hello_header {
	uint8_t version[2];//length is from here
	uint8_t unix_time[4];
	uint8_t random[28];
	uint8_t session_id_length;
	uint8_t session_id[32];
	uint8_t cipher_suite[2];
	uint8_t compression;
} __attribute__((packed));

class TLS
{//this class just deals with memory structure -> decoupled from underlying algorithm
public:
	TLS(unsigned char* buf_received, unsigned char* buf_to_send = nullptr);
	std::string decode();
	int encode(std::string s);
	std::array<unsigned char, 32> client_hello();
	int server_hello(std::array<unsigned char, 32> id), server_certificate(),
		server_key_exchange(), server_hello_done();
	std::array<unsigned char, 64> client_key_exchange();
	int	client_finished(), server_finished();
	std::array<unsigned char, 64> use_key(std::array<unsigned char, 64> keys);
protected:
	TLS_header *rec_received_, *rec_to_send_;
	AES server_aes_, client_aes_;
	SHA1 server_mac_, client_mac_;
	DiffieHellman diffie_;
	std::array<unsigned char, 32> session_id_, server_random_, client_random_;
	int id_length_;
private:
	unsigned char* init(int handshake_type, int sz);
	std::array<unsigned char, 64> use_key(std::vector<unsigned char> keys);
	static std::vector<unsigned char> certificate_;
	static RSA rsa_;
};
