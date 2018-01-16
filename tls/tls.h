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
enum HandShakeType {
    hello_request        =   0,
    client_hello         =   1,
    server_hello         =   2,
    hello_verify_request =   3,    /* DTLS addition */
    session_ticket       =   4,
    end_of_early_data    =   5,
    hello_retry_request  =   6,
    encrypted_extensions =   8,
    certificate          =  11,
    server_key_exchange  =  12,
    certificate_request  =  13,
    server_hello_done    =  14,
    certificate_verify   =  15,
    client_key_exchange  =  16,
    finished             =  20,
    certificate_status   =  22,
    key_update           =  24,
    change_cipher_hs     =  55,    /* simulate unique handshake type for sanity
                                      checks.  record layer change_cipher
                                      conflicts with handshake finished */
    message_hash         = 254,    /* synthetic message type for TLS v1.3 */
    no_shake             = 255     /* used to initialize the DtlsMsg record */
};

struct Hello_header {
	uint8_t version[2];//length is from here
	uint8_t unix_time[4];
	uint8_t random[28];
	uint8_t session_id_length;
	uint8_t session_id[32];
	uint8_t cipher_suite[2];
	uint8_t compression;
	uint8_t end;
} __attribute__((packed));

class TLS
{//this class just deals with memory structure -> decoupled from underlying algorithm
public:
	TLS(unsigned char* buf_received, unsigned char* buf_to_send = nullptr);
	int handshake();
	std::string decode();
	int encode(std::string s);
	std::array<unsigned char, 32> client_hello();
	int server_hello(std::array<unsigned char, 32> id), server_certificate(),
		server_key_exchange(), server_hello_done(), client_key_exchange(),
		client_finished(), server_finished();
protected:
	TLS_header *rec_received_, *rec_to_send_;
	AES server_aes_, client_aes_;
	HMAC server_mac_, client_mac_;
	DiffieHellman diffie_;
	std::array<unsigned char, 32> session_id_, server_random_, client_random_, 
		client_key_, server_key_;
	std::array<unsigned char, 16> client_iv_, server_iv_;
	int id_length_;
private:
	void init(int sz);
};
/*
ya is party a's public key; ya = g ^ xa mod p
         yb is party b's public key; yb = g ^ xb mod p
         xa is party a's private key
         xb is party b's private key
         p is a large prime
         q is a large prime
         g = h^{(p-1)/q} mod p, where
         h is any integer with 1 < h < p-1 such that h{(p-1)/q} mod p > 1
           (g has order q mod p; i.e. g^q mod p = 1 if g!=1)
         j a large integer such that p=qj + 1
         (See Section 2.2 for criteria for keys and parameters)
*/
