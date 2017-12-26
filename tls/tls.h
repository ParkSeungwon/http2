#include<map>
#include<chrono>
#include"server.h"
#include<gmpxx.h>
#include<wolfssl/wolfcrypt/aes.h>
#include<wolfssl/wolfcrypt/sha.h>

class AES256 
{
public:
	AES256(mpz_class key, mpz_class iv);

protected:
	unsigned char key_[32], iv_[16];
	Aes enc_, dec_;
};

typedef struct __attribute__((packed)) {
	uint8_t content_type;  // 0x17 for Application Data
	uint16_t version;      // 0x0303 for TLS 1.2
	uint16_t length;       // length of encrypted_data
    uint8_t encrypted_data[];
} TLSRecord;


class TLS : public Server
{
public:
	TLS(int outport = 3000, int inport = 2001);
	~TLS();
	void start();

protected:
	struct Channel : public Client, public std::chrono::system_clock::time_point {
		Channel(int port);
	};
	struct Less {
		bool operator()(const unsigned char* a, const unsigned char* b) const;
	};
	std::map<const unsigned char*, TLS::Channel*, TLS::Less> idNchannel_;
	int inport_;
	gnutls_anon_server_credentials_t anoncred;

};

