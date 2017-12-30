#pragma once
#include<map>
#include<chrono>
#include"server.h"

typedef struct __attribute__((packed)) {
	uint8_t content_type;  // 0x17 for Application Data, 0x16 handshake
	uint16_t version;      // 0x0303 for TLS 1.2
	uint16_t length;       // length of encrypted_data
	unsigned char handshake_type;
	unsigned char length_[3];
	unsigned char version_[2];//length is from here
	unsigned char unix_time[4];
	unsigned char random[28];
	unsigned char session_id_length;
	unsigned char session_id[32];
	unsigned char cipher_suite[2];
    uint8_t encrypted_data[];//01 hello - 5 - 4 unixtime- 28 random - sessionid length
	//02 - serverhello - 5 - 4 =time - 24 random - sessionidlength 0x20 - 32 - 00,35
	//14 -serverhellodone
} TLSRecord;

class Interface
{
public:
	virtual bool find_id(std::array<unsigned char, 32> id) {}
	virtual std::array<unsigned char, 32> new_id() {}

protected:
	static Interface* hI;
};

class TLS : public Interface
{//this class just deals with memory structure
public:
	TLS(unsigned char* start);
	int client_hello(), server_hello(), server_hello_done(), server_certificate(), server_key_exchange(), client_key_exchange();//16

protected:
	TLSRecord* record_;
	std::array<unsigned char, 32> session_id_, random_;
	int id_length_;
};

class HTTPS : public Server, Interface
{
public:
	HTTPS(int outport = 4000, int inport = 2001);
	virtual ~HTTPS();
	virtual bool find_id(std::array<unsigned char, 32> id);
	virtual std::array<unsigned char, 32> new_id();
	void start();

protected:
	struct Channel : public Client, std::chrono::system_clock::time_point {
		Channel(int port);
		std::array<unsigned char, 32> key;
	};
	std::map<std::array<unsigned char, 32>, HTTPS::Channel*> idNchannel_;
	int inport_;

private:
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
