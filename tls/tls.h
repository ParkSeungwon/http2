#pragma once
#include<map>
#include<chrono>
#include"server.h"

typedef struct __attribute__((packed)) {
	uint8_t content_type;  // 0x17 for Application Data, 0x16 handshake
	uint16_t version;      // 0x0303 for TLS 1.2
	uint16_t length;       // length of encrypted_data
	unsigned char handshake_type;
	unsigned char blank[5];
	unsigned char unix_time[4];
	unsigned char random[28];
	unsigned char session_id_length;
	unsigned char session_id[32];
	unsigned char cipher_suite[2];
    uint8_t encrypted_data[];//01 hello - 5 - 4 unixtime- 28 random - sessionid length
	//02 - serverhello - 5 - 4 =time - 24 random - sessionidlength 0x20 - 32 - 00,35
	//14 -serverhellodone
} TLSRecord;

class TLS
{//this class just deals with memory structure
public:
	TLS(unsigned char* start);
	int client_hello(), server_hello(), server_hello_done();

protected:
	TLSRecord* record_;
	std::array<unsigned char, 32> session_id_, random_;
};

class HTTPS : public Server
{
public:
	HTTPS(int outport = 3000, int inport = 2001);
	~HTTPS();
	void start();

protected:
	struct Channel : public Client, public std::chrono::system_clock::time_point {
		Channel(int port);
		std::array<unsigned char, 32> key;
	};
	std::map<std::array<unsigned char, 32>, TLS::Channel*> idNchannel_;
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
