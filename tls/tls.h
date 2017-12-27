#include<map>
#include<chrono>
#include"server.h"

typedef struct __attribute__((packed)) {
	uint8_t content_type;  // 0x17 for Application Data, 0x16 handshake
	uint16_t version;      // 0x0303 for TLS 1.2
	uint16_t length;       // length of encrypted_data
    uint8_t encrypted_data[];//01 hello - 5 - 4 unixtime- 28 random - sessionid length
	//02 - serverhello - 5 - 4 =time - 24 random - sessionidlength 0x20 - 32 - 00,35
	//14 -serverhellodone
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
	int inport_, id_length_;
	TLSRecord* record_;
	unsigned char random_[32], session_id_[32];

private:
	void client_hello(), server_hello(), server_hello_done();
};


