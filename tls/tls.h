#pragma once
#include<type_traits>
#include<valarray>
#include<memory>
#include<functional>
#include"crypt.h"
#include"block_cipher.h"
#include"hash.h"
#include"x25519.h"
#define DH_KEY_SZ 256
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
	bool support_dhe(), is_tls12();
	std::pair<int, int> get_content_type(const std::string &s = "");//"" -> manual set
	void set_buf(void* p);
	void session_id(std::array<unsigned char, 32> id);
	std::array<unsigned char, KEY_SZ> use_key(std::array<unsigned char, KEY_SZ> keys);
	std::string decode(std::string &&s = "");//if not rvalue use set_buf
	std::string encode(std::string &&s = "", int type = 0x17);//for finished 0x16

	void handshake(std::function<std::string(void)> read_func,
			std::function<void(std::string)> write_func);
	void handshake(std::function<void(void)> read_func,
			std::function<void(void)> write_func);
	std::string client_hello(std::string &&s = "");//s != "" -> buffer is set to s
	std::string server_hello(std::string &&s = "");//s == "" -> manual buffer set
	std::string server_certificate(std::string &&s = "");
	std::string server_key_exchange(std::string &&s = "");
	std::string server_hello_done(std::string &&s = "");
	std::string client_key_exchange(std::string &&s = "");
	std::string change_cipher_spec(std::string &&s = "");//if s=="" send, else recv
	std::string finished(std::string &&s = "");//if s=="" send, else recv
	int alert(std::string &&s = "");
	std::string alert(uint8_t level, uint8_t desc);

protected:
	const void *rec_received_;
	uint8_t selected_cipher_suite[2];
	bool tls12_ = false;
	std::unique_ptr<CipherMode> cipher_{nullptr};
	std::unique_ptr<MAC> mac_[2] = {nullptr, nullptr};
	std::unique_ptr<DHE> dhe_{nullptr};
	std::unique_ptr<ECDHE> ecdhe_{nullptr};
	std::unique_ptr<IHKDF> hkdf_{nullptr};
	size_t hash_code_;
	std::array<unsigned char, 32> session_id_, server_random_, client_random_;
	std::vector<unsigned char> master_secret_, psk_;
	std::map<std::string, std::vector<uint8_t>> psk_key_schedule_;
	std::string accumulated_handshakes_;
	static std::string certificate_;
	int id_length_;
	mpz_class enc_seq_num_ = 0, dec_seq_num_ = 0;
		
private:
	static RSA rsa_;
	int finish_msg_count_ = -1;

	void generate_signature(unsigned char* p_length, unsigned char* p);
	std::array<unsigned char, KEY_SZ> derive_keys(mpz_class premaster_secret);
	std::map<std::string, std::vector<uint8_t>>
		psk_key_schedule(std::vector<uint8_t> dh_shared_secret, std::string psk = "");
	std::string accumulate(std::string s);
	void accumulate();
	void allocate_cipher(uint8_t cipher_suite_first_byte, uint8_t second_byte);
	template<class D, class A, template<int> class C, int B, 
		template<class> class M, class H> void set_cipher();
	bool process_extension(uint8_t *p);
	std::string ecdhe_server_key_exchange(std::string &&);
	std::string dhe_server_key_exchange(std::string &&);
};

const int CHANGE_CIPHER_SPEC = 0x14
		, ALERT = 0x15
		, HANDSHAKE = 0x16
		, APPLICATION_DATA = 0x17
		;
const int HELLO_REQUEST = 0x00
		, CLIENT_HELLO = 0x01
		, SERVER_HELLO = 0x02
		, CERTIFICATE = 0x0b
		, SERVER_KEY_EXCHANGE = 0x0c
		, CERTIFICATE_REQUEST = 0x0d
		, SERVER_DONE = 0x0e
		, CERTIFICATE_VERIFY = 0x0f
		, CLIENT_KEY_EXCHANGE = 0x10
		, FINISHED = 0x14
		;

