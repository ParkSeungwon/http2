//http://blog.fourthbit.com/2014/12/23/traffic-analysis-of-an-ssl-slash-tls-session
#include<cstring>
#include<iostream>
#include<unistd.h>
#include<arpa/inet.h>//htons
#include<cassert>
#include<initializer_list>
#include<fstream>
#include<deque>
#include"tls.h"
using namespace std;

array<mpz_class, 3> get_keys(istream& is);
mpz_class get_prvkey(istream& is);
std::string get_certificate_core(std::istream& is);

//static member initialization
static mpz_class ze, zd, zK;//used in TLS constructor
static vector<unsigned char> to_byte(int k, int sz)
{
	vector<unsigned char> v(sz);
	mpz2bnd(k, v.begin(), v.end());
	return v;
}
static vector<unsigned char> init_certificate()
{
	ifstream f2("key.pem");//generated with openssl genrsa 2048 > key.pem
	ifstream f("cert.pem");//openssl req -x509 -days 1000 -new -key key.pem -out cert.pem
	auto [K, e, d] = get_keys(f2);
	zK = K; ze = e; zd = d;
//	mpz_class m{"0x23232"};
//	auto z = powm(m, e, K);
//	assert(m == powm(z, d, K));
	vector<vector<unsigned char>> vv;

	for(string s; (s = get_certificate_core(f)) != "";) {
		vector<unsigned char> v;
		for(unsigned char c : base64_decode(s)) v.push_back(c);
		vv.push_back(v);
	}

	deque<unsigned char> r;
	for(const auto &v : vv) {
		for(unsigned char c : to_byte(v.size(), 3)) r.push_back(c);
		for(unsigned char c : v) r.push_back(c);
	}
	for(int i=0; i<2; i++) {
		auto v = to_byte(r.size(), 3);
		r.insert(r.begin(), v.begin(), v.end());
	}
	r.push_front(0x0b);
	auto v = to_byte(r.size(), 2);
	r.insert(r.begin(), v.begin(), v.end());
	r.push_front(3); r.push_front(3); r.push_front(0x16);

	v.clear();
	for(unsigned char c : r) v.push_back(c);
	return v;
}
template<bool SV> vector<unsigned char> TLS<SV>::certificate_ = init_certificate();
template<bool SV> RSA TLS<SV>::rsa_{ze, zd, zK};

string TLS::decode()
{
//	assert(rec_received_->content_type == 0x17);
	unsigned char* p = reinterpret_cast<unsigned char*>(rec_received_ + 1);
	client_aes_.iv(p);
	auto v = client_aes_.decrypt(p + 16, p + rec_received_->length[0] * 0x100 + rec_received_->length[1]);
	cout << "v size " << v.size() << ", back " << +v.back() << endl;
	for(int i=v.back(); i>=0; i--) v.pop_back();//remove padding
	auto a = client_mac_.hash(v.begin(), v.end() - 20);
	for(int i=0; i<20; i++)
		cout << hex << +a[i] << ':' << hex << +v[v.size() - 20 + i] << endl;
	return {v.data(), v.data() + v.size() - 20};//v.back() == padding length
}
/***********************
ApplicationData Protocol format

The mission of this protocol is to properly encapsulate the data coming from the Application Layer of the network stack, so it can seamlessly be handled by the underlying protocol (TCP) without forcing changes in any of those layers. The format of the messages in this protocols follows the same structure as the previous ones.

                           |
                           |
                           |
         Record Layer      |  ApplicationData Layer (encrypted)
                           |
                           |
  +----+----+----+----+----+----+----+--- - - - - - - --+---------+
  | 23 |    |    |    |       length-delimited data     |         |
  |0x17|    |    |    |    |    |    |                  |   MAC   |
  +----+----+----+----+----+----+----+--- - - - - - - --+---------+
    /               /      |
   /               /       |
  type: 23        /        |
                 /
                /
           length: arbitrary (up to 16k)
******************/

vector<string> TLS::encode(string s) {
	struct {
		TLS_header h1;
		//uint8_t random[16];
	}__attribute__((packed)) r;
	r.h1.content_type = 0x17;
	vector<string> vs;

	const int chunk_size = (2 << 14) - 1024 - 20;//cut string into 2^14
	for(int sq = 1; chunk_size * (sq - 1) < s.size(); sq++) {
//		auto z = random_prime(16);
//		mpz2bnd(z, r.random, r.random + 16);
//		server_aes_.iv(z);

		int len = sq * chunk_size > s.size() ? s.size() % chunk_size : chunk_size;
		int padding_length = 16 - (len + 20) % 16;//20 = sha1 digest, 16 block sz
		mpz2bnd(len + 20 + 16 + 1, r.h1.length, r.h1.length + 2);
		std::string s2 = string{sq} + string{(const char*)&r.h1, 5} + 
			s.substr((sq-1) * chunk_size, min((int)s.size(), sq*chunk_size));
		auto verify = server_mac_.hash((uint8_t*)s2.data(),
				(uint8_t*)s2.data() + s.size());
		s2 += string{verify.begin(), verify.end()};
		s2 += string(padding_length, padding_length);
		auto v = server_aes_.encrypt((uint8_t*)s2.data()+6,//exclude first 6 bytes
				(uint8_t*)s2.data() + s2.size());
		string s3 = s2.substr(0, 6) + //string{(const char*)r.random, 16} +
			string{v.begin(), v.end()};
		vs.push_back(s3);
	}
	return vs;
}
/***************
The MAC is generated as:
MAC(MAC_write_key, seq_num + TLSCompressed.type + TLSCompressed.version +
	TLSCompressed.length + TLSCompressed.fragment);
where "+" denotes concatenation.

struct {
	opaque IV[SecurityParameters.record_iv_length];//16
	block-ciphered struct {
		opaque content[TLSCompressed.length];//len
		opaque MAC[SecurityParameters.mac_length];//20
		uint8 padding[GenericBlockCipher.padding_length];//pad
		uint8 padding_length;//1
	};
} GenericBlockCipher;
*********************/

void TLS::change_cipher_spec(int) {}
int TLS::client_finished()
{
	string s = decode();
	for(unsigned char c : s) cout << noskipws << hex << +c << ' ';
	Handshake_header* ph = (Handshake_header*)(rec_received_ + 1);
//	assert(ph->handshake_type == 20);
	return 7;
}
/***********************
Finished: This message signals that the TLS negotiation is complete and the CipherSuite is activated. It should be sent already encrypted, since the negotiation is successfully done, so a ChangeCipherSpec protocol message must be sent before this one to activate the encryption. The Finished message contains a hash of all previous handshake messages combined, followed by a special number identifying server/client role, the master secret and padding. The resulting hash is different from the CertificateVerify hash, since there have been more handshake messages.

     |
     |
     |
     |  Handshake Layer
     |
     |
- ---+----+----+----+----+----------+
     | 20 |    |    |    |  signed  |
     |0x14|    |    |    |   hash   |
- ---+----+----+----+----+----------+
  /  |  \    \---------\
 /       \        \
record    \     length
length     \
            type: 20
*********************/

