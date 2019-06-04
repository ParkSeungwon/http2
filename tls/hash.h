#pragma once
#include<vector>
#include<valarray>
#include<nettle/sha1.h>
#include<nettle/sha2.h>
#include<nettle/sha3.h>

class SHA1
{
public:
	static const int block_size = 64;
	static const int output_size = 20;
	SHA1() {
		sha1_init(&sha_);
	}
	template<typename It>
	std::array<unsigned char, output_size> hash(const It begin, const It end) {
		std::array<unsigned char, output_size> r;
		sha1_update(&sha_, end - begin, (const unsigned char*)&*begin);
		sha1_digest(&sha_, 20, &r[0]);
		return r;
	}
protected:
	sha1_ctx sha_;
};

class SHA256
{//sha256, sha2 due to some naming reason
public:
	static const int block_size = 64;
	static const int output_size = 32;
	SHA256() {
		sha256_init(&sha_);
	}
	template<typename It>
	std::array<unsigned char, output_size> hash(const It begin, const It end) {
		std::array<unsigned char, output_size> r;
		sha256_update(&sha_, end - begin, (const unsigned char*)&*begin);
		sha256_digest(&sha_, output_size, &r[0]);
		return r;
	}
protected:
	sha256_ctx sha_;
};

class SHA384
{
public:
	static const int block_size = 128;
	static const int output_size = 48;
	SHA384() {
		sha384_init(&sha_);
	}
	template<typename It>
	std::array<unsigned char, output_size> hash(const It begin, const It end) {
		std::array<unsigned char, output_size> r;
		sha384_update(&sha_, end - begin, (const unsigned char*)&*begin);
		sha384_digest(&sha_, output_size, &r[0]);
		return r;
	}
protected:
	sha384_ctx sha_;
};

class SHA512
{//sha512
public:
	static const int block_size = 128;
	static const int output_size = 64;
	SHA512() {
		sha512_init(&sha_);
	}
	template<class It>
	std::array<unsigned char, output_size> hash(const It begin, const It end) {
		std::array<unsigned char, output_size> r;
		sha512_update(&sha_, end - begin, (const unsigned char*)&*begin);
		sha512_digest(&sha_, output_size, &r[0]);
		return r;
	}
protected:
	sha512_ctx sha_;
};

struct MAC {
	virtual void key(const uint8_t*, int) = 0;
	virtual std::vector<uint8_t> hash(const uint8_t*, int) = 0;
};

template<class H> class HMAC : MAC
{//hmac using sha1
public:
	HMAC() : o_key_pad_(H::block_size), i_key_pad_(H::block_size)
	{ }
	template<typename It> void key(const It begin, const It end)
	{//if less than block size(sha1 16? 64?) pad 0, more than block size hash -> 20
		int length = end - begin;//below (int)0x0 : compiler confuse with null ptr
		std::valarray<unsigned char> key((int)0x0, H::block_size),
			out_xor(0x5c, H::block_size), in_xor(0x36, H::block_size);
		if(length > H::block_size) {
			auto h = sha_.hash(begin, end);
			for(int i=0; i<H::output_size; i++) key[i] = h[i];
		} else if(int i = 0; length < H::block_size)
			for(auto it = begin; it != end; it++) key[i++] = *it;

		o_key_pad_ = key ^ out_xor;
		i_key_pad_ = key ^ in_xor;
	}
	template<typename It> auto hash(const It begin, const It end)
	{
		std::vector<unsigned char> v;
		v.insert(v.begin(), std::begin(i_key_pad_), std::end(i_key_pad_));
		v.insert(v.end(), begin, end);
		auto h = sha_.hash(v.begin(), v.end());
		v.clear();
		v.insert(v.begin(), std::begin(o_key_pad_), std::end(o_key_pad_));
		v.insert(v.end(), h.begin(), h.end());
		return sha_.hash(v.begin(), v.end());
	}
	void key(const uint8_t *k, int sz) {
		key(k, k + sz);
	}
	std::vector<uint8_t> hash(const uint8_t *begin, int sz) {
		auto a = hash(begin, begin + sz);
		return std::vector<uint8_t>{a.begin(), a.end()};
	}
protected:
	H sha_;
	std::valarray<unsigned char> o_key_pad_, i_key_pad_;
};
/**********************************
Function hmac
   Inputs:
	  key:        Bytes     array of bytes
	  message:    Bytes     array of bytes to be hashed
	  hash:       Function  the hash function to use (e.g. SHA-1)
	  blockSize:  Integer   the block size of the underlying hash function (e.g. 64 bytes for SHA-1)
	  outputSize: Integer   the output size of the underlying hash function (e.g. 20 bytes for SHA-1)
 
   Keys longer than blockSize are shortened by hashing them
   if (length(key) > blockSize) then
	  key ← hash(key) //Key becomes outputSize bytes long
   
   Keys shorter than blockSize are padded to blockSize by padding with zeros on the right
   if (length(key) < blockSize) then
	  key ← Pad(key, blockSize)  //pad key with zeros to make it blockSize bytes long
	
   o_key_pad = key xor [0x5c * blockSize]   //Outer padded key
   i_key_pad = key xor [0x36 * blockSize]   //Inner padded key
	
   return hash(o_key_pad + hash(i_key_pad +message)) //Where +is concatenation
************************************/

template<class H> class PRF
{//H is hash function usually sha256
public:
	template<class It> void secret(const It begin, const It end) {
		secret_.clear();
		for(It it = begin; it != end; it++) secret_.push_back(*it);
		hmac_.key(secret_.begin(), secret_.end());
	}
	void label(const char* p) {
		label_.clear();
		while(*p) label_.push_back(*p++);
	}
	template<class It> void seed(const It begin, const It end) {
		seed_.clear();
		for(It it = begin; it != end; it++) seed_.push_back(*it);
	}
	std::vector<unsigned char> get_n_byte(int n) {
		auto seed = label_;//seed = label + seed_
		seed.insert(seed.end(), seed_.begin(), seed_.end());
		std::vector<unsigned char> r, v;
		std::vector<std::array<unsigned char, H::output_size>> vA;
		vA.push_back(hmac_.hash(seed.begin(), seed.end()));//A(1)
		while(r.size() < n) {
			v.clear();
			v.insert(v.end(), vA.back().begin(), vA.back().end());
			v.insert(v.end(), seed.begin(), seed.end());
			auto h = hmac_.hash(v.begin(), v.end());
			r.insert(r.end(), h.begin(), h.end());
			vA.push_back(hmac_.hash(vA.back().begin(), vA.back().end()));//A(i+1)
		}
		while(r.size() != n) r.pop_back();
		return r;
	}

protected:
	HMAC<H> hmac_;
	std::vector<unsigned char> secret_, label_, seed_;
};

/******************************
P_hash(secret, seed) = HMAC_hash(secret, A(1) + seed) +
					   HMAC_hash(secret, A(2) + seed) +
					   HMAC_hash(secret, A(3) + seed) + ...
where + indicates concatenation.
A() is defined as:
A(0) = seed
A(i) = HMAC_hash(secret, A(i-1))
P_hash can be iterated as many times as necessary to produce the
required quantity of data. For example, if P_SHA256 is being used to
create 80 bytes of data, it will have to be iterated three times
(through A(3)), creating 96 bytes of output data; the last 16 bytes
of the final iteration will then be discarded, leaving 80 bytes of
output data.
TLS’s PRF is created by applying P_hash to the secret as:
PRF(secret, label, seed) = P_<hash>(secret, label + seed)
The label is an ASCII string. It should be included in the exact
form it is given without a length byte or trailing null character.
For example, the label "slithy toves" would be processed by hashing
the following bytes:
73 6C 69 74 68 79 20 74 6F 76 65 73
******************************/

