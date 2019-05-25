#include<vector>
#include<cassert>
#include<nettle/chacha-poly1305.h>

class ChaCha
{
public:
	void enc_key(const uint8_t *key);
	void dec_key(const uint8_t *key);
	void enc_nonce(const uint8_t *nonce);
	void dec_nonce(const uint8_t *nonce);
	template<class It> std::vector<uint8_t> encrypt(const It begin, const It end) {
		int sz = end - begin;
		assert(sz % CHACHA_POLY1305_BLOCK_SIZE == 0);//64
		std::vector<uint8_t> result(sz + CHACHA_POLY1305_DIGEST_SIZE);//16
		chacha_poly1305_update(&enc_ctx_, 8, enc_sequence_num_);
		increase_seq_num(enc_sequence_num_);
		chacha_poly1305_encrypt(&enc_ctx_, sz, &result[0], &*begin);
		chacha_poly1305_digest(&enc_ctx_, CHACHA_POLY1305_DIGEST_SIZE, &result[sz]);
		return result;
	}
	template<class It> std::vector<uint8_t> decrypt(const It begin, const It end) {
		int sz = end - begin;
		assert(sz % CHACHA_POLY1305_BLOCK_SIZE == 0);
		std::vector<uint8_t> result(sz + CHACHA_POLY1305_DIGEST_SIZE);
		chacha_poly1305_update(&dec_ctx_, 8, dec_sequence_num_);
		increase_seq_num(dec_sequence_num_);
		chacha_poly1305_decrypt(&dec_ctx_, sz, &result[0], &*begin);
		chacha_poly1305_digest(&dec_ctx_, CHACHA_POLY1305_DIGEST_SIZE, &result[sz]);
		return result;
	}
protected:
	chacha_poly1305_ctx enc_ctx_, dec_ctx_;
	unsigned char enc_sequence_num_[8], dec_sequence_num_[8];
private:
	void increase_seq_num(unsigned char *p);
};

