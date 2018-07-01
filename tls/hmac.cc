#include<valarray>
#include<iostream>
#include"crypt.h"
using namespace std;

template<typename It> void HMAC::key(const It begin, const It end)
{//if less than block size(sha1 16? 64?) pad 0, more than block size hash -> 20
	int length = end - begin;
	valarray<unsigned char> key((int)0x0, block_size_),
							out_xor(0x5c, block_size_), in_xor(0x36, block_size_);
	if(length > block_size_) {
		auto h = sha_.hash(begin, end);
		for(int i=0; i<20; i++) key[i] = h[i];
	} else if(int i=0; length < block_size_)
		for(auto it = begin; it != end; it++) key[i++] = *it;
		
	auto o_key_pad = key ^ out_xor;
	auto i_key_pad = key ^ in_xor;
	for(int i=0; i<64; i++)
		o_key_pad_[i] = o_key_pad[i], i_key_pad_[i] = i_key_pad[i];
}

template<typename It> array<unsigned char,20> HMAC::hash(const It begin, const It end) 
{//
	vector<unsigned char> v;
	v.insert(v.begin(), i_key_pad_.begin(), i_key_pad_.end());
	v.insert(v.end(), begin, end);
	auto h = sha_.hash(v.begin(), v.end());
	v.clear();
	v.insert(v.begin(), o_key_pad_.begin(), o_key_pad_.end());
	v.insert(v.end(), h.begin(), h.end());
	return sha_.hash(v.begin(), v.end());
}


template void HMAC::key(vector<unsigned char>::iterator a, vector<unsigned char>::iterator b);
template void HMAC::key(unsigned char* a, unsigned char* b);
template array<unsigned char,20> HMAC::hash(vector<unsigned char>::iterator a, vector<unsigned char>::iterator b);
template array<unsigned char,20> HMAC::hash(unsigned char* a, unsigned char* b);
/***********************************
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
    
   return hash(o_key_pad ∥ hash(i_key_pad ∥ message)) //Where ∥ is concatenation
*************************************/
