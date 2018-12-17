#pragma once
#include<valarray>
#include<array>
#include<iomanip>
#include<iostream>
#include<sstream>
#include<cassert>
#include<gmpxx.h>
#include<cstdio>
#include<json/json.h>

Json::Value pem2json(std::istream& is);
Json::Value der2json(std::istream& is);
std::array<mpz_class, 3> get_pubkeys(std::istream& is);
std::array<mpz_class, 3> get_pubkeys(const Json::Value& jv);
std::string base64_encode(std::vector<unsigned char> v);
std::vector<unsigned char> base64_decode(std::string s);
template<typename... Args> void show(mpz_class a, Args... b);
mpz_class random_prime(unsigned byte);
mpz_class nextprime(mpz_class n);
mpz_class powm(mpz_class base, mpz_class exp, mpz_class mod);
template<typename It> void mpz2bnd(mpz_class n, It begin, It end)
{//mpz to big endian
	for(It i=end; i!=begin; n /= 0x100) *--i = mpz_class{n % 0x100}.get_ui();
}
template<typename It> mpz_class bnd2mpz(It begin, It end)
{//big endian to mpz
	std::stringstream ss; ss << "0x";
	for(It i=begin; i!=end; i++)
		ss << std::hex << std::setfill('0') << std::setw(2) << +*i;
	return mpz_class{ss.str()};
}
void print(unsigned char* r, const char* c);
std::string get_certificate_core(std::istream& is);

template<class C> std::string hexprint(const char *p, const C &c)
{//log container specialization
	std::stringstream ss;
	ss << p << " : 0x";
	for(unsigned char a : c) ss << std::hex << std::setw(2) << std::setfill('0')<< +a;
	return ss.str();
}

class DiffieHellman
{//256 byte = 2048 bit
public:
	DiffieHellman(int bit_sz = 1024);
	DiffieHellman(mpz_class p, mpz_class g, mpz_class ya);
	mpz_class set_yb(mpz_class pub_key);
	mpz_class p{"0xd6c094ad57f5374f68d58c7b096872d945cee1f82664e0594421e1d5e3c8e98bc3f0a6af8f92f19e3fef9337b99b9c93a055d55a96e425734005a68ed47040fdf00a55936eba4b93f64cba1a004e4513611c9b217438a703a2060c2038d0cfaaffbba48fb9dac4b2450dc58cb0320a0317e2a31b44a02787c657fb0c0cbec11d"};
	mpz_class g{"0x27e1ab131b6c22d259d199e9df8acbb1fe2fd4461afb7cb321d6946b02c66a9a45c062d5ffd01e47075cf7b082845e87e49529a66a8405354d1148184933078341c9fa627fde3c2a9a195e2cae33145c47bd86bbcd49b012f235bbc58486ce1d75522175fc7c9efd3aeaac06855b003e65a2208d16e7d89d9359dfd5e7002de1"};
	mpz_class ya, yb, K;

protected:
	mpz_class xa, xb;
private:
	mpz_class premade{"0xb0a108069c0813ba59063cbc30d5f500c14f44a7d6ef4ac625271ce8d296530a5c91dda2c29484bf7db2449f9bd2c18ac5be725ca7e791e6d49f7307855b6648c770fab4ee02c93d9a4ada3dc1463e1969d1174607a34d9f2b9617396d308d2af394d375cfa075e6f2921f1a7005aa04835730fbda76933850e827fd63ee3ce5b7c809ae6f50358e84ce4a00e9127e5a31d733fc211376cc1630db0cfcc562a735b8efb7b0acc036f6d9c94648f94090002b1baa6ce31ac30b039e1bc246e4484e22736fc35fd49ad6300748d68c90abd4f6f1e348d3584ba6b9cd29bf681f084b63862f5c6bd6b60665f7a6dc00676bbbc3a94183fbc7fac8e21e7eaf003f93"};
};

class RSA
{
public:
	RSA(int key_size);//generate key
	RSA(mpz_class e, mpz_class d, mpz_class K);//read frem certificate or memory
	mpz_class sign(mpz_class m), decode(mpz_class m), encode(mpz_class m);
	mpz_class K, e;
protected:
	mpz_class p, q, d, phi;
};

