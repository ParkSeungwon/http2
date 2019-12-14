#include"options/log.h"
#include"crypt.h"
using namespace std;

DiffieHellman::DiffieHellman(int bit_sz)
{//server side
	if(bit_sz == 2048) {
		p = premade;
		g = 2;
	}
	xa = random_prime(bit_sz / 8);
	ya = powm(g, xa, p);
}
DiffieHellman::DiffieHellman(mpz_class p, mpz_class g, mpz_class ya)
{//client side
	this->p = p; this->g = g; this->ya = ya;
	if(mpz_sizeinbase(p.get_mpz_t(), 16) <= 256) xb = random_prime(128);
	else xb = random_prime(256);
	yb = powm(g, xb, p);
	K = powm(ya, xb, p);
	LOGD << "p : " << hex << p;
	LOGD << "g : " << hex << g;
	LOGD << "ya : " << hex << ya;
	LOGD << "yb : " << hex << yb;
	LOGD << "K : " << hex << K;
}
mpz_class DiffieHellman::set_yb(mpz_class pub_key)
{//set client pub key
	yb = pub_key;
	K = powm(yb, xa, p);
	return K;
}


