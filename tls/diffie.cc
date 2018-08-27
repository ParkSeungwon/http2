#include"crypt.h"
using namespace std;

DiffieHellman::DiffieHellman()
{//server side
	p = bnd2mpz(premade, premade + 256);
	xa = random_prime(256);
	ya = powm(g, xa, p);
}
DiffieHellman::DiffieHellman(mpz_class p, mpz_class g, mpz_class ya)
{//client side
	this->p = p; this->g = g; this->ya = ya;
	xb = random_prime(256);
	yb = powm(g, xb, p);
	K = powm(ya, xb, p);
}
mpz_class DiffieHellman::set_yb(mpz_class pub_key)
{//set client pub key
	yb = pub_key;
	K = powm(yb, xa, p);
	return K;
}


