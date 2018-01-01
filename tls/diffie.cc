#include"crypt.h"
using namespace std;

DiffieHellman::DiffieHellman()
{
	p = random_prime(32), q = random_prime(16), h = random_prime(16);
	g = powm(h, (p-1)/q, p);
	ya = random_prime(32);
	xa = powm(g, xa, p);
}

mpz_class DiffieHellman::yb(mpz_class pub_key)
{
	return K = powm(yb_ = pub_key, xa, p);
}


