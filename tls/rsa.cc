#include"crypt.h"
using namespace std;

RSA::RSA(int key_size)
{
	p = random_prime(key_size / 2);
	q = random_prime(key_size / 2);
	K = p * q;
	phi = lcm(p-1, q-1);//e와 phi는 서로소
	for(e = random_prime(key_size / 2); gcd(e, phi) != 1; e = nextprime(e));
	mpz_invert(d.get_mpz_t(), e.get_mpz_t(), phi.get_mpz_t());//modular inverse
}

mpz_class RSA::encode(mpz_class m)
{
	return powm(m, e, K);
}
mpz_class RSA::decode(mpz_class m)
{
	return powm(m, d, K);
}
mpz_class RSA::sign(mpz_class m)
{
	return decode(m);
}
