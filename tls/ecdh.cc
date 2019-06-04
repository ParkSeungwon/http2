#include<nettle/curve25519.h>
#include"crypt.h"
using namespace std;

static void mpz2lnd(mpz_class z, uint8_t *p)
{
	uint8_t tmp[32];
	mpz2bnd(z, tmp, tmp + 32);
	for(int i=0; i<32; i++) p[i] = tmp[31-i];
}

static mpz_class lnd2mpz(uint8_t *p)
{
	uint8_t tmp[32];
	for(int i=0; i<32; i++) tmp[i] = p[31-i];
	return bnd2mpz(tmp, tmp + 32);
}

ECDHE::ECDHE() : N{random_prime(32)}
{
	mpz2lnd(N, n);
	curve25519_mul_g(q, n);
	Q = lnd2mpz(q);
}

mpz_class ECDHE::set_Q(mpz_class Q)
{
	mpz2lnd(Q, q);
	curve25519_mul(k, n, q);
	return K = lnd2mpz(k);
}

void ECDHE::set_P(mpz_class P)
{
	mpz2lnd(P, p);
	curve25519_mul(q, n, p);
	Q = lnd2mpz(q);
}
