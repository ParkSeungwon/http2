#include<gmpxx.h>

struct X25519 : public mpz_class
{
	X25519(const mpz_class &z = 9);
	X25519 operator*(const mpz_class &r) const;
};

X25519 operator*(const mpz_class &z, const X25519 &x);

struct ECDHE
{//curve25519 nettle library
	ECDHE();
	mpz_class set_Q(const X25519& Q);
	mpz_class N;
	X25519 Q, K;
};
