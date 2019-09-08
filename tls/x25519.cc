#include<nettle/curve25519.h>
#include"crypt.h"
#include"x25519.h"
using namespace std;

X25519::X25519(const mpz_class &z) : mpz_class{z}
{ }

X25519 X25519::operator*(const mpz_class &z) const
{// 2^251 <= z < 2^252의 8의 배수
	uint8_t r_[32], buf_[32], z_[32];
	mpz2bnd(*this, buf_, buf_+32);
	mpz2bnd(z, z_, z_+32);
	if(*this == 9) curve25519_mul_g(r_, z_);
	else curve25519_mul(r_, z_, buf_);
	return bnd2mpz(r_, r_+32);
}

X25519 operator*(const mpz_class &z, const X25519 &r)
{
	return r * z;
}

ECDHE::ECDHE() : N{random_prime(32)}
{//N is hidden
	Q = N * X25519{};
}

mpz_class ECDHE::set_Q(const X25519 &Q)
{
	return K = N * Q;
}
