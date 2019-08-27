#include<nettle/curve25519.h>
#include"x255519.h"
using namespace std;

X25519::X25519(string s) : mpz_class{s}
{ }

X25519 X25519::operator*(const mpz_class &z)
{
	uint8_t r[32], buf[32], z_[32];
	mpz2bnd(*this, buf, buf+32);
	mpz2bnd(z, z_, z_+32);
	reverse(buf, buf+32);
	reverse(z, z+32);
	curve25519_mul(r, z, buf);
	reverse(r, r+32);
	return bnd2mpz(r, r+32);
}

X25519 operator*(const mpz_class &z, const X25519 &r)
{
	return r * z;
}
