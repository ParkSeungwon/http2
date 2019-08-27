#include<gmpxx.h>

struct X25519 : public mpz_class
{
	X25519(std::string s = "0x9");
	X25519 operator*(const mpz_class &r);
};

X25519 operator*(const mpz_class &z, const X25519 &x);
