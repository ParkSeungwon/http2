#include<nettle/curve25519.h>
#include"crypt.h"
using namespace std;

//static void mpz2lnd(mpz_class z, uint8_t *p)
//{
//	uint8_t tmp[32];
//	mpz2bnd(z, tmp, tmp + 32);
//	for(int i=0; i<32; i++) p[i] = tmp[31-i];
//}
//
//static mpz_class lnd2mpz(uint8_t *p)
//{
//	uint8_t tmp[32];
//	for(int i=0; i<32; i++) tmp[i] = p[31-i];
//	return bnd2mpz(tmp, tmp + 32);
//}

ECDHE::ECDHE() : N{random_prime(32)}
{//N is hidden
	mpz2bnd(N, n, n + 32);
	curve25519_mul_g(q, n);
	Q = bnd2mpz(q, q+32);
}

mpz_class ECDHE::set_Q(mpz_class Q)
{
	mpz2bnd(Q, q, q + 32);
	curve25519_mul(k, n, q);
	return K = bnd2mpz(k, k+32);
}

//void ECDHE::set_P(mpz_class P)
//{
//	mpz2lnd(P, p);
//	curve25519_mul(q, n, p);
//	Q = lnd2mpz(q);
//}
//-- Constant: CURVE25519_SIZE
//     The size of the strings representing curve25519 points and scalars,
//     32.
//
// -- Function: void curve25519_mul_g (uint8_t *Q, const uint8_t *N)
//     Computes Q = N G, where G is the group generator and N is an
//     integer.  The input argument N and the output argument Q use a
//     little-endian representation of the scalar and the x-coordinate,-wrong big endian
//     respectively.  They are both of size ‘CURVE25519_SIZE’.
//
//     This function is intended to be compatible with the function
//     ‘crypto_scalar_mult_base’ in the NaCl library.
//
// -- Function: void curve25519_mul (uint8_t *Q, const uint8_t *N, const
//          uint8_t *P)
//     Computes Q = N P, where P is an input point and N is an integer.
//     The input arguments N and P and the output argument Q use a
//     little-endian representation of the scalar and the x-coordinates,
//     respectively.  They are all of size ‘CURVE25519_SIZE’.
