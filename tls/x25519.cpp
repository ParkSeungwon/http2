#include<iomanip>
#include<iostream>
#include<nettle/curve25519.h>
#include"crypt.h"
#include"x25519.h"
using namespace std;

int main()
{
 	mpz_class a{"0x77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a"},
			  b{"0x5dab087e624a8a4b79e17f8b83800ee66f3bb1292618b6fd1c2f8b27ff88e0eb"},
			  pa{"0x8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a"},
			  pb{"0xde9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f"},
			  k{"0x4a5d9d5ba4ce2de1728e3bf480350f25e07e21c947d19e3376f09b3c1e161742"};
	X25519 x;
	cout << x << endl;
	auto aa = a * x, bb = b * x;
	cout << hex << aa << endl << bb << endl;
	cout << aa * b << endl << bb * a << endl;
	uint8_t A[32], B[32], R[32], nine[32], PB[32], PA[32];
	for(auto& i : nine) i = 0;
	nine[0] = 9;
	mpz2bnd(a, A, A+32);
//	reverse(A, A+32);
	mpz2bnd(b, B, B+32);
//	reverse(B, B+32);
	curve25519_mul_g(PA, A);
	curve25519_mul_g(PB, B);
	cout << hexprint("PA", PA) << endl;
	cout << hexprint("PB", PB) << endl;
	curve25519_mul(R, A, nine);
	cout << hexprint("PA with mul", R) << endl;
	curve25519_mul(R, B, PA);
	cout << hexprint("Key", R) << endl;
	curve25519_mul(R, A, PB);
	cout << hexprint("Key", R) << endl;
	cout << aa * b << endl;
//	k = mpz_class{"0xa546e36bf0527c9d3b16154b82465edd62144c0ac1fc5a18506a2244ba449ac4"};
//	mpz_class
//	p = mpz_class{"0xe6db6867583030db3594c1a424b15f7c726624ec26b3353b10a903a6d0ab1c4c"};
//	mpz_class
//	kp =mpz_class{"0xc3da55379de9c6908e94ea4df28d084f32eccf03491c71f754b4075577a28552"};
//	cout << k * X25519{p} << endl;
	{
	mpz_class k, p, kp;
	k = mpz_class{"0xa546e36bf0527c9d3b16154b82465edd62144c0ac1fc5a18506a2244ba449ac4"};
	p = mpz_class{"0xe6db6867583030db3594c1a424b15f7c726624ec26b3353b10a903a6d0ab1c4c"};
	kp =mpz_class{"0xc3da55379de9c6908e94ea4df28d084f32eccf03491c71f754b4075577a28552"};
	cout << k * X25519{p} <<endl;
	k = mpz_class{"0x4b66e9d4d1b4673c5ad22691957d6af5c11b6421e0ea01d42ca4169e7918ba0d"};
	p = mpz_class{"0xe5210f12786811d3f4b7959d0538ae2c31dbe7106fc03c3efc4cd549c715a493"};
	kp =mpz_class{"0x95cbde9476e8907d7aade45cb4b873f88b595a68799fa152e6f8f7647aac7957"};
	cout << k * X25519{p} <<endl;

	uint8_t K[32], P[32], KP[32], R[32];
	mpz2bnd(k, K, K+32);
//	reverse(K, K+32);
	mpz2bnd(p, P, P+32);
//	reverse(P, P+32);
	mpz2bnd(kp, KP, KP+32);
//	reverse(KP, KP+32);
	curve25519_mul(R, K, P);
	cout << hexprint("(KP:", R) << endl;
	cout << mpz_class{1} * X25519{} << endl;
	}
}

