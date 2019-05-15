#include<cassert>
#include"crypt.h"
using namespace std;

unsigned char schedule[11][16];
void expand_key(const unsigned char *pkey) {
	memcpy(schedule[0], pkey, 16);
	unsigned char *p = &schedule[1][0];
	for(int i=1; i<11; i++) {
		for(int j=0; j<3; j++) *(p+j) = *(p+j-3);
		*(p+3) = *(p-4);
		for(int j=0; j<4; j++) *(p+j) = sbox[*(p+j)];
		for(int j=0; j<4; j++, p++) {//p+=4
			*p ^= rcon[4*i/N-1][j];
			*p ^= *(p - 4*N);
		}
		for(int j=0; j<12; j++, p++) *p = *(p - 4*N) ^ *(p - 4);//p+=12
	}
}
int main()
{
	DiffieHellman Alice;
	DiffieHellman Bob{Alice.p, Alice.g, Alice.ya};
	Alice.set_yb(Bob.yb);
	cout << hex << Alice.K << endl << Bob.K << endl;
	assert(Alice.K == Bob.K);

	RSA rsa{256};
	auto a = rsa.encode(mpz_class{"0x23423423"});
	cout << hex << rsa.decode(a) << endl;

	unsigned char key1[] = {0x54, 0x68, 0x61, 0x74, 0x73, 0x20, 0x6D, 0x79,
							0x20, 0x4B, 0x75, 0x6E, 0x67, 0x20, 0x46, 0x75};
	expand_key(key1);
	for(int i=0; i<11; i++) {
		for(int j=0; j<16; j++) cout << schedule[i][j] << ' ';
		cout << endl;
	}
}

