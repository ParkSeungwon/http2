#include"crypt.h"
#include<wolfssl/wolfcrypt/rsa.h>
using namespace std;

int main()
{
	RsaKey genKey;
	RNG rng;
	int ret;
	wc_InitRng(&rng);
	wc_InitRsaKey(&genKey,0);
	ret = wc_MakeRsaKey(&genKey, 1024, 65537, &rng);
}

