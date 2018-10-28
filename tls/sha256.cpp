#include<cstdio>
#include"options/option.h"
#include"options/log.h"
#include"crypt.h"
using namespace std;

int main(int ac, char **av)
{//sha256 0x2323f1 -> result
	CMDoption co{
		{"hex", "hex big number to hash with sha256", "0x123456"}
	};
	if(!co.args(ac, av)) return 0;
	mpz_class z{co.get<const char*>("hex")};
	Log::get_instance()->set_log_filter("d");
	Log::get_instance()->set_log_level(Log::DEBUG);
	LOG << "you entered " << showbase << hex << z << endl;
	LOG << "this will not be printed" << endl;
	unsigned char ar[5000];
	int k = mpz_sizeinbase(z.get_mpz_t(), 16);
	if(k % 2) k++;
	k /= 2;
	mpz2bnd(z, ar, ar + k);
	SHA2 sha;
	for(unsigned char c : sha.hash(ar, ar + k)) printf("%02x", c);
	cout << endl;
}
