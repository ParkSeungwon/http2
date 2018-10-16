#include<fmt/format.h>
#include"crypt.h"
using namespace std;

int main(int ac, char **av)
{//sha256 0x2323f1 -> result
	mpz_class z{av[1]};
	unsigned char ar[5000];
	int k = mpz_sizeinbase(z.get_mpz_t(), 16);
	if(k % 2) k++;
	k /= 2;
	mpz2bnd(z, ar, ar + k);
	SHA2 sha;
	for(unsigned char c : sha.hash(ar, ar + k)) fmt::print("{:02x}", c);
}
