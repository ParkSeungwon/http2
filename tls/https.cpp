#include"options/option.h"
#include"tls.h"
#include"https.h"
#include"crypt.h"
using namespace std;

int main(int ac, char** av) 
{
	CMDoption co{
		{"port", "listening port", 4433},
		{"inner port", "http host port", 2001},
	};
	if(!co.args(ac, av)) return 0;
	HTTPS sv{co.get<int>("port"), co.get<int>("inner")};
	sv.start();
}


