#include"server.h"
#include"middle.h"
#include"options/option.h"
using namespace std;


int main(int ac, char** av)
{//middle.x 3000 2001
	CMDoption co{
		{"port", "listening port", 3000},
		{"inner port", "web hosting port", 2001}
	};
	if(!co.args(ac, av)) return 0;
	Middle sv{co.get<int>("port"), co.get<int>("inner port")};
	sv.start();
}

