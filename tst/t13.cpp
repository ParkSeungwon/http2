#include<gmpxx.h>
#include<thread>
#include<unistd.h>
#include<json/json.h>
#include<iostream>
using namespace std;
int main()
{
	int k = 0;
	Json::Value jv;
	jv[0] = "z@d.d";
	jv[1] = 32;
	jv[2] = true;
	jv[3] = "123123123123131312313131231313131321313123";
	jv[4] = (int)mpz_class{32};
	cout << jv << endl;
	jv.clear();
	cout << jv << endl;
}
