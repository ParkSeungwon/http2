#include<tcpip.h>
#include<server.h>
#include<iostream>
using namespace std;

struct F {
	string operator()(string s) {
		cout << s << endl;
		return s;
	}
} f;

int main()
{
	Server sv;
	sv.start(f);
}
