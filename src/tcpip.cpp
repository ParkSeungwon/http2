#include<iostream>
#include<string>
#include"server.h"
using namespace std;

class Functor
{
public:
	int i=0;
	string operator()(string s) {
		i++;
		return s + to_string(i) +'\n';
	}
} f;

int main()
{
	Server sv;
	sv.start(f);
}
