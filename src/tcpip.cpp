#include<iostream>
#include<string>
#include"server.h"
using namespace std;

class Functor
{
public:
	int i=0;
	string operator()() {
		i++;
		return to_string(i) +'\n';
	}
} f;

int main()
{
	Server sv;
	sv.start();
}
