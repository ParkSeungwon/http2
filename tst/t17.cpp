#include<algorithm>
#include<cassert>
#include<iostream>
#include<fstream>
#include<json/json.h>
using namespace std;

Json::Value pem2json(istream&);
int main(int ac, char** av)
{
	ifstream f(av[1]);
	cout << pem2json(f);
}

