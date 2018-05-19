#include<fstream>
#include<iostream>
#include<json/json.h>
using namespace std;

Json::Value pem2json(istream& is);

int main(int ac, char** av) {
	ifstream f(av[1]);
	cout << pem2json(f) << endl;
}
