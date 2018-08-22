#include<fstream>
#include<iostream>
#include"crypt.h"
using namespace std;

int main(int ac, char **av) {
	ifstream f(av[1]);
	cout << pem2json(f) << endl;
}

