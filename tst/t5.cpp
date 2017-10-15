#include"server.h"
#include<fstream>
#include<iostream>
using namespace std;

int main()
{
	char buf[100000];
	ifstream f("logo.jpg");
	int i;
	for(i=0; f >> noskipws >> buf[i]; i++);
	for(int j=0; j<i; j++) cout << buf[j];
}

