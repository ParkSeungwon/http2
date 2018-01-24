#include<iostream>
#include<vector>
#include"crypt.h"
using namespace std;

int main(int ac, char** av)
{
	unsigned char c; vector<unsigned char> v;
	while(cin >> noskipws >> c) v.push_back(c);
	cout << "<img src='data:image/jpeg;base64,";
	cout << base64_encode(v);
	cout << "'>";
}

