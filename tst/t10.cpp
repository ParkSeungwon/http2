#include<map>
#include<string>
#include<iostream>
using namespace std;

int main()
{
	map<string, string> m;
	m["pass"] = "cockcodk0";
	cout << (m["pass"] == string("cockcodk0"));
}

