#include<thread>
#include<unistd.h>
#include<json/json.h>
#include<iostream>
using namespace std;
int main()
{
	int k = 0;
	Json::Value jv;
	jv[0]["email"] = "z@d.d";
	cout << jv;
	jv.clear();
	cout << jv;
}
