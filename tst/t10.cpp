#include<string>
#include<iostream>
#include<fstream>
#include<vector>
#include"src/bootstrap.h"

using namespace std;

class A : public BootStrapServer
{
public:
	static string carousel(vector<string> img, vector<string> desc, vector<string> href) {
		return BootStrapServer::carousel(img, desc, href);
	}
};


int main()
{
	ifstream f("carousel.txt");
	int n; string s; vector<string> v[3];
	f >> n;
	getline(f, s);
	for(int i=0; i<n; i++) {
		for(int j=0; j<3; j++) {
			getline(f, s);
			v[j].push_back(s);
		}
	}
	for(int i=0; i<3; i++) for(auto s : v[i]) cout << s << ' ';
	s = A::carousel(v[0], v[1], v[2]);
	cout << s;
}

