#include"mysqldata.h"
using namespace std;

int main()
{
	SqlQuery sq;
	sq.connect("localhost", "shopping_mall", "shopping_mall", "shopping_mall");
	sq.select("회원");
	for(auto& a : sq) {
		if(a[2] == "cockcodk0") cout << "password match" << endl;
		for(auto& b : a) {
			cout << b << ' ';
			string s = b;
			cout << endl;
		}
	}
}

