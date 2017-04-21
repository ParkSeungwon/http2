#include<iostream>
#include<string>
#include<atomic>
#include"server.h"
#include"asyncqueue.h"
using namespace std;

void f(string s) {
	cout << s << endl;
}

const char* win_def = R"(
W1--------------------------------------------------------^
|
|
|   L1-----  T1----------------<
|   | Login  |    
|            |
|
|
|
|
|                B1------>     B2------->
|                | OK          | Cancel
|
<-------------------------------------------------------
)";
int main(int ac, char** av)
{
	Client cl{"127.0.0.1", atoi(av[1])};
	AsyncQueue<string> aq{bind(&Client::recv, &cl), f};//how beautiful
	string s;
	while(cin >> s) {
		cl.send(s + '\n');
		if(s == "end") break;
	}
}
