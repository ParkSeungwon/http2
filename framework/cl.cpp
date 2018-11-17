#include<iostream>
#include<string>
#include<atomic>
#include"server.h"
#include"asyncqueue.h"
#include"options/option.h"
using namespace std;

int main(int ac, char** av)
{
	CMDoption co{
		{"port", "listening port", 3000},
		{"host", "web hosting address", "127.0.0.1"}
	};
	if(!co.args(ac, av)) return 0;
	Client cl{co.get<const char*>("host"), co.get<int>("port")};
	AsyncQueue<string> aq{bind(&Client::recv, &cl, 0), 
		[](string s) { cout << s << endl; } };//how beautiful
	string s;
	while(cin >> s) {
		cl.send(s);
		if(s == "end") break;
	}
}
