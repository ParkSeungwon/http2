#include<regex>
#include<fstream>
#include<iostream>
#include<string>
using namespace std;

int main()
{
	string s; char c;
	ifstream f("index.html");
	while(f >> noskipws >> c) s += c;
	regex e{R"((log_panel.+?>)([\s\S]+?)(</div>))"};
	s = regex_replace(s, e, "$1박승원$3");
	cout << s;
}

