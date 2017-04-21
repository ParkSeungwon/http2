#include<iostream>
#include<regex>
#include<sstream>
#include"matrix.h"
using namespace std;

string getstring() {
	string s;
	cin >> s;
	return s;
}

Matrix<char> win_def(string s)
{///window ascii art -> 2 dimension matrix
	stringstream ss;
	ss << s;
	string t;
	int line = 0, maxlen = 0;
	while(getline(ss, t)) {
		int len = t.size();
		maxlen = len > maxlen ? len : maxlen;
		line++;
	}
	Matrix<char> mat{maxlen, line};
	int x = 1, y = 0;
	for(int i=0; i<s.size(); i++) {
		if(s[i] == '\n') y++, x=1; 
		else mat[x++][y] = s[i];
	}
	return mat;
}

const char* win_def_str = R"(
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


int main()
{
	string s{win_def_str};
	auto mat = win_def(s);
	cout << mat;

	regex e{R"(([A-Z]\d)-+)"};
	smatch m;
	while(regex_search(s, m, e)) {
		cout << m[0] << ' ';
		cout << m[1].str().size();
		s = m.suffix();
	}
}
