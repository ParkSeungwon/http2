#include<iostream>
#include<string>
#include"server.h"
using namespace std;

class Functor
{
public:
	int i=0;
	string operator()(string s) {
		if(s.find("GET") != string::npos) return R"(
HTTP/1.1 200 OK
Content-Type: text/html; 

<!DOCTYPE html>
<html>
<head>
<meta charset="utf-8" />
<title></title>
</head>
<body>
<form action="/cgi-bin/login.cgi" method="post">
ID : <input type="text" name="id" value="" /><br>
Password : <input type="password" name="password" value="" />
<input type="submit" name="" value="LogIn" />
</form>
우리는 사나이 
</body>
</html>
)";
		cout << s << endl;
		i++;
		return s + to_string(i) +'\n';
	}
} f;

int main(int ac, char** av)
{
	int port = ac < 2 ? 2001 : atoi(av[1]);
	Server sv{port};
	sv.start(f);
}
