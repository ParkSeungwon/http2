#include<iostream>
#include<sstream>
#include<string>
#include"server.h"
#include"util.h"
using namespace std;

class Functor
{
public:
	int i=0;
	string operator()(string s) {
		if(s.find("GET") != string::npos) content =  R"(
<!DOCTYPE html>
<html>
<head>
<meta charset="utf-8" />
<title></title>
</head>
<body>
<form  method="post">
ID : <input type="text" name="id" value="" /><br>
Password : <input type="password" name="password" value="" />
<input type="submit" name="" value="LogIn" />
</form>
우리는 사나이 
</body>
</html>
)";
		else if(s.find("POST") != string::npos) {
			cout << s << endl;
			stringstream ss;
			ss << s;
			while(s != "\r") getline(ss, s);//pass header part
			auto m = parse_post(ss);
			for(auto el : m) content += el.first + ':' + el.second + '\n';
		}
		i++;
		return header + to_string(content.size()) + "\r\n\r\n" + content;
	}

private:
	string header = R"(
HTTP/1.1 200 OK
Content-Type: text/html;
Content-Length: )";
	string content;
} f;

int main(int ac, char** av)
{
	int port = ac < 2 ? 2001 : atoi(av[1]);
	Server sv{port};
	sv.start(f);
}
