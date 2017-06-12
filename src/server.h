#pragma once
#include<functional>
#include"tcpip.h"

class Client : public Tcpip
{
public:
	Client(std::string ip = "127.0.0.1", int port = 2001); ///<constructor
private:
	std::string get_addr(std::string host);
};

class Server : public Tcpip
{
public:
	Server(int port = 2001, unsigned int time_out = 600, int queue_limit = 10,
			std::string end_string = "end");
	template<typename T> void start(T& f);

protected:
	std::string end_string;
	int time_out;

private:
	void init_template();
};

class Functor
{
public:
	int i=0;
	std::string operator()(std::string s) {
		if(s.find("GET") != std::string::npos) return R"(
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
		std::cout << s << std::endl;
		i++;
		return s + std::to_string(i) +'\n';
	}
};


