#include<iostream>
#include<sstream>
#include<string>
#include"server.h"
#include"util.h"
using namespace std;

class HTMLServer
{
public:
	void set_template(std::string filename);
	std::string get_template(std::string filename);
	int i=0;
	std::string operator()(std::string s);

protected:
	std::map<std::string, std::string> nameNvalue_;
	std::string id_;
	int level_;
	std::string content_;

private:
	static std::map<std::string, std::string> fileNhtml_;
	const std::string header_ 
		= "HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nContent-Length: ";
};

