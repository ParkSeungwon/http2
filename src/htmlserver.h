#include<iostream>
#include<sstream>
#include<string>
#include"server.h"
#include"util.h"
using namespace std;

class HTMLServer {
public:
	std::string operator()(std::string s);

protected:
	virtual void process() {}//child should implement this
	std::map<std::string, std::string> nameNvalue_, cookies_;//parameter & cookie
	std::string content_;//set content_

private:
	std::string urldecode(std::string s);
	std::string requested_document_;
	static std::map<std::string, std::string> fileNhtml_;
	const std::string header_ 
		= "HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nContent-Length: ";
};

