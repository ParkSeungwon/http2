#pragma once
#include<map>
#include<string>
using namespace std;

class HTMLServer {
public:
	HTMLServer();
	std::string operator()(std::string s);
	std::string event();

protected:
	virtual void process() {}//child should implement this
	std::map<std::string, std::string> nameNvalue_, cookies_;//parameter & cookie
	std::string content_;//set content_

private:
	std::string urldecode(std::string s);
	std::string requested_document_;
	const std::map<std::string, std::string> fileNhtml_;
	const std::string header_ 
		= "HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nContent-Length: ";
};

class Dndd : public HTMLServer {
public:
protected:
	virtual void process() {
		content_.replace(content_.find("사나이"), 6, "Man");
	}
};
