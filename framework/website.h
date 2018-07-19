#pragma once
#include<map>
#include<string>
using namespace std;

class WebSite 
{//specific server will derive this class
public:
	WebSite();
	std::string operator()(std::string s);

protected:
	virtual void process() {}//child should implement this
	bool swap(std::string, std::string), append(std::string, std::string);
	std::map<std::string, std::string> nameNvalue_;//parameter
	std::string content_, requested_document_;//set content_

private:
	static std::map<std::string, std::string> fileNhtml_;
	const std::string header_ = 
	"HTTP/1.1 200 OK\r\nContent-Type: text/html; charset=utf-8\r\nContent-Length: ";
};
