#pragma once
#include<map>
#include<string>
using namespace std;

class HTMLServer 
{//specific server will derive this class
public:
	HTMLServer();
	std::string operator()(std::string s);

protected:
	virtual void process() {}//child should implement this
	int swap(std::string, std::string);
	std::map<std::string, std::string> nameNvalue_, cookie_;//parameter& cookie
	std::string content_, requested_document_;//set content_

private:
	std::string set_cookie();
	static std::map<std::string, std::string> fileNhtml_;
	const std::string header_[3] = {"HTTP/1.1 200 OK\r\n", "Content-Type: ", "\r\nContent-Length: "};
	const std::string mime_[2] = { "text/html; charset=utf-8", "image/jpeg" };
};
