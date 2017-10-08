#pragma once
#include<map>
#include<string>
using namespace std;

class HTMLServer {
public:
	std::string operator()(std::string s);

protected:
	virtual void process() {}//child should implement this
	std::map<std::string, std::string> nameNvalue_;//parameter & cookie
	std::string content_, requested_document_;//set content_

private:
	void parse_multipart(std::istream& is);
	std::string boundary_;
	static std::map<std::string, std::string> fileNhtml_;
	const std::string header_ 
		= "HTTP/1.1 200 OK\r\nContent-Type: text/html; charset=utf-8\r\nContent-Length: ";
};
