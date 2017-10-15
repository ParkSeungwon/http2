#include<fstream>
#include<sstream>
#include<cstring>
#include<iostream>
#include"util.h"
#include"server.h"
#include"htmlserver.h"
using namespace std;

map<string, string> HTMLServer::fileNhtml_;
HTMLServer::HTMLServer()
{
	for(auto& a : getdir(".")) {//read html files in the current directory
		size_t pos = a.first.find_last_of('.');
		if(pos != string::npos) {
			string ext = a.first.substr(pos+1);
			if(ext == "html" || ext == "js" || ext == "css" || ext == "jpg") {
				cout << "loading " << a.first << endl;
				string s; char c;
				ifstream f(a.first);
				while(f >> noskipws >> c) s += c;
				fileNhtml_[a.first] = s;
			}
		}
	}
}

std::string HTMLServer::operator()(string s) 
{//will set requested_document and nameNvalue (= parameter of post or get)
	nameNvalue_.clear();
//	cout << s << flush;
	stringstream ss; ss << s; ss >> s;
	if(s == "POST") {//parse request and header
		ss >> requested_document_;
		requested_document_ = requested_document_.substr(1);
		while(s != "\r") getline(ss, s);
		nameNvalue_ = parse_post(ss);
	} else if(s == "GET") {
		ss >> s;
		stringstream ss2; ss2 << s;//GET '/login.html?adf=fdsa'
		getline(ss2, s, '?');
		requested_document_ = s.substr(1);//get rid of '/'
		nameNvalue_ = parse_post(ss2);
	}
	if(requested_document_ == "") requested_document_ = "index.html";
	content_ = fileNhtml_[requested_document_];
	process();//derived class should implement this-> set content_ & cookie
	string r = header_[0] + set_cookie() + header_[1] + 
			mime_[requested_document_.find(".jpg") != string::npos]
			+ header_[2] + to_string(content_.size()) + "\r\n\r\n" + content_;
	cout << r.size() << " sent " << endl;
	return r;
}

string HTMLServer::set_cookie()
{//manipulate map cookie_ to set cookie --> deprecated because of middle server
	string cookie;
	for(const auto& a : cookie_) 
		cookie += "Set-Cookie:" + a.first + '=' + a.second + ";\r\n";
	cookie_.clear();
	return cookie;
}

