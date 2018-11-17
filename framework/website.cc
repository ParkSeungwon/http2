#include<fstream>
#include<sstream>
#include<cstring>
#include<iostream>
#include<experimental/filesystem>
#include"database/util.h"
#include"server.h"
#include"website.h"
using namespace std;
using namespace std::experimental::filesystem;

map<string, string> WebSite::fileNhtml_;
WebSite::WebSite(string dir)
{
	dir_ = dir;
	reload(dir_);
}

void WebSite::reload(string dir)
{
	fileNhtml_.clear();
	for(const path& a : directory_iterator{dir}) {//directory entry has operator path
		ifstream f(a.string()); string s; char c;
		while(f >> noskipws >> c) s += c;
		fileNhtml_[a.filename()] = s;
		cout << "loading " << a.filename() << endl;
	}
}
bool WebSite::swap(string b, string a)
{//child classes will use this to change content_
	if(content_.find(b) == string::npos) return false;
	content_.replace(content_.find(b), b.size(), a);
	return true;	
}

bool WebSite::append(string a, string b)
{
	if(content_.find(a) == string::npos) return false;
	content_.insert(content_.find(a) + a.size(), b);
	return true;	
}

std::string WebSite::operator()(string s) 
{//will set requested_document and nameNvalue (= parameter of post or get)
	nameNvalue_.clear();
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
	} else if(s == "RELOAD") reload(dir_);
	if(requested_document_ == "") requested_document_ = "index.html";
	content_ = fileNhtml_[requested_document_];
	try {
		process();//derived class should implement this -> set content_ & cookie
	} catch(const exception& e) {
		cerr << e.what() << endl;
	}
	return header_ + to_string(content_.size()) + "\r\n\r\n" + content_;
}

