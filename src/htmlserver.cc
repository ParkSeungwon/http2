#include<fstream>
#include<sstream>
#include<cstring>
#include<iostream>
#include"util.h"
#include"server.h"
#include"htmlserver.h"
using namespace std;

static map<string, string> init()
{//load webpages
	map<string, string> tmp;
	for(auto& a : getdir(".")) {//read html files in the current directory
		size_t pos = a.first.find_last_of('.');
		if(pos != string::npos) {
			string ext = a.first.substr(pos+1);
			if(ext == "html" || ext == "js" || ext == "css" || ext == "jpg") {
				cout << "loading " << a.first << endl;
				string s; char c;
				ifstream f(a.first);
				while(f >> noskipws >> c) s += c;
				tmp[a.first] = s;
			}
		}
	}
	return tmp;
}

map<string, string> HTMLServer::fileNhtml_ = init();

void HTMLServer::parse_multipart(istream& is)
{
	string s, t, u; char c;
	while(getline(is, s)) {
		if(s == string{"--"} + boundary_ + "--") break;
		else if(s.find(boundary_) != string::npos) {
			if(u != "") nameNvalue_[t] = u, u = "";
			is >> s; is >> s; for(int i=0; i<6; i++) is >> c;//pass
			is >> s; s.pop_back(); if(s.back() == '\"') s.pop_back();//set name
			is >> c; 
			if(c == 'f') {//if file data
				for(int i=0; i<9; i++) is >> c;//pass
				is >> t; t.pop_back();//set filename
				nameNvalue_[s] = t;
				for(int i=0; i<3; i++) getline(is, s);
			} else {//if name=value
				for(int i=0; i<4; i++) getline(is, t);
				nameNvalue_[s] = t;
			}
		} else u += s + '\n';
	}
}

std::string HTMLServer::operator()(string s) 
{//will set requested_document and nameNvalue (= parameter of post or get)
	nameNvalue_.clear();
	boundary_ = "";
	cout << s << flush;
	stringstream ss; ss << s; ss >> s;
	if(s == "POST") {//parse request and header
		ss >> requested_document_;
		requested_document_ = requested_document_.substr(1);
		while(s != "\r") {
			getline(ss, s);
			if(!strncmp(s.data(), "Content-Type: multipart", 23)) {
				boundary_ = s.substr(s.find_last_of('=') + 1);
				cout << "boundary detected : " << boundary_ << endl;
			}
		}
		if(boundary_ == "") nameNvalue_ = parse_post(ss);
		else parse_multipart(ss);
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
	return header_ + to_string(content_.size()) + "\r\n\r\n" + content_;
}
