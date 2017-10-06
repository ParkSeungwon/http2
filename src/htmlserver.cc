#include<fstream>
#include<thread>
#include<sstream>
#include<iostream>
#include"util.h"
#include"server.h"
#include"htmlserver.h"
using namespace std;

static map<string, string> tmp;

static map<string, string> init()
{
	for(auto& a : getdir(".")) {//read html files in the current directory
		size_t pos = a.first.find_last_of('.');
		if(pos != string::npos) {
			string ext = a.first.substr(pos+1);
			if(ext == "html" || ext == "js" || ext == "css") {
				cout << a.first << endl;
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

std::string HTMLServer::event()
{//event from server
	this_thread::sleep_for(5s);
	return "5 seconds passed";
}

std::string HTMLServer::operator()(string s) 
{//will set requested_document and nameNvalue (= parameter of post or get)
	nameNvalue_.clear();
	stringstream ss; ss << s; ss >> s;
	if(s == "POST") {//parse request and header
		ss >> requested_document_;
		while(s != "\r") getline(ss, s);
		nameNvalue_ = parse_post(ss);
	} else if(s == "GET") {
		ss >> s;
		stringstream ss2; ss2 << s;
		getline(ss2, s, '?');
		requested_document_ = s.substr(1);
		while(getline(ss2, s, '=')) {
			string t;
			getline(ss, t, '&');
			nameNvalue_[urldecode(s)] = urldecode(t);
		}
	}
	if(requested_document_ == "/") requested_document_ = "index.html";
	content_ = fileNhtml_.at(requested_document_);
	if(!nameNvalue_.empty()) 
		process();//derived class should implement this-> set content_ & cookie
	return header_ + to_string(content_.size()) + "\r\n\r\n" + content_;
}

string HTMLServer::urldecode(string s)
{
	int pos;
	for(pos = s.find('+', 0); pos != string::npos; pos = s.find('+', pos))
		s.replace(pos, 1, 1, ' ');
	for(pos = s.find('%', 0); pos != string::npos; pos = s.find('%', pos))
		s.replace(pos, 3, 1, (char)stoi(s.substr(pos + 1, 2), nullptr, 16));
	return s;
}

//static void template_init()
//{
//	HTMLServer hs;
//	Server sv;
//	template void Server::start(HTMLServer);
//}
