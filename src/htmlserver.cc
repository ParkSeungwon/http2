#include<fstream>
#include"util.h"
#include"htmlserver.h"
using namespace std;

static map<string, string> tmp;
static map<string, string> set_template(string filename)
{
	string s; char c;
	ifstream f(filename);
	while(f >> noskipws >> c) s += c;
	tmp[filename] = s;
}

static map<string, string>&& init()
{
	for(auto& a : getdir(".")) {//read html files in the current directory
		size_t pos = a.first.find_last_of('.');
		if(pos != string::npos) {
			string ext = a.first.substr(pos+1);
			if(ext == "html" || ext == "js" || ext == "css") set_template(a.first);
		}
	}
	return move(tmp);
}

map<string, string> HTMLServer::fileNhtml_ = init();

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
	content_ = fileNhtml_[requested_document_];
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

