#include<fstream>
#include"htmlserver.h"
using namespace std;

map<string, string> HTMLServer::fileNhtml_;
std::string HTMLServer::operator()(string s) 
{
	std::stringstream ss; ss << s;
//	process_header(ss);
//	if(s.find("GET") != string::npos) content =  R"(
//)";
//	else if(s.find("POST") != string::npos) {
//		cout << s << endl;
//		stringstream ss;
//		ss << s;
//		while(s != "\r") getline(ss, s);//pass header part
//		auto m = parse_post(ss);
//		for(auto el : m) content += el.first + ':' + el.second + '\n';
//	}
//	i++;
	return header_ + to_string(content_.size()) + "\r\n\r\n" + content_;
}

void HTMLServer::set_template(string filename)
{
	string s; char c;
	ifstream f(filename);
	while(f >> noskipws >> c) s += c;
	fileNhtml_[filename] = s;
}

string HTMLServer::get_template(string filename)
{
	return fileNhtml_[filename];
}

