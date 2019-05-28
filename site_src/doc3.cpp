#include<map>
#include<iostream>
#include"framework/server.h"//Server class
#include"framework/website.h"//WebSite class
using namespace std;

class My_site : public WebSite
{
public:
	My_site() : WebSite{"site_html"} {}
protected:
	void process() {
		if(requested_document_ == "doc1.html") {
			if(!nameNvalue_.empty()) {
				content_ = "<html><h2>";
				for(auto [a, b] : nameNvalue_) content_ += a + ':' + b + "<br>";
				content_ += "</h2></html>";
			}
		} else if(requested_document_ == "jquery_post") content_ ="respose from server";
		else if(requested_document_ == "s2.html") {
			for(const auto& [name, value] : nameNvalue_) m[name] = value;
		} else if(requested_document_ == "s3.html") {
			for(const auto& [name, value] : nameNvalue_) m[name] = value;
//			for(const auto& [a, b] : m) content_ += a + " : " + b + "<br>";
			swap("@ADDRESS", m["address"]);
			swap("@NAME", m["name"]);
			swap("@ID", m["id"]);
			swap("@EMAIL", m["email"]);
		}
	}
	map<string, string> m;
};

int main(int ac, char** av)
{
	My_site my_site;//directory name relative to your exe file
							//directory contains html files
	Server sv{2000};//port number
	cout << "opening port " << 2000 << endl;
	sv.start(my_site);//go infinite loop
}


