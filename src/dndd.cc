#include<regex>
#include<fstream>
#include"dndd.h"
using namespace std;

Dndd::Dndd()
{
	sq.connect("localhost", "shopping_mall", "shopping_mall", "shopping_mall");
}

void Dndd::process()
{
	const char* rq[]
		= {"login.cgi", "signin.cgi", "up.cgi", "index.html", "logo.jpg", ""};
	int i;
	for(i=0; i<6; i++) if(rq[i] == requested_document_) break;
	switch(i) {
		case 0: login(); break;
		case 1: signin(); break;
		case 2: upload(); break;
		case 3: index(); break;
		case 4: {
					ofstream f("/tmp/tt");
					f << content_ << endl;
				}
	}
}

void Dndd::index()
{
	regex e{R"((log_panel.+?>)[\s\S]+?<br>[\s\S]+?<br>)"};
	if(id != "") content_ = regex_replace(content_, e, "$1<h3>" + id + " Hello</h3>");
}
	
void Dndd::login()
{
	if(!sq.select("회원", "where 이메일='" + nameNvalue_["email"] + "';")) return;
	auto it = sq.begin();

	if((*it)[2] == nameNvalue_["password"]) {
		id = static_cast<string>((*it)[0]);
		password = static_cast<string>((*it)[2]);
		level = static_cast<string>((*it)[5]);
		name = static_cast<string>((*it)[1]);
		content_ = name + "님 반갑습니다.";
	} else content_ = "log in failed";
}

void Dndd::signin()
{//sq.select returns row count
	if(sq.select("회원", "where 이메일='" + nameNvalue_["email"] + "';"))
		content_ = "아이디가 이미 존재합니다.";
	else {//select will retrieve table structure, which makes inserting possible
		sq.insert({nameNvalue_["email"], nameNvalue_["username"], nameNvalue_["password"], nameNvalue_["address"], nameNvalue_["tel"], "1"});
		content_ = "가입완료";
	}
	cout << id << endl;
}

void Dndd::upload()
{
//	if(level != "" && stoi(level) < 2) return;
	sq.select("상품", "limit 1");
	sq.insert({"null", id, nameNvalue_["desc"], nameNvalue_["goods"]});
	ofstream f("image/fdfd.jpg");
	content_ = nameNvalue_["file"];
}

