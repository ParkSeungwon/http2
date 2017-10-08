#include<fstream>
#include"dndd.h"
using namespace std;

Dndd::Dndd()
{
	sq.connect("localhost", "shopping_mall", "shopping_mall", "shopping_mall");
}

void Dndd::process()
{
	if(requested_document_ == "login.cgi") login();
	else if(requested_document_ == "signin.cgi") signin();
	else if(requested_document_ == "up.cgi") upload();
}
	
void Dndd::login()
{
	if(!sq.select("회원", "where 이메일='" + nameNvalue_["email"] + "';")) return;
	auto it = sq.begin();

	if((*it)[2] == nameNvalue_["password"]) {
		id = static_cast<string>((*it)[0]);
		password = static_cast<string>((*it)[2]);
		level = static_cast<string>((*it)[5]);
		content_ = static_cast<string>((*it)[1]) + "님 반갑습니다.";
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
}

void Dndd::upload()
{
//	if(level != "" && stoi(level) < 2) return;
	sq.select("상품", "limit 1");
	sq.insert({"null", "zezeon@msn.com", nameNvalue_["desc"], nameNvalue_["goods"]});
	ofstream f("image/fdfd.jpg");
	content_ = nameNvalue_["file"];
}

