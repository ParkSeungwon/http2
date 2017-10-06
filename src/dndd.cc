#include"dndd.h"
using namespace std;

Dndd::Dndd()
{
	sq.connect("localhost", "shopping_mall", "shopping_mall", "shopping_mall");
}

void Dndd::process()
{
	if(requested_document_ == "login.cgi") login();
}
	
void Dndd::login()
{
	sq.select("회원", "where 이메일='" + nameNvalue_["email"] + "';");
	auto it = sq.begin();

	if((*it)[2] == nameNvalue_["password"]) {
		id = static_cast<string>((*it)[0]);
		password = static_cast<string>((*it)[2]);
		level = static_cast<int>((*it)[5]);
		content_ = static_cast<string>((*it)[1]) + "님 반갑습니다.";
	} else content_ = "log in failed";
}

