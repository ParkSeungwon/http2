#include<cassert>
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
		= {"index.html", "signin.cgi", "up.cgi", "index.html", "logo.jpg", ""};
	int i;
	for(i=0; i<6; i++) if(rq[i] == requested_document_) break;
	switch(i) {
		case 0: index(); break;
		case 1: signin(); break;
		case 2: upload(); break;
		case 3: index(); break;
		case 4: {
					ofstream f("/tmp/tt");
					f << content_ << endl;
				}
	}
}

void Dndd::if_logged()
{
	swap("LogIn", "LogOut");
	swap("SignIn", "Sell Item");
	swap("signin.html", "upload.html");
	swap("visible", "hidden");
}

void Dndd::index()
{
	if(nameNvalue_.empty()) {//just page load, no submit click
		if(id != "") if_logged();//if logged in
	} else {//submit click
		for(auto& a : nameNvalue_) cout << a.first << ':' << a.second << endl;
		if(id == "") {//login attempt
			if(!sq.select("회원", "where 이메일='" + nameNvalue_["email"] + "';"))
				swap("replace\">", "replace\">No such ID");
			else {
				vector<string> v;
				for(auto& a : sq) for(auto& b : a) v.push_back(b);
				for(auto& a : v) cout << a << endl;
				cout << v[2] << ':' << nameNvalue_["pass"]  << ':' << endl;
				if(v[2] == nameNvalue_["pass"]) cout << "same" << endl;
				else cout << "different" << endl;
				for(auto& a : nameNvalue_) cout << a.first << ':' << a.second << endl;
				cout << v[2].size() << ' ' << nameNvalue_["pass"].size() << endl;
				if(v[2] == nameNvalue_["pass"]) {//login succeed
					id = v[0]; name = v[1]; password = v[2]; level = v[5];
					if_logged();
					assert(id != "");
					swap("replace\">", "replace\">" + id + "님 반갑습니다.");
				} else swap("replace\">", "replace\">Log in failed"); 
			}
		} else {//logout

		}
	}
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

