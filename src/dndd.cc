#include<cassert>
#include<fstream>
#include"dndd.h"
using namespace std;

DnDD::DnDD()
{
	sq.connect("localhost", "dndd", "dndddndd", db);
}

void DnDD::process()
{
	cout << requested_document_ << endl;
	for(auto& a : nameNvalue_) cout << a.first << ':' << a.second << endl;
	if(requested_document_ == "index.html") index();
	else if(requested_document_ == "signin.cgi") signin();
	else if(requested_document_ == "up.cgi") upload();
	else if(requested_document_ == "search.cgi") search();
}

void DnDD::search()
{
	string s = nameNvalue_["search"];
	sq.select("상품", 
			"where 상품정보 like \'%" + s + "%\' or 상품명 like \'%" + s + "%\'");
	content_ = "<table bgcolor=\"#005500\" border=\"1\">";
	for(auto& a : sq) {
		content_ += "<tr><td><img src=\"";
		ifstream f("image/" + (string)a[0]);
		char c;
		while(f >> noskipws >> c) content_ += c;
		content_ += "\" height=300 width=300 /></td>";
		for(const string& b : a) content_ += "<td>" + b + "</td>";
		content_ += "</tr>";
	}
	content_ += "</table>";
}

void DnDD::if_logged()
{
	swap("LOGIN", "LogOut");
	swap("SIGNIN", "Sell Item");
	swap("signin.html", "upload.html");
	swap("visible", "hidden");
}

void DnDD::index()
{
	if(nameNvalue_.empty()) {//just page load, no submit click
		if(id != "") if_logged();//if logged in
	} else {//submit click
		for(auto& a : nameNvalue_) cout << a.first << ':' << a.second << endl;
		if(id == "") {//login attempt
			if(!sq.connect("localhost", "dndd", "dndddndd", nameNvalue_["group"])) return;
			if(!sq.select("Users", "where email='" + nameNvalue_["id"] + "' order by date desc limit 1"))
				swap("replace\">", "replace\">No such ID");
			else {
				vector<string> v;
				for(auto& a : sq) for(auto& b : a) v.push_back(b);
				if(v[1] == sq.password(nameNvalue_["pass"])) {//login succeed
					id = v[0]; name = v[1]; password = v[2]; level = v[5];
					if_logged();
					assert(id != "");
					swap("replace\">", "replace\">" + name + "님 반갑습니다.");
				} else swap("replace\">", "replace\">Log in failed"); 
			}
		} else id = name = password = level = "";//logout
	}
}

void DnDD::signin()
{//sq.select returns row count
	if(sq.select("회원", "where 이메일='" + nameNvalue_["email"] + "';"))
		content_ = "아이디가 이미 존재합니다.";
	else {//select will retrieve table structure, which makes inserting possible
		sq.insert({nameNvalue_["email"], nameNvalue_["username"], nameNvalue_["password"], nameNvalue_["address"], nameNvalue_["tel"], "1"});
		content_ = "가입완료<br><a href=\"index.html\">메인화면으로</a><br>";
	}
	cout << id << endl;
}

void DnDD::upload()
{
	if(level != "" && stoi(level) < 2 && nameNvalue_["desc"].size() < 2) return;
	sq.select("상품", "order by 상품아이디 desc limit 1");
	int max = 1;
	for(auto& a : sq) max = a[0];
	sq.insert({to_string(max+1), id, nameNvalue_["desc"], nameNvalue_["goods"]});
	ofstream f("image/" + to_string(max+1));
	for(char& c : nameNvalue_["file"]) if(c == ' ') c = '+';//post parse contradiction
	f << nameNvalue_["file"];
	content_ = "uploaded<br> <a href=\"index.html\">메인화면으로</a><br>";
}

