#include<cassert>
#include<fstream>
#include<regex>
#include"dndd.h"
using namespace std;

DnDD::DnDD()
{
	sq.connect("localhost", "dndd", "dndddndd", "dndd");
}

void DnDD::process()
{
	cout << requested_document_ << endl;
	for(auto& a : nameNvalue_) cout << a.first << ':' << a.second << endl;
	if(requested_document_ == "index.html") index();
	else if(requested_document_ == "main.html") mn();
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
	ifstream f("carousel.txt");
	int n; string s; vector<string> v[3];
	f >> n;
	getline(f, s);
	for(int i=0; i<n; i++) {
		for(int j=0; j<3; j++) {
			getline(f, s);
			v[j].push_back(s);
		}
	}
	swap("CAROUSEL", carousel(v[0], v[1], v[2]));
}

void DnDD::mn()
{
	if(nameNvalue_["db"] != "")//if first connection -> set database
		sq.connect("localhost", "dndd", "dndddndd", db = nameNvalue_["db"]);
	vector<string> v = sq.show_tables();//navbar setting
	string t;
	for(auto s : v) 
		if(s != "Users" && s != "Vote" && s != "Follow")
			t += "<li><a href=\"main.html?field=" + s + "\">" + s + "</a></li>"; 
	swap("NAVITEM", t); t = "";

	if(nameNvalue_["email"] != "") {//if login attempt
		sq.select("Users", "where email = \'" + nameNvalue_["email"] + "\' order by date desc limit 1");
		v.clear();
		for(auto a : sq) for(auto b : a) v.push_back(b);
		if(v[1] == sq.encrypt(nameNvalue_["pwd"])) id=v[0], level=v[2], name=v[3];
	}
	regex e{R"(<form[\s\S]+?</form>)"};
	if(id != "") content_ = regex_replace(content_, e, name + "님 레벨" + level +"으로 로그인되었습니다.");

	if(nameNvalue_["field"] != "") {//if navbar select
		sq.select(table = nameNvalue_["field"], "where title <> \'코멘트임.\' order by num desc, page, date, edit desc");
		sq.group_by("email", "date");
		for(auto& a : sq) {
			v.clear();
			for(auto b : a) v.push_back(b);
			if(a[1] == "0") {//if book
				t += "<div class=\"panel-heading\"><a href=\"." + v[0];
				t += "\" data-toggle=\"collapse\">" + v[0] + ". " + v[3] + "</div>";
			} else {
				t += "<div class=\"panel-body collapse ";
				t += v[0] + "\">&nbsp;&nbsp;" + v[1] + ". " + v[3] + "</div>";
			}
		}
		swap("PANEL", t);
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

