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
	else if(requested_document_ == "signin.html") signin();
	else if(requested_document_ == "search") content_ = search(nameNvalue_["search"]);
	else if(requested_document_ == "page.html") pg();
	else if(requested_document_ == "edit.html") edit();
	else if(requested_document_ == "add.html") add();
	else if(requested_document_ == "new.html") new_book();
	else if(requested_document_ == "comment.html") comment();
	else if(requested_document_ == "vote.html") vote();
	else if(requested_document_ == "follow") content_ = follow();
}

string DnDD::follow()
{
	if(id == "") return "login first";
	if(stoi(level) > 2) return "representative cannot follow"; 

	sq.select("Users", "where email=\'" + nameNvalue_["follow"] + "\' order by date desc limit 1");
	vector<string> v;
	for(auto& a : sq) for(string s : a) v.push_back(s);
	if(stoi(v[2]) < 3) return "you can only follow representatives";

	sq.select("Follow", "limit 1");
	sq.insert({nameNvalue_["follow"], id, 
			nameNvalue_["secret"] == "on" ? "1" : "0", sq.now()});
	return "follow complete";
}

void DnDD::vote()
{
	if(nameNvalue_["option"] == "") {//vote page load
		string r, s = "<label class=\"radio-inline\"><input type=\"radio\" name=\"option\" value=\"";
		for(int i=1; i<=allow[4]; i++) 
			r += s + to_string(i) + "\">" + to_string(i) + "</label>\n";
		swap("OPTIONS", r);
	} else {//vote action post
		sq.select("Vote", "limit 1");
		sq.insert({table, book, id, nameNvalue_["option"], 
				nameNvalue_["secret"] == "on" ? "1" : "0", sq.now(), level});
		content_ = "<a href=\"page.html?table=" + table + "&book=" + book + "&page=" + page + "\">back to page</a>";
	}
}

void DnDD::comment()
{
	if(id == "") content_ = "<script>alert(\"login first.\")</script>";
	else if(stoi(level) < allow[2]) 
		content_ = "<script>alert(\"your level does not qualify.\")</script>"; 
}

void DnDD::new_book()
{
	if(id == "") content_ = "<script>alert(\"login first.\")</script>";
}

void DnDD::add() 
{
	tmp.clear();
	if(nameNvalue_["title"] != "") {//from new.html
		cout << "0" << endl;
		sq.select(table, "order by num desc limit 1");
		vector<string> v;
		for(auto& a : sq) for(string s : a) v.push_back(s);
		book = to_string(stoi(v[0]) + 1);
		cout << "1" << endl;
		sq.insert({book, "0", id, nameNvalue_["title"], 
				nameNvalue_["read"] + nameNvalue_["write"] + nameNvalue_["comment"] 
				+ nameNvalue_["vote"] + '0' + nameNvalue_["option"] + '0', 
				sq.now(), "null"});
		cout << "2" << endl;
		page = "1";
	} else if(id != "" && stoi(level) >= allow[1])//from page.html, check write level
		page = to_string(maxpage(table, book) + 1);
	else content_ = "<script>alert(\"your level does not qualify.\")</script>";
}

void DnDD::edit()
{
	if(page == "0") 
		content_ = "<script>alert(\"This page cannot be edited.\");</script>";
	else if(id == tmp[2]) {
		swap("TITLE", tmp[3]);
		swap("CONTENT", tmp[4]);
	} else content_ = "<script>alert(\"you do not own this page\");</script>";
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

string DnDD::search(string s)
{//return search result as a boot strap panel string
	vector<string> v1 = tables(), v2;
	string t;
	for(string table : v1) {
		sq.select(table, "where title like \'%" + s + "%\' and title <> \'코멘트임.\' order by num desc, page, edit desc" ); 
		sq.group_by("email", "date");
		for(auto& a : sq) {
			v2.clear();
			for(auto& b : a) v2.push_back(b);
			t += "<div class=\"panel-body\"><a href=\"page.html?table=" + table;
			t += "&book=" + v2[0] + "&page=" + v2[1] + "\">" + table + ' ' + v2[0];
			t += '.' + v2[1] + ". " + v2[3] + "</a></div>\n";
		}
	}
	return t;
}

void DnDD::mn()
{//main.html
	if(nameNvalue_["db"] != "") {//if first connection -> set database
		sq.connect("localhost", "dndd", "dndddndd", nameNvalue_["db"]);
		if(nameNvalue_["db"] != db) db = nameNvalue_["db"], id = level = name = "";
	}
	
	vector<string> v = tables();//navbar setting
	string t;
	for(auto s : v) t += "<li><a href=\"main.html?field=" +s+ "\">" +s+ "</a></li>"; 
	swap("NAVITEM", t); t = "";
	table = nameNvalue_["field"] == "" ? v[0] : nameNvalue_["field"];
	swap("PANEL", field(table));
	
	if(nameNvalue_["email"] != "") {//if login attempt
		sq.select("Users", "where email = \'" + nameNvalue_["email"] + "\' order by date desc limit 1");
		v.clear();
		for(auto a : sq) for(auto b : a) v.push_back(b);
		if(v[1] == sq.encrypt(nameNvalue_["pwd"])) id=v[0], level=v[2], name=v[3];
	}

	regex e{R"(<form[\s\S]+?</form>)"};
	if(id != "") content_ = regex_replace(content_, e, name + "님 레벨" + level +"으로 로그인되었습니다.");
}

void DnDD::signin()
{//sq.select returns row count
	if(nameNvalue_.empty()) return;
	if(nameNvalue_["password"] != nameNvalue_["verify"])
		swap("REPLACE", "password not match");
	else if(sq.select("Users", "where email='" + nameNvalue_["email"] + "';"))
		swap("REPLACE", "아이디가 이미 존재합니다.");
	else {//select will retrieve table structure, which makes inserting possible
		sq.insert({nameNvalue_["email"], sq.encrypt(nameNvalue_["password"]), "1", nameNvalue_["username"], nameNvalue_["tel"], sq.now()});
		if(nameNvalue_["check"] != "") 
			id = nameNvalue_["email"], level = "1", name = nameNvalue_["username"];
		swap("REPLACE", "가입완료<br><a href=\"main.html\">메인화면으로</a><br>");
	}

	const char *append_str[]//to remember user input
		= {"email", "password", "verify", "username", "address", "tel"};
	for(string s : append_str) 
		append("id=\"" + s + '\"', " value=\"" + nameNvalue_[s] + '\"');
	cout << id << endl;
}

