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

vector<string> DnDD::tables()
{//return data tables
	vector<string> v;
	auto tb = sq.show_tables();
	for(auto s : tb) if(s != "Users" && s != "Vote" && s != "Follow") v.push_back(s);
	return v;
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

string DnDD::field(string s)
{//return table contents as bootstrap panel string
	vector<string> v;
	string t;
	sq.select(s, "where title <> \'코멘트임.\' order by num desc, page, date, edit desc");
	sq.group_by("email", "date");
	for(auto& a : sq) {
		v.clear();
		for(auto b : a) v.push_back(b);
		if(a[1] == "0") {//if book
			t += "<div class=\"panel-heading\"><a href=\"." + v[0];
			t += "\" data-toggle=\"collapse\">" + v[0] + ". " + v[3] + "</div>\n";
		} else {
			t += "<div class=\"panel-body collapse " + v[0];
			t += "\">&nbsp;&nbsp;<a href=\"page.html?table=" + s + "&book=" + v[0];
			t += "&page=" + v[1] + "\">" + v[1] + ". " + v[3] + "</a></div>\n";
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

	if(nameNvalue_["field"] != "") swap("PANEL", field(table = nameNvalue_["field"]));
	else if(nameNvalue_["email"] != "") {//if login attempt
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

void DnDD::pg()
{
	table = nameNvalue_["table"];
	book = nameNvalue_["book"];
	page = nameNvalue_["page"]; 
	int max_page = maxpage(table, book);
	int ipage = stoi(page);

	swap("FIRST", table + "&book=" + book + "&page=0");//set buttons
	swap("PREV", table + "&book=" + book + "&page=" + to_string(ipage ? ipage-1 : 0));
	swap("NEXT", table + "&book=" + book + "&page=" + to_string(ipage == max_page ? max_page : ipage + 1));
	swap("LAST", table + "&book=" + book + "&page=" + to_string(max_page));

	sq.select(table, "where num=" + book + " and page=" + page + " and title <> \'코멘트임.\' order by edit desc limit 1");
	vector<string> v;
	for(auto& a : sq) for(string s : a) v.push_back(s);
	swap("TITLE", v[3]);
	swap("MAINTEXT", quote_encode(v[4]));
}

int DnDD::maxpage(string table, string book)
{
	sq.select(table, "where num=" + book + " order by page desc limit 1");
	vector<string> v;
	for(auto& a : sq) for(string s : a) v.push_back(s);
	return stoi(v[1]);
}

string DnDD::quote_encode(string s)
{
	for(auto i = s.find('\"'); i != string::npos; i = s.find('\"', i)) 
		s.replace(i, 1, "%34");
	if(s.find('<') > 10) 
		for(auto i = s.find('\n'); i != string::npos; i = s.find('\n', i)) 
			s.replace(i, 1, "<br>");
	return s;
}

