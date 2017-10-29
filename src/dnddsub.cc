#include<cassert>
#include<fstream>
#include<regex>
#include<cassert>
#include"dndd.h"
using namespace std;

vector<string> DnDD::tables()
{//return data tables
	vector<string> v;
	auto tb = sq.show_tables();
	for(auto s : tb) if(s != "Users" && s != "Vote" && s != "Follow") v.push_back(s);
	return v;
}

array<int, 5> DnDD::allowlevel(string table, string book)
{//read write comment vote
	array<int, 5> ar;
	sq.select(table, "where num=" + book + " and page=0 and title <> \'코멘트임.\' order by edit desc limit 1");
	vector<string> v;
	for(auto& a : sq) for(string s : a) v.push_back(s);
	for(int i=0; i<4; i++) ar[i] = v[4][i] - '0';
	ar[4] = v[4][5] - '0';
	return ar;
}

int DnDD::maxpage(string table, string book)
{
	assert(sq.select(table, "where num=" + book + " order by page desc limit 1") > 0);
	vector<string> v;
	for(auto& a : sq) for(string s : a) v.push_back(s);
	return stoi(v[1]);
}

string DnDD::quote_encode(string s)
{//" -> ' to embed inside srcdoc, if text \n -> <br>
	for(auto i = s.find('\"'); i != string::npos; i = s.find('\"', i)) 
		s.replace(i, 1, "\'");
	if(s.find('<') > 10) 
		for(auto i = s.find('\n'); i != string::npos; i = s.find('\n', i)) 
			s.replace(i, 1, "<br>");
	return s;
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

