#include<cassert>
#include<fstream>
#include<regex>
#include"dndd.h"
using namespace std;

static string quote_encode(string s)
{//" -> ' to embed inside srcdoc, if text \n -> <br>
	for(auto i = s.find('\"'); i != string::npos; i = s.find('\"', i)) 
		s.replace(i, 1, "\'");
	if(s.find('<') > 10) 
		for(auto i = s.find('\n'); i != string::npos; i = s.find('\n', i)) 
			s.replace(i, 1, "<br>");
	return s;
}

static string level2txt(array<int, 5> allow)
{
	string s[6] = {"anonymous", "registered", "regular", "representative", "senior", "root"};
	string r = "<html><body><h3>Read level &#x2267 " + s[allow[0]];
	r += "<br>Write level &#x2267 " + s[allow[1]];
	r += "<br>Comment level &#x2267 " + s[allow[2]];
	r += "<br>Vote level &#x2267 " + s[allow[3]];
	r += "<br>Voting options = " + to_string(allow[4]) + "</h3></body></html>";
	return r;
}

void DnDD::pg()
{
	if(nameNvalue_["title"] != "") {//if from edit, or new->add->page
		sq.select(table, "limit 1");
		sq.insert({book, page, id, nameNvalue_["title"], nameNvalue_["content"], 
				tmp.size() ? tmp[5] : sq.now(), "null"});//if from page no date
	} else if(nameNvalue_["comment"] != "") {//if from comment
		sq.select(table, "limit 1");
		sq.insert({book, page, id, "코멘트임.", nameNvalue_["comment"], sq.now(), "null"});
	} else {//if get method
		table = nameNvalue_["table"];
		book = nameNvalue_["book"];
		page = nameNvalue_["page"]; 
	}
	int max_page = maxpage(table, book);
	int ipage = stoi(page);
	allow = allowlevel(table, book);

	if(id != "" && stoi(level) < allow[0]) {//check read level
		content_ = "<script>alert(\"not enough level to read this article\")</script>";
		return;
	}

	//set buttons
	swap("FIRST", table + "&book=" + book + "&page=0");
	swap("PREV", table + "&book=" + book + "&page=" + to_string(ipage ? ipage-1 : 0));
	swap("NEXT", table + "&book=" + book + "&page=" + to_string(ipage == max_page ? max_page : ipage + 1));
	swap("LAST", table + "&book=" + book + "&page=" + to_string(max_page));
	swap("RESULT", table + "&book=" + book + "&option=" + to_string(allow[4]) + "&db=" + db);
	string r, s = "<label class=\"radio-inline\"><input type=\"radio\" name=\"option\" value=\"";
	for(int i=1; i<=allow[4]; i++) 
		r += s + to_string(i) + "\">" + to_string(i) + "</label>\n";
	swap("OPTIONS", r);

	//main frame
	sq.select(table, "where num=" + book + " and page=" + page + " and title <> \'코멘트임.\' order by edit desc limit 1");
	vector<string> v;
	for(auto& a : sq) for(string s : a) v.push_back(s);
	swap("FOLLOW", v[2]);
	swap("TITLE", v[3]);
	swap("MAINTEXT", page == "0" ? level2txt(allow) : quote_encode(v[4]));
	tmp = v;//5 date

	//attachment덧글
	sq.select(table, "where num=" + book + " and page=" + page + " and title = \'코멘트임.\' order by date desc, email, edit desc");
	sq.group_by("date", "email", "edit");
	string t;
	for(auto& a : sq) {
		v.clear();
		for(string s : a) v.push_back(s);
		t += "<div class=\"panel-heading\">written by " + v[2] + " on " + v[5];
		t += "</div>\n<div class=\"panel-body\">" + v[4] + "</div>\n";
	}
	swap("ATTACHMENT", t);
}

