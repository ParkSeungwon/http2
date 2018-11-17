#include<cassert>
#include<fstream>
#include<regex>
#include<string>
#include"my_site.h"
#include"database/util.h"
#include"tls/crypt.h"
using namespace std;

Site::Site() : WebSite{"site_html"}
{//SqlQuery destructor -> mysqlquery destructor nullify
	sq.connect("localhost", "site", "sitesite", "site");//sq prohibit destruct
}

void Site::process()
{
	cout << requested_document_ << endl;
	for(auto& a : nameNvalue_) cout << a.first << ':' << a.second << endl;
	if(requested_document_ == "index.html") index();
	else if(requested_document_ == "db.html") db();
}

void Site::index()
{
	sq.select("bbs", "where num=1 and page=1 and comment_order=1 order by edit desc limit 1");
	swap("TEXT", sq[0]["content"].asString());
	swap("TITLE", sq[0]["title"].asString());
}

void Site::db()
{
	sq.select("bbs", "where num=1 and page=1 and comment_order=1 order by edit desc limit 1");
	sq.insert(nameNvalue_["title"], nameNvalue_["content"], sq.now(), 
			1, 1, 1, sq[0]["edit"].asInt() + 1, "zezeon@msn.com");
	stringstream ss; ss << sq[0];
	swap("DATA", "inserted " + ss.str());
}