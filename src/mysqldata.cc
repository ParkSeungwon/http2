#include <chrono>
#include<initializer_list>
#include<unordered_map>
#include <ctime>
#include "mysqldata.h"
using namespace std;

bool SqlData::is_int(int n)
{
	return structure[n].second.find("INT") != string::npos;
}
std::vector<Any>* SqlData::begin() {return &contents[0];}
std::vector<Any>* SqlData::end() {return &contents[contents.size()];}

void SqlQuery::create_table(string tb) {
	table_name = tb;
	string s = "create table ";
	s += tb + " (";
	for(auto& a : structure) {
		for(auto& b : a.first) if(b == ' ') b = '_';
		s += a.first + ' ';
		s += a.second + ',';
	}
	s.back() = ')';
	s += ';';
	cout << s << endl;
	myQuery(s);
}

bool SqlQuery::insert(vector<string> v) 
{//d should be 1 record
	string q = "insert into " + table_name + " values (";
	for(int i=0; i<structure.size(); i++) {
		string s = v[i];
		if(structure[i].second == "INT" || structure[i].second == "FLOAT" || s == "null") 
			q += s + ",";
		else q += "'" + s + "',";
	}
	q.back() = ')';
	q += ";";
	return myQuery(q);
}

bool SqlQuery::insert()
{//d should be 1 record
	auto& record = contents[0];
	string q = "insert into " + table_name + " values (";
	for(int i=0; i<structure.size(); i++) {
		string s = record[i];
		if(structure[i].second.find("INT") != string::npos) q += s + ",";
		else q += "'" + s + "',";
	}
	q.back() = ')';
	q += ";";
	return myQuery(q);
}

string SqlQuery::now()
{
	myQuery("select now();");
	res->next();
	return res->getString(1);
}

string SqlQuery::encrypt(string s)
{
	myQuery("select password('" + s + "');");
	res->next();
	return res->getString(1);
}

int SqlQuery::select(string table, string where)
{
	string q = "select * from " + table + ' ' + where + ';';
	myQuery(q);

	table_name = table;
	sql::ResultSetMetaData* mt = res->getMetaData();
	int c = mt->getColumnCount();
	structure.clear();
	contents.clear();
	for(int i = 0; i < c; i++) //populate structure
		structure.push_back({mt->getColumnName(i+1), mt->getColumnTypeName(i+1)});
	vector<Any> record;
	while(res->next()) { //populate contents
		record.clear();
		for(int i = 0; i < c; i++) {
			if(is_int(i)) record.push_back(res->getInt(i+1));
			else record.push_back(Any(res->getString(i+1)));
		}
		contents.push_back(record);
	}
	return contents.size();
}


/*string SqlData::now()
{
	auto now = chrono::system_clock::now();
	auto tp = chrono::system_clock::to_time_t(now);
	string t = ctime(&tp);
	unordered_map<string, string> months {
		{"Jan", "01"}, {"Feb", "02"}, {"Mar", "03"}, {"Apr", "04"}, 
		{"May", "05"}, {"Jun", "06"}, {"Jul", "07"}, {"Aug", "08"}, 
		{"Sep", "09"}, {"Oct", "10"}, {"Nov", "11"}, {"Dec", "12"}
	};

	string s = t.substr(20, 4) + "-" + months[t.substr(4, 3)] + "-";
	if(t[8] == ' ') s += '0';
	else s += t[8];
	s += t.substr(9, 10);
	return s;
}*/

vector<string> SqlQuery::show_tables()
{
	vector<string> record;
	myQuery("show tables;");
	while(res->next()) record.push_back(res->getString(1));
	return record;
}

bool SqlQuery::order_lambda(const std::vector<Any>& a, 
		const std::vector<Any>& b, std::vector<int> cols)
{
	int i=0;
	while(a[abs(cols[i])-1] == b[abs(cols[i])-1] && i < cols.size()-1) i++; 
	bool desc = false;
	if(cols[i] < 0) {
		cols[i] = -cols[i];
		desc = true;
	}
	bool asc = a[cols[i]-1] < b[cols[i]-1];
	return desc ? !asc : asc;
}
