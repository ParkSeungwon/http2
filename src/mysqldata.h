#pragma once
#include <vector>
#include<functional>
#include "mysqlquery.h"
#include"any.h"

class SqlData
{
public:
	std::vector<Any>* begin();
	std::vector<Any>* end(); 
	bool is_int(int nth_column);
	bool empty() {return contents.empty();}
	std::vector<std::pair<std::string, std::string>>& desc() {
		return structure;
	}

protected:
	std::string table_name;
	std::vector<std::pair<std::string, std::string>> structure;
	std::vector<std::vector<Any>> contents;
};

class SqlQuery : public Mysqlquery, public SqlData
{
public:
	int select(std::string table, std::string where = "");
	bool insert();
	bool insert(std::vector<std::string> v);
	
	std::string encrypt(std::string pass);
	void create_table(std::string tb);
	std::vector<std::string> show_tables();
	std::string now();//system clock->mysql datetime string
	template <typename... Args> int group_by(Args... args)
	{//first order_by -> group_by(col = 1,2,3,...)
		arguments.clear();
		get_args(args...);
		std::vector<Any> before;
		before.resize(arguments.size());
		bool del;
		for(auto& c : contents) {
			del = true;
			for(auto& a : arguments) {
				if(c[a-1] != before[a-1]) {
					del = false;
					break;
				}
			}
			if(del) c[0] = "this_will@be&deleted";
			else before = c;
		}
		auto it = remove_if(contents.begin(), contents.end(), 
				[](const std::vector<Any>& a) {
				return a[0] == "this_will@be&deleted";});
		contents.erase(it, contents.end());
		return contents.size();
	}

	template <typename... Args> bool order_by(Args... args) 
	{//use [-nth] column to order desc
		arguments.clear();
		get_args(args...);
		std::sort(contents.begin(), contents.end(), 
				std::bind(&SqlQuery::order_lambda, this, std::placeholders::_1, 
					std::placeholders::_2, arguments));
	}

	template <typename... Args> std::string to_html_table(Args... args)
	{
		arguments.clear();
		get_args(args...);
		if(arguments.empty()) 
			for(int i=1; i<=structure.size(); i++) arguments.push_back(i);
		std::string tb = "<table>";
		tb += "<tr>";
		for(int& a : arguments) tb += "<th>" + structure[abs(a)-1].first + "</th>";
		tb += "</tr>\n";
		for(auto& a : contents) {
			tb += "<tr>";
			for(int& b : arguments) tb += "<td>" + (std::string)a[abs(b)-1] + "</td>";
			tb += "</tr>\n";
		}
		return tb + "</table>";
	}

private:
	std::vector<int> arguments;
	template<typename... Args> void get_args(int col, Args... args) {
		arguments.push_back(col);
		get_args(args...);
	}
	template<typename... Args> void get_args(std::string col, Args... args) {
		int i = 0;
		while(structure[i].first != col) i++;
		get_args(i+1, args...);
	}
	void get_args() {}

	bool order_lambda(const std::vector<Any>& a, 
			const std::vector<Any>& b, std::vector<int> cols);
};

